"""Pyramid views for the versioned F11 administrator API."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from pyramid.response import Response

from devpi_guardian.verdicts.errors import (
    ArtifactNotFound,
    InvalidSha256,
    StoreUnavailable,
    TransitionConflict,
)
from devpi_guardian.verdicts.models import (
    ArtifactAdminDetails,
    ArtifactAdminSummary,
    ArtifactState,
    QuarantinePage,
    validate_sha256,
)

from .service import AdminFeatureUnavailable, AdminMutationsUnavailable, AdminRequestError

ADMIN_SERVICE_REGISTRY_KEY = "devpi_guardian.admin_service"
_DEFAULT_STATES = (
    ArtifactState.DISCOVERED,
    ArtifactState.SCANNING,
    ArtifactState.REVIEW,
    ArtifactState.DENY,
    ArtifactState.ERROR,
)
_MAX_JSON_BYTES = 1024 * 1024
_MAX_TEXT = 4096


class SerializationError(ValueError):
    """A provider returned a value outside the bounded JSON contract."""


class RegistryUnavailable(RuntimeError):
    """The admin service registry entry is absent or malformed."""


def _json_value(
    value: Any, *, depth: int = 0, seen: set[int] | None = None, count: list[int] | None = None
) -> Any:
    if depth > 32:
        raise SerializationError("response is too deeply nested")
    seen = set() if seen is None else seen
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > 10_000:
        raise SerializationError("response contains too many values")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        if len(value.encode("utf-8")) > _MAX_TEXT or any(
            ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F or 0xD800 <= ord(char) <= 0xDFFF
            for char in value
        ):
            raise SerializationError("response contains invalid text")
        return value
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise SerializationError("response contains a non-finite number")
        return value
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise SerializationError("response contains a naive datetime")
        return value.isoformat()
    if isinstance(value, Enum):
        return _json_value(value.value, depth=depth + 1, seen=seen, count=count)
    identity = id(value)
    if identity in seen:
        raise SerializationError("response contains a cycle")
    seen.add(identity)
    try:
        if is_dataclass(value) and not isinstance(value, type):
            return {
                field.name: _json_value(
                    getattr(value, field.name), depth=depth + 1, seen=seen, count=count
                )
                for field in fields(value)
            }
        if isinstance(value, Mapping):
            result = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise SerializationError("response object keys must be strings")
                result[key] = _json_value(item, depth=depth + 1, seen=seen, count=count)
            return result
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [_json_value(item, depth=depth + 1, seen=seen, count=count) for item in value]
    except (RecursionError, TypeError, ValueError) as exc:
        if isinstance(exc, SerializationError):
            raise
        raise SerializationError("response serialization failed") from exc
    finally:
        seen.discard(identity)
    raise SerializationError("response contains an unsupported value")


def _response(payload: dict[str, Any], status: int = 200) -> Response:
    converted = _json_value(payload)
    try:
        import json

        encoded = json.dumps(converted, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise SerializationError("response serialization failed") from exc
    if len(encoded.encode("utf-8")) > _MAX_JSON_BYTES:
        raise SerializationError("response is too large")
    return Response(json_body=converted, status=status)


def _error(status: int, code: str, message: str) -> Response:
    return _response({"error": {"code": code, "message": message}}, status)


def _domain_error(exc: Exception) -> Response:
    if isinstance(exc, ArtifactNotFound):
        return _error(404, "artifact_not_found", "artifact was not found")
    if isinstance(exc, TransitionConflict):
        return _error(409, "transition_conflict", "artifact state does not allow the operation")
    if isinstance(exc, AdminMutationsUnavailable):
        return _error(503, "mutations_unavailable", "guardian mutations are unavailable")
    if isinstance(exc, AdminFeatureUnavailable):
        return _error(503, f"{exc.feature}_unavailable", str(exc))
    if isinstance(exc, RegistryUnavailable):
        return _error(503, "admin_service_unavailable", "guardian admin service is unavailable")
    if isinstance(exc, StoreUnavailable):
        return _error(503, "store_unavailable", "guardian store is unavailable")
    if isinstance(exc, InvalidSha256):
        return _error(
            400,
            "invalid_request",
            "sha256 must be a lowercase 64-character hexadecimal digest",
        )
    if isinstance(exc, AdminRequestError):
        return _error(400, "invalid_request", str(exc))
    if isinstance(exc, SerializationError):
        return _error(503, "serialization_unavailable", "guardian response is unavailable")
    if isinstance(exc, (ValueError, TypeError)):
        return _error(503, "provider_unavailable", "guardian provider is unavailable")
    raise exc


def _service(request):
    try:
        service = request.registry[ADMIN_SERVICE_REGISTRY_KEY]
    except (KeyError, TypeError, AttributeError) as exc:
        raise RegistryUnavailable from exc
    required = ("list_quarantine", "inspect", "health")
    if not all(callable(getattr(service, name, None)) for name in required):
        raise RegistryUnavailable
    return service


def _actor(request) -> str:
    actor = request.authenticated_userid
    if (
        not isinstance(actor, str)
        or not actor.strip()
        or len(actor) > _MAX_TEXT
        or any(
            ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F or 0xD800 <= ord(char) <= 0xDFFF
            for char in actor
        )
    ):
        raise AdminRequestError("authenticated actor is required")
    return actor


def _body(request) -> dict[str, Any]:
    try:
        body = request.json_body
    except (ValueError, TypeError, UnicodeError):
        raise AdminRequestError("invalid JSON request") from None
    if not isinstance(body, dict):
        raise AdminRequestError("JSON object body is required")
    try:
        snapshot = _json_value(body)
    except SerializationError as exc:
        raise AdminRequestError("request JSON is invalid") from exc
    if not isinstance(snapshot, dict):
        raise AdminRequestError("JSON object body is required")
    import json

    try:
        if (
            len(json.dumps(snapshot, ensure_ascii=False, allow_nan=False).encode("utf-8"))
            > _MAX_JSON_BYTES
        ):
            raise AdminRequestError("request JSON is too large")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise AdminRequestError("request JSON is invalid") from exc
    return snapshot


def _reason(body: Mapping[str, Any]) -> str:
    reason = body.get("reason")
    if (
        not isinstance(reason, str)
        or not reason.strip()
        or len(reason) > _MAX_TEXT
        or any(
            ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F or 0xD800 <= ord(char) <= 0xDFFF
            for char in reason
        )
    ):
        raise AdminRequestError("reason is required")
    return reason


def _policy(body: Mapping[str, Any]) -> dict[str, Any]:
    policy = body.get("policy")
    if not isinstance(policy, dict):
        raise AdminRequestError("policy object is required")
    return policy


def _sha(value: Any) -> str:
    if not isinstance(value, str):
        raise AdminRequestError("sha256 is required")
    try:
        return validate_sha256(value)
    except InvalidSha256:
        raise


def _states(value: str | None) -> tuple[ArtifactState, ...]:
    if value is None:
        return _DEFAULT_STATES
    if not isinstance(value, str):
        raise AdminRequestError("invalid quarantine state filter")
    if len(value) > _MAX_TEXT or value.count(",") + 1 > 50:
        raise AdminRequestError("invalid quarantine state filter")
    if not value.strip():
        return _DEFAULT_STATES
    try:
        result = tuple(
            dict.fromkeys(ArtifactState(item.strip().upper()) for item in value.split(","))
        )
    except (TypeError, ValueError) as exc:
        raise AdminRequestError("invalid quarantine state filter") from exc
    if not result or ArtifactState.ALLOW in result or ArtifactState.MISSING in result:
        raise AdminRequestError("invalid quarantine state filter")
    return result


def _bounded_int(value: str | None, *, default: int, minimum: int, maximum: int) -> int:
    try:
        result = default if value is None else int(value)
    except (TypeError, ValueError) as exc:
        raise AdminRequestError("pagination value is out of range") from exc
    if result < minimum or result > maximum:
        raise AdminRequestError("pagination value is out of range")
    return result


def _filter_text(value: object, name: str) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > _MAX_TEXT
        or any(
            ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F or 0xD800 <= ord(char) <= 0xDFFF
            for char in value
        )
    ):
        raise AdminRequestError(f"{name} is invalid")
    return value


def _valid_quarantine_page(page: object) -> bool:
    if not isinstance(page, QuarantinePage):
        return False
    if type(page.total) is not int or page.total < 0:
        return False
    if type(page.limit) is not int or not 1 <= page.limit <= 200:
        return False
    if type(page.offset) is not int or page.offset < 0:
        return False
    if not isinstance(page.items, tuple) or len(page.items) > 200:
        return False
    for item in page.items:
        if not isinstance(item, ArtifactAdminSummary):
            return False
        if type(item.sha256) is not str:
            return False
        try:
            validate_sha256(item.sha256)
        except InvalidSha256:
            return False
        if type(item.size_bytes) is not int or item.size_bytes < 0:
            return False
        if not isinstance(item.state, ArtifactState) or item.state in {
            ArtifactState.ALLOW,
            ArtifactState.MISSING,
        }:
            return False
        for timestamp in (item.discovered_at, item.updated_at):
            if (
                not isinstance(timestamp, datetime)
                or timestamp.tzinfo is None
                or timestamp.utcoffset() is None
            ):
                return False
        if item.cooldown_until is not None and (
            not isinstance(item.cooldown_until, datetime)
            or item.cooldown_until.tzinfo is None
            or item.cooldown_until.utcoffset() is None
        ):
            return False
        if item.last_error is not None and not isinstance(item.last_error, str):
            return False
    return True


def list_quarantine(request) -> Response:
    try:
        states = _states(request.params.get("state"))
        page = _service(request).list_quarantine(
            states=states,
            limit=_bounded_int(request.params.get("limit"), default=50, minimum=1, maximum=200),
            offset=_bounded_int(
                request.params.get("offset"), default=0, minimum=0, maximum=1_000_000
            ),
        )
        if not _valid_quarantine_page(page):
            raise SerializationError("invalid quarantine response")
        return _response(
            {"items": page.items, "total": page.total, "limit": page.limit, "offset": page.offset}
        )
    except Exception as exc:
        return _domain_error(exc)


def inspect_artifact(request) -> Response:
    try:
        details = _service(request).inspect(_sha(request.matchdict["sha256"]))
        if not isinstance(details, ArtifactAdminDetails):
            raise SerializationError("invalid artifact response")
        return _response({"artifact": details})
    except Exception as exc:
        return _domain_error(exc)


def artifact_diff(request) -> Response:
    try:
        result = _service(request).artifact_diff(_sha(request.matchdict["sha256"]))
        if not isinstance(result, Mapping):
            raise SerializationError("invalid diff response")
        return _response({"diff": result})
    except Exception as exc:
        return _domain_error(exc)


def list_audit(request) -> Response:
    try:
        sha256 = request.params.get("sha256")
        if sha256 is not None:
            sha256 = _sha(sha256)
        limit = _bounded_int(request.params.get("limit"), default=50, minimum=1, maximum=200)
        offset = _bounded_int(request.params.get("offset"), default=0, minimum=0, maximum=1_000_000)
        result = _service(request).list_audit(
            sha256=sha256,
            actor=_filter_text(request.params.get("actor"), "actor"),
            action=_filter_text(request.params.get("action"), "action"),
            limit=limit,
            offset=offset,
        )
        if not isinstance(result, Mapping):
            raise SerializationError("invalid audit response")
        return _response({**result, "limit": limit, "offset": offset})
    except Exception as exc:
        return _domain_error(exc)


def list_baselines(request) -> Response:
    try:
        project = request.params.get("project")
        if (
            not isinstance(project, str)
            or not project.strip()
            or len(project) > _MAX_TEXT
            or any(
                ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F or 0xD800 <= ord(char) <= 0xDFFF
                for char in project
            )
        ):
            raise AdminRequestError("project is required")
        result = _service(request).list_baselines(project)
        if (
            isinstance(result, (str, bytes, bytearray))
            or not isinstance(result, Sequence)
            or not all(isinstance(item, Mapping) for item in result)
        ):
            raise SerializationError("invalid baseline response")
        snapshot = tuple(dict(item) for item in result)
        return _response({"items": snapshot})
    except Exception as exc:
        return _domain_error(exc)


def add_baseline(request) -> Response:
    try:
        body = _body(request)
        sha256 = _sha(body.get("sha256"))
        result = _service(request).add_baseline(sha256, actor=_actor(request), reason=_reason(body))
        if result is not None:
            raise AdminMutationsUnavailable("guardian mutation did not complete safely")
        return _response({"sha256": sha256, "status": "baseline_added"})
    except Exception as exc:
        return _domain_error(exc)


def remove_baseline(request) -> Response:
    try:
        body = _body(request)
        sha256 = _sha(request.matchdict["sha256"])
        result = _service(request).remove_baseline(
            sha256, actor=_actor(request), reason=_reason(body)
        )
        if result is not None:
            raise AdminMutationsUnavailable("guardian mutation did not complete safely")
        return _response({"sha256": sha256, "status": "baseline_removed"})
    except Exception as exc:
        return _domain_error(exc)


def import_baselines(request) -> Response:
    try:
        body = _body(request)
        records = body.get("records")
        if (
            not isinstance(records, list)
            or not records
            or len(records) > 1000
            or not all(isinstance(item, dict) for item in records)
        ):
            raise AdminRequestError("non-empty records array is required")
        result = _service(request).import_baselines(
            tuple(records), actor=_actor(request), reason=_reason(body)
        )
        if not isinstance(result, Mapping):
            raise SerializationError("invalid baseline import response")
        return _response(dict(result))
    except Exception as exc:
        return _domain_error(exc)


def policy_validate(request) -> Response:
    try:
        body = _body(request)
        result = _service(request).validate_policy(_policy(body))
        if not isinstance(result, Mapping):
            raise SerializationError("invalid policy response")
        return _response(dict(result))
    except Exception as exc:
        return _domain_error(exc)


def policy_simulate(request) -> Response:
    try:
        body = _body(request)
        result = _service(request).simulate_policy(_policy(body), sha256=_sha(body.get("sha256")))
        if not isinstance(result, Mapping):
            raise SerializationError("invalid policy response")
        return _response(dict(result))
    except Exception as exc:
        return _domain_error(exc)


def _mutation(request, operation, status: str) -> Response:
    try:
        body = _body(request)
        sha256 = _sha(request.matchdict["sha256"])
        result = operation(sha256, actor=_actor(request), reason=_reason(body))
        if result is not None:
            raise AdminMutationsUnavailable("guardian mutation did not complete safely")
        return _response({"sha256": sha256, "status": status})
    except Exception as exc:
        return _domain_error(exc)


def approve_artifact(request) -> Response:
    try:
        return _mutation(request, _service(request).approve, "approved")
    except Exception as exc:
        return _domain_error(exc)


def block_artifact(request) -> Response:
    try:
        return _mutation(request, _service(request).block, "blocked")
    except Exception as exc:
        return _domain_error(exc)


def rescan_artifact(request) -> Response:
    try:
        return _mutation(request, _service(request).rescan, "rescan_requested")
    except Exception as exc:
        return _domain_error(exc)


def revoke_artifact(request) -> Response:
    try:
        return _mutation(request, _service(request).revoke, "override_revoked")
    except Exception as exc:
        return _domain_error(exc)


def add_exception(request) -> Response:
    try:
        body = _body(request)
        raw_expiry = body.get("expires_at")
        if not isinstance(raw_expiry, str) or len(raw_expiry) > _MAX_TEXT:
            raise AdminRequestError("expires_at is required")
        try:
            expires_at = datetime.fromisoformat(raw_expiry)
        except ValueError as exc:
            raise AdminRequestError("expires_at is invalid") from exc
        sha256 = _sha(request.matchdict["sha256"])
        result = _service(request).add_exception(
            sha256, actor=_actor(request), reason=_reason(body), expires_at=expires_at
        )
        if result is not None:
            raise AdminMutationsUnavailable("guardian mutation did not complete safely")
        return _response({"sha256": sha256, "status": "exception_added"})
    except Exception as exc:
        return _domain_error(exc)


def health(request) -> Response:
    try:
        result = _service(request).health()
        if not isinstance(result, Mapping):
            raise SerializationError("invalid health response")
        return _response(dict(result))
    except Exception as exc:
        return _domain_error(exc)


def configure_admin_routes(pyramid_config) -> None:
    prefix = "/+guardian/api/v1"
    routes = (
        ("guardian_quarantine", f"{prefix}/quarantine"),
        ("guardian_artifact", f"{prefix}/artifacts/{{sha256}}"),
        ("guardian_artifact_diff", f"{prefix}/artifacts/{{sha256}}/diff"),
        ("guardian_artifact_approve", f"{prefix}/artifacts/{{sha256}}/approve"),
        ("guardian_artifact_block", f"{prefix}/artifacts/{{sha256}}/block"),
        ("guardian_artifact_rescan", f"{prefix}/artifacts/{{sha256}}/rescan"),
        ("guardian_artifact_revoke", f"{prefix}/artifacts/{{sha256}}/revoke"),
        ("guardian_artifact_exception", f"{prefix}/artifacts/{{sha256}}/exceptions"),
        ("guardian_health", f"{prefix}/health"),
        ("guardian_audit", f"{prefix}/audit"),
        ("guardian_baselines", f"{prefix}/baselines"),
        ("guardian_baseline_import", f"{prefix}/baselines/import"),
        ("guardian_baseline_remove", f"{prefix}/baselines/{{sha256}}"),
        ("guardian_policy_validate", f"{prefix}/policy/validate"),
        ("guardian_policy_simulate", f"{prefix}/policy/simulate"),
    )
    views = (
        ("guardian_quarantine", list_quarantine, "GET"),
        ("guardian_artifact", inspect_artifact, "GET"),
        ("guardian_artifact_diff", artifact_diff, "GET"),
        ("guardian_artifact_approve", approve_artifact, "POST"),
        ("guardian_artifact_block", block_artifact, "POST"),
        ("guardian_artifact_rescan", rescan_artifact, "POST"),
        ("guardian_artifact_revoke", revoke_artifact, "POST"),
        ("guardian_artifact_exception", add_exception, "POST"),
        ("guardian_health", health, "GET"),
        ("guardian_audit", list_audit, "GET"),
        ("guardian_baselines", list_baselines, "GET"),
        ("guardian_baselines", add_baseline, "POST"),
        ("guardian_baseline_remove", remove_baseline, "DELETE"),
        ("guardian_baseline_import", import_baselines, "POST"),
        ("guardian_policy_validate", policy_validate, "POST"),
        ("guardian_policy_simulate", policy_simulate, "POST"),
    )
    for name, path in routes:
        pyramid_config.add_route(name, path)
    for route_name, view, method in views:
        pyramid_config.add_view(
            view, route_name=route_name, request_method=method, permission="user_modify"
        )
