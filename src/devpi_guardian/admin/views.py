"""Pyramid views for the versioned F11 administrator API."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
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
from devpi_guardian.verdicts.models import ArtifactState

from .service import AdminFeatureUnavailable, AdminMutationsUnavailable

ADMIN_SERVICE_REGISTRY_KEY = "devpi_guardian.admin_service"
_DEFAULT_STATES = (
    ArtifactState.DISCOVERED,
    ArtifactState.SCANNING,
    ArtifactState.REVIEW,
    ArtifactState.DENY,
    ArtifactState.ERROR,
)


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {key: _json_value(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _response(payload: dict[str, Any], status: int = 200) -> Response:
    return Response(json_body=_json_value(payload), status=status)


def _error(status: int, code: str, message: str) -> Response:
    return _response({"error": {"code": code, "message": message}}, status)


def _domain_error(exc: Exception) -> Response:
    if isinstance(exc, ArtifactNotFound):
        return _error(404, "artifact_not_found", "artifact was not found")
    if isinstance(exc, TransitionConflict):
        return _error(409, "transition_conflict", "artifact state does not allow the operation")
    if isinstance(exc, AdminMutationsUnavailable):
        return _error(503, "mutations_unavailable", str(exc))
    if isinstance(exc, AdminFeatureUnavailable):
        return _error(503, f"{exc.feature}_unavailable", str(exc))
    if isinstance(exc, StoreUnavailable):
        return _error(503, "store_unavailable", "guardian store is unavailable")
    if isinstance(exc, (InvalidSha256, ValueError, TypeError)):
        return _error(400, "invalid_request", str(exc))
    raise exc


def _service(request):
    return request.registry[ADMIN_SERVICE_REGISTRY_KEY]


def _actor(request) -> str:
    actor = request.authenticated_userid
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("authenticated actor is required")
    return actor


def _reason(request) -> str:
    body = request.json_body
    reason = body.get("reason") if isinstance(body, dict) else None
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("reason is required")
    return reason


def _body(request) -> dict[str, Any]:
    body = request.json_body
    if not isinstance(body, dict):
        raise ValueError("JSON object body is required")
    return body


def _policy(request) -> dict[str, Any]:
    policy = _body(request).get("policy")
    if not isinstance(policy, dict):
        raise ValueError("policy object is required")
    return policy


def _states(value: str | None) -> tuple[ArtifactState, ...]:
    if value is None or not value.strip():
        return _DEFAULT_STATES
    result = tuple(ArtifactState(item.strip().upper()) for item in value.split(","))
    if not result or ArtifactState.ALLOW in result or ArtifactState.MISSING in result:
        raise ValueError("invalid quarantine state filter")
    return result


def _bounded_int(value: str | None, *, default: int, minimum: int, maximum: int) -> int:
    result = default if value is None else int(value)
    if result < minimum or result > maximum:
        raise ValueError("pagination value is out of range")
    return result


def list_quarantine(request) -> Response:
    try:
        states = _states(request.params.get("state"))
        limit = _bounded_int(request.params.get("limit"), default=50, minimum=1, maximum=200)
        offset = _bounded_int(request.params.get("offset"), default=0, minimum=0, maximum=1_000_000)
        page = _service(request).list_quarantine(states=states, limit=limit, offset=offset)
        return _response(
            {
                "items": page.items,
                "total": page.total,
                "limit": page.limit,
                "offset": page.offset,
            }
        )
    except Exception as exc:
        return _domain_error(exc)


def inspect_artifact(request) -> Response:
    try:
        details = _service(request).inspect(request.matchdict["sha256"])
        return _response({"artifact": details})
    except Exception as exc:
        return _domain_error(exc)


def artifact_diff(request) -> Response:
    try:
        result = _service(request).artifact_diff(request.matchdict["sha256"])
        return _response({"diff": result})
    except Exception as exc:
        return _domain_error(exc)


def list_audit(request) -> Response:
    try:
        limit = _bounded_int(request.params.get("limit"), default=50, minimum=1, maximum=200)
        offset = _bounded_int(
            request.params.get("offset"),
            default=0,
            minimum=0,
            maximum=1_000_000,
        )
        result = _service(request).list_audit(
            sha256=request.params.get("sha256"),
            actor=request.params.get("actor"),
            action=request.params.get("action"),
            limit=limit,
            offset=offset,
        )
        return _response({**result, "limit": limit, "offset": offset})
    except Exception as exc:
        return _domain_error(exc)


def list_baselines(request) -> Response:
    try:
        project = request.params.get("project")
        if not isinstance(project, str) or not project.strip():
            raise ValueError("project is required")
        return _response({"items": _service(request).list_baselines(project)})
    except Exception as exc:
        return _domain_error(exc)


def add_baseline(request) -> Response:
    try:
        sha256 = _body(request).get("sha256")
        if not isinstance(sha256, str):
            raise ValueError("sha256 is required")
        _service(request).add_baseline(sha256, actor=_actor(request), reason=_reason(request))
        return _response({"sha256": sha256, "status": "baseline_added"})
    except Exception as exc:
        return _domain_error(exc)


def remove_baseline(request) -> Response:
    try:
        sha256 = request.matchdict["sha256"]
        _service(request).remove_baseline(
            sha256,
            actor=_actor(request),
            reason=_reason(request),
        )
        return _response({"sha256": sha256, "status": "baseline_removed"})
    except Exception as exc:
        return _domain_error(exc)


def import_baselines(request) -> Response:
    try:
        records = _body(request).get("records")
        if (
            not isinstance(records, list)
            or not records
            or not all(isinstance(item, dict) for item in records)
        ):
            raise ValueError("non-empty records array is required")
        result = _service(request).import_baselines(
            tuple(records),
            actor=_actor(request),
            reason=_reason(request),
        )
        return _response(dict(result))
    except Exception as exc:
        return _domain_error(exc)


def policy_validate(request) -> Response:
    try:
        return _response(dict(_service(request).validate_policy(_policy(request))))
    except Exception as exc:
        return _domain_error(exc)


def policy_simulate(request) -> Response:
    try:
        body = _body(request)
        sha256 = body.get("sha256")
        if not isinstance(sha256, str):
            raise ValueError("sha256 is required")
        return _response(dict(_service(request).simulate_policy(_policy(request), sha256=sha256)))
    except Exception as exc:
        return _domain_error(exc)


def _mutation(request, operation, status: str) -> Response:
    try:
        sha256 = request.matchdict["sha256"]
        operation(sha256, actor=_actor(request), reason=_reason(request))
        return _response({"sha256": sha256, "status": status})
    except Exception as exc:
        return _domain_error(exc)


def approve_artifact(request) -> Response:
    return _mutation(request, _service(request).approve, "approved")


def block_artifact(request) -> Response:
    return _mutation(request, _service(request).block, "blocked")


def rescan_artifact(request) -> Response:
    return _mutation(request, _service(request).rescan, "rescan_requested")


def revoke_artifact(request) -> Response:
    return _mutation(request, _service(request).revoke, "override_revoked")


def add_exception(request) -> Response:
    try:
        body = request.json_body
        raw_expiry = body.get("expires_at") if isinstance(body, dict) else None
        if not isinstance(raw_expiry, str):
            raise ValueError("expires_at is required")
        expires_at = datetime.fromisoformat(raw_expiry)
        sha256 = request.matchdict["sha256"]
        _service(request).add_exception(
            sha256,
            actor=_actor(request),
            reason=_reason(request),
            expires_at=expires_at,
        )
        return _response({"sha256": sha256, "status": "exception_added"})
    except Exception as exc:
        return _domain_error(exc)


def health(request) -> Response:
    try:
        return _response(_service(request).health())
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
        (
            "guardian_artifact_exception",
            f"{prefix}/artifacts/{{sha256}}/exceptions",
        ),
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
            view,
            route_name=route_name,
            request_method=method,
            permission="user_modify",
        )
