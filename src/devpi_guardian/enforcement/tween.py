"""Fail-closed direct Artifact download enforcement."""

from __future__ import annotations

from pyramid.httpexceptions import HTTPNotFound, HTTPServiceUnavailable

from devpi_guardian.verdicts.errors import StoreUnavailable
from devpi_guardian.verdicts.models import (
    ArtifactState,
    Decision,
    DecisionSource,
    EnforcementDecision,
)

from .resolve import ArtifactIdentityUnavailable, resolve_release_sha256

VERDICT_READER_REGISTRY_KEY = "devpi_guardian.verdict_reader"
_MANUAL_ALLOW_STATES = (
    ArtifactState.ALLOW,
    ArtifactState.REVIEW,
    ArtifactState.DENY,
    ArtifactState.ERROR,
)
_UNKNOWN = "unknown"


def _route_classification(request: object) -> str:
    try:
        path_info = request.path_info
    except Exception:
        return _UNKNOWN
    if not isinstance(path_info, str):
        return _UNKNOWN
    parts = path_info.split("/")
    if len(parts) > 3 and parts[3] in {"+f", "+e"}:
        return parts[3]
    return _UNKNOWN


def _enum_value(
    value: object,
    enum_type: type[Decision] | type[DecisionSource] | type[ArtifactState],
) -> str:
    for member in enum_type:
        if value is member:
            return member.value
    return _UNKNOWN


def _safe_decision_field(
    decision: object | None,
    field_name: str,
    enum_type: type[Decision] | type[DecisionSource] | type[ArtifactState],
) -> str:
    if decision is None:
        return _UNKNOWN
    try:
        value = getattr(decision, field_name)
        return _enum_value(value, enum_type)
    except Exception:
        return _UNKNOWN


def _safe_log(
    request: object,
    *,
    sha256: object,
    decision: object | None,
    block_category: str,
) -> None:
    """Best-effort static logging that never changes enforcement behavior."""
    try:
        logger = request.log
        safe_sha256 = sha256 if type(sha256) is str else _UNKNOWN
        logger.info(
            "guardian direct download blocked route=%s sha256=%s "
            "effective=%s state=%s source=%s category=%s",
            _route_classification(request),
            safe_sha256,
            _safe_decision_field(decision, "effective_decision", Decision),
            _safe_decision_field(decision, "artifact_state", ArtifactState),
            _safe_decision_field(decision, "source", DecisionSource),
            block_category,
        )
    except Exception:
        return


def _is_exact_allow(decision: object, sha256: str) -> bool:
    """Accept only a structurally valid, reader-produced effective ALLOW."""
    if not isinstance(decision, EnforcementDecision):
        return False
    if type(decision.sha256) is not str or decision.sha256 != sha256:
        return False
    if decision.allowed is not True:
        return False
    if decision.effective_decision is not Decision.ALLOW:
        return False
    if decision.source is DecisionSource.AUTOMATED:
        return decision.artifact_state is ArtifactState.ALLOW
    if decision.source is DecisionSource.MANUAL_OVERRIDE:
        artifact_state = decision.artifact_state
        return any(artifact_state is state for state in _MANUAL_ALLOW_STATES)
    return False


def guardian_enforcement_tween_factory(handler, registry):
    """Build the Pyramid tween that gates protected release-file requests."""
    reader = registry[VERDICT_READER_REGISTRY_KEY]

    def enforce(request):
        try:
            sha256 = resolve_release_sha256(request)
        except ArtifactIdentityUnavailable:
            _safe_log(
                request,
                sha256=_UNKNOWN,
                decision=None,
                block_category="identity_unavailable",
            )
            return HTTPServiceUnavailable()
        except StoreUnavailable:
            _safe_log(
                request,
                sha256=_UNKNOWN,
                decision=None,
                block_category="store_unavailable",
            )
            return HTTPServiceUnavailable(headers={"Retry-After": "5"})

        if sha256 is None:
            return handler(request)

        try:
            decision = reader.get_effective_decision(sha256)
        except StoreUnavailable:
            _safe_log(
                request,
                sha256=sha256,
                decision=None,
                block_category="store_unavailable",
            )
            return HTTPServiceUnavailable(headers={"Retry-After": "5"})

        if not _is_exact_allow(decision, sha256):
            _safe_log(
                request,
                sha256=sha256,
                decision=decision,
                block_category="not_allowed",
            )
            return HTTPNotFound()
        return handler(request)

    return enforce
