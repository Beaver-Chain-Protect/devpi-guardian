"""Fail-closed direct Artifact download enforcement."""

from __future__ import annotations

from pyramid.httpexceptions import HTTPNotFound, HTTPServiceUnavailable

from devpi_guardian.verdicts.errors import InvalidSha256, StoreUnavailable
from devpi_guardian.verdicts.models import (
    ArtifactState,
    Decision,
    DecisionSource,
    EnforcementDecision,
    validate_sha256,
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
    if type(path_info) is not str:
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
    if type(decision) is not EnforcementDecision:
        return False
    try:
        decision_sha256 = decision.sha256
        allowed = decision.allowed
        effective_decision = decision.effective_decision
        source = decision.source
        artifact_state = decision.artifact_state
        policy_version = decision.policy_version
    except Exception:
        return False

    if type(decision_sha256) is not str or decision_sha256 != sha256:
        return False
    if allowed is not True or effective_decision is not Decision.ALLOW:
        return False
    if source is DecisionSource.AUTOMATED:
        allowed_state = artifact_state is ArtifactState.ALLOW
        return allowed_state and _valid_policy_version(policy_version)
    if source is not DecisionSource.MANUAL_OVERRIDE:
        return False
    if artifact_state is ArtifactState.ERROR:
        return policy_version is None or _valid_policy_version(policy_version)
    if any(artifact_state is state for state in _MANUAL_ALLOW_STATES[:-1]):
        return _valid_policy_version(policy_version)
    return False


def _valid_policy_version(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _valid_resolved_sha256(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        validate_sha256(value)
    except InvalidSha256:
        return False
    return True


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
        if not _valid_resolved_sha256(sha256):
            _safe_log(
                request,
                sha256=_UNKNOWN,
                decision=None,
                block_category="identity_unavailable",
            )
            return HTTPServiceUnavailable()

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
