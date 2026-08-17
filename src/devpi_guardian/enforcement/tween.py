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
_ALLOW_SOURCES = frozenset(
    (DecisionSource.AUTOMATED, DecisionSource.MANUAL_OVERRIDE),
)


def _safe_log(request: object, message: str) -> None:
    """Best-effort static logging that never changes enforcement behavior."""
    try:
        logger = request.log
        logger.info(message)
    except Exception:
        return


def _is_exact_allow(decision: object, sha256: str) -> bool:
    """Accept only a structurally valid, reader-produced effective ALLOW."""
    if not isinstance(decision, EnforcementDecision):
        return False
    return (
        decision.sha256 == sha256
        and decision.allowed is True
        and decision.effective_decision is Decision.ALLOW
        and decision.source in _ALLOW_SOURCES
        and isinstance(decision.artifact_state, ArtifactState)
    )


def guardian_enforcement_tween_factory(handler, registry):
    """Build the Pyramid tween that gates protected release-file requests."""
    reader = registry[VERDICT_READER_REGISTRY_KEY]

    def enforce(request):
        try:
            sha256 = resolve_release_sha256(request)
            if sha256 is None:
                return handler(request)
            decision = reader.get_effective_decision(sha256)
        except ArtifactIdentityUnavailable:
            _safe_log(request, "guardian blocked unresolved artifact identity")
            return HTTPServiceUnavailable()
        except StoreUnavailable:
            _safe_log(request, "guardian verdict store unavailable")
            return HTTPServiceUnavailable(headers={"Retry-After": "5"})

        if not _is_exact_allow(decision, sha256):
            _safe_log(request, "guardian blocked artifact")
            return HTTPNotFound()
        return handler(request)

    return enforce
