"""Application service for audited F11 administrator operations."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from devpi_guardian.verdicts.models import (
    ArtifactAdminDetails,
    ArtifactState,
    Decision,
    ManualOverrideInput,
    QuarantinePage,
)


class AdminMutationsUnavailable(RuntimeError):
    """F12's transactional audit writer has not been connected yet."""


class AdminReader(Protocol):
    def list_quarantine(
        self,
        *,
        states: tuple[ArtifactState, ...],
        limit: int,
        offset: int,
    ) -> QuarantinePage: ...

    def get_artifact_details(self, sha256: str) -> ArtifactAdminDetails: ...

    def health(self) -> dict[str, object]: ...


class AdminStore(Protocol):
    def set_manual_override(self, override: ManualOverrideInput) -> None: ...

    def request_rescan(self, sha256: str, actor: str, reason: str) -> None: ...


class GuardianAdminService:
    def __init__(
        self,
        *,
        reader: AdminReader,
        store: AdminStore | None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._reader = reader
        self._store = store
        self._now = now if now is not None else lambda: datetime.now(UTC)

    def list_quarantine(
        self,
        *,
        states: tuple[ArtifactState, ...],
        limit: int,
        offset: int,
    ) -> QuarantinePage:
        return self._reader.list_quarantine(states=states, limit=limit, offset=offset)

    def inspect(self, sha256: str) -> ArtifactAdminDetails:
        return self._reader.get_artifact_details(sha256)

    def approve(self, sha256: str, *, actor: str, reason: str) -> None:
        self._override(sha256, Decision.ALLOW, actor, reason, None)

    def block(self, sha256: str, *, actor: str, reason: str) -> None:
        self._override(sha256, Decision.DENY, actor, reason, None)

    def add_exception(
        self,
        sha256: str,
        *,
        actor: str,
        reason: str,
        expires_at: datetime,
    ) -> None:
        self._override(sha256, Decision.ALLOW, actor, reason, expires_at)

    def _override(
        self,
        sha256: str,
        decision: Decision,
        actor: str,
        reason: str,
        expires_at: datetime | None,
    ) -> None:
        store = self._require_store()
        store.set_manual_override(
            ManualOverrideInput(
                sha256=sha256,
                decision=decision,
                actor=actor,
                reason=reason,
                created_at=self._now(),
                expires_at=expires_at,
            )
        )

    def rescan(self, sha256: str, *, actor: str, reason: str) -> None:
        self._require_store().request_rescan(sha256, actor, reason)

    def health(self) -> dict[str, object]:
        result = dict(self._reader.health())
        result["mutations_ready"] = self._store is not None
        return result

    def _require_store(self) -> AdminStore:
        if self._store is None:
            raise AdminMutationsUnavailable("transactional audit writer is unavailable")
        return self._store
