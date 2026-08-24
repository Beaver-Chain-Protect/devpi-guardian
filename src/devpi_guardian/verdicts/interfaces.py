from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from datetime import datetime
from sqlite3 import Connection
from typing import Protocol

from .models import (
    AllowedRelease,
    ArtifactInput,
    AuditEventInput,
    ClaimedArtifact,
    EnforcementDecision,
    EvidenceInput,
    ManualOverrideInput,
    ReleaseInput,
    VerdictInput,
)


class VerdictReader(Protocol):
    def get_effective_decision(self, sha256: str) -> EnforcementDecision: ...

    def get_effective_decisions(
        self, sha256s: Collection[str]
    ) -> Mapping[str, EnforcementDecision]: ...

    def list_allowed_releases(
        self,
        project: str,
    ) -> tuple[AllowedRelease, ...]: ...


class AuditWriter(Protocol):
    def append_in_transaction(
        self,
        connection: Connection,
        event: AuditEventInput,
    ) -> None: ...


class ArtifactStore(Protocol):
    def discover_artifact(
        self,
        artifact: ArtifactInput,
        release: ReleaseInput,
    ) -> None: ...

    def claim_next(
        self,
        worker_id: str,
        lease_until: datetime,
    ) -> ClaimedArtifact | None: ...

    def recover_expired_claims(self, now: datetime) -> int: ...

    def record_verdict(
        self,
        claim: ClaimedArtifact,
        verdict: VerdictInput,
        evidence: Sequence[EvidenceInput],
    ) -> None: ...

    def mark_analysis_error(
        self,
        claim: ClaimedArtifact,
        error: str,
    ) -> None: ...
    def request_rescan(self, sha256: str, actor: str, reason: str) -> None: ...
    def set_manual_override(self, override: ManualOverrideInput) -> None: ...

    def revoke_manual_override(
        self,
        sha256: str,
        actor: str,
        reason: str,
    ) -> None: ...
