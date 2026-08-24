from __future__ import annotations

from datetime import UTC, datetime, timedelta

from devpi_guardian.admin.service import GuardianAdminService
from devpi_guardian.verdicts.models import (
    ArtifactAdminDetails,
    ArtifactAdminSummary,
    ArtifactState,
    Decision,
    DecisionSource,
    QuarantinePage,
)

SHA256 = "a" * 64
NOW = datetime(2026, 8, 24, tzinfo=UTC)


class Reader:
    def __init__(self) -> None:
        self.summary = ArtifactAdminSummary(
            sha256=SHA256,
            size_bytes=42,
            state=ArtifactState.REVIEW,
            discovered_at=NOW,
            updated_at=NOW,
            cooldown_until=None,
            last_error=None,
        )
        self.details = ArtifactAdminDetails(
            summary=self.summary,
            allowed=False,
            effective_decision=Decision.DENY,
            decision_source=DecisionSource.AUTOMATED,
            policy_version="policy-1",
            analyzer_version="analyzer-1",
            baseline_sha256=None,
            baseline_tier=None,
            releases=(),
            evidence=(),
        )

    def list_quarantine(self, *, states, limit, offset):
        self.list_call = states, limit, offset
        return QuarantinePage((self.summary,), 1, limit, offset)

    def get_artifact_details(self, sha256):
        self.inspect_call = sha256
        return self.details

    def health(self):
        return {"database": "ok", "schema_version": 3}


class Store:
    def __init__(self) -> None:
        self.overrides = []
        self.rescans = []

    def set_manual_override(self, override):
        self.overrides.append(override)

    def request_rescan(self, sha256, actor, reason):
        self.rescans.append((sha256, actor, reason))


def test_service_lists_quarantine_and_inspects_by_sha256() -> None:
    reader = Reader()
    service = GuardianAdminService(reader=reader, store=Store(), now=lambda: NOW)

    page = service.list_quarantine(
        states=(ArtifactState.REVIEW,),
        limit=25,
        offset=10,
    )
    details = service.inspect(SHA256)

    assert page.total == 1
    assert details.summary.sha256 == SHA256
    assert reader.list_call == ((ArtifactState.REVIEW,), 25, 10)
    assert reader.inspect_call == SHA256


def test_service_approve_block_exception_and_rescan_use_f4_transitions() -> None:
    store = Store()
    service = GuardianAdminService(reader=Reader(), store=store, now=lambda: NOW)

    service.approve(SHA256, actor="root", reason="reviewed")
    service.block(SHA256, actor="root", reason="malicious behavior")
    expires_at = NOW + timedelta(hours=2)
    service.add_exception(
        SHA256,
        actor="root",
        reason="temporary build unblock",
        expires_at=expires_at,
    )
    service.rescan(SHA256, actor="root", reason="policy updated")

    assert [item.decision for item in store.overrides] == [
        Decision.ALLOW,
        Decision.DENY,
        Decision.ALLOW,
    ]
    assert store.overrides[0].expires_at is None
    assert store.overrides[2].expires_at == expires_at
    assert all(item.actor == "root" for item in store.overrides)
    assert store.rescans == [(SHA256, "root", "policy updated")]


def test_service_health_reports_write_readiness() -> None:
    ready = GuardianAdminService(reader=Reader(), store=Store(), now=lambda: NOW)
    read_only = GuardianAdminService(reader=Reader(), store=None, now=lambda: NOW)

    assert ready.health()["mutations_ready"] is True
    assert read_only.health()["mutations_ready"] is False
