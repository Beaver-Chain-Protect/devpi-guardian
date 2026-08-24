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


class Operations:
    def __init__(self) -> None:
        self.calls = []

    def worker_health(self):
        return {
            "status": "running",
            "pending_jobs": 2,
            "processing_jobs": 1,
            "failed_jobs": 0,
        }

    def list_audit(self, *, sha256, actor, action, limit, offset):
        self.calls.append(("audit", sha256, actor, action, limit, offset))
        return {"items": [{"action": "artifact.approve"}], "total": 1}

    def artifact_diff(self, sha256):
        self.calls.append(("diff", sha256))
        return {"sha256": sha256, "files": {"added": ["pkg/new.py"]}}

    def list_baselines(self, project):
        self.calls.append(("baseline-list", project))
        return ({"project": project, "sha256": SHA256},)

    def add_baseline(self, sha256, *, actor, reason):
        self.calls.append(("baseline-add", sha256, actor, reason))

    def remove_baseline(self, sha256, *, actor, reason):
        self.calls.append(("baseline-remove", sha256, actor, reason))

    def import_baselines(self, records, *, actor, reason):
        self.calls.append(("baseline-import", records, actor, reason))
        return {"imported": len(records)}

    def validate_policy(self, policy):
        self.calls.append(("policy-validate", policy))
        return {"valid": True, "policy_version": "policy-2"}

    def simulate_policy(self, policy, *, sha256):
        self.calls.append(("policy-simulate", policy, sha256))
        return {"sha256": sha256, "decision": "REVIEW"}


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
    operations = Operations()
    ready = GuardianAdminService(
        reader=Reader(),
        store=Store(),
        worker_health_reader=operations,
        audit_reader=operations,
        diff_reader=operations,
        baseline_manager=operations,
        policy_manager=operations,
        now=lambda: NOW,
    )
    read_only = GuardianAdminService(reader=Reader(), store=None, now=lambda: NOW)

    assert ready.health()["mutations_ready"] is True
    assert ready.health()["worker"]["status"] == "running"
    assert ready.health()["features"]["audit"] is True
    assert read_only.health()["mutations_ready"] is False
    assert read_only.health()["worker"]["status"] == "unavailable"
    assert read_only.health()["features"]["audit"] is False


def test_service_delegates_remaining_f11_operations() -> None:
    operations = Operations()
    service = GuardianAdminService(
        reader=Reader(),
        store=Store(),
        worker_health_reader=operations,
        audit_reader=operations,
        diff_reader=operations,
        baseline_manager=operations,
        policy_manager=operations,
        now=lambda: NOW,
    )
    policy = {"revision": "2"}
    records = ({"sha256": SHA256},)

    assert (
        service.list_audit(
            sha256=SHA256,
            actor="root",
            action="artifact.approve",
            limit=20,
            offset=0,
        )["total"]
        == 1
    )
    assert service.artifact_diff(SHA256)["sha256"] == SHA256
    assert service.list_baselines("demo")[0]["project"] == "demo"
    service.add_baseline(SHA256, actor="root", reason="trusted")
    service.remove_baseline(SHA256, actor="root", reason="revoked")
    assert service.import_baselines(records, actor="root", reason="bootstrap") == {"imported": 1}
    assert service.validate_policy(policy)["valid"] is True
    assert service.simulate_policy(policy, sha256=SHA256)["decision"] == "REVIEW"

    assert operations.calls == [
        ("audit", SHA256, "root", "artifact.approve", 20, 0),
        ("diff", SHA256),
        ("baseline-list", "demo"),
        ("baseline-add", SHA256, "root", "trusted"),
        ("baseline-remove", SHA256, "root", "revoked"),
        ("baseline-import", records, "root", "bootstrap"),
        ("policy-validate", policy),
        ("policy-simulate", policy, SHA256),
    ]


def test_service_fails_closed_when_optional_operation_provider_is_missing() -> None:
    from devpi_guardian.admin.service import AdminFeatureUnavailable

    service = GuardianAdminService(reader=Reader(), store=Store(), now=lambda: NOW)

    for operation in (
        lambda: service.artifact_diff(SHA256),
        lambda: service.list_audit(
            sha256=None,
            actor=None,
            action=None,
            limit=20,
            offset=0,
        ),
        lambda: service.list_baselines("demo"),
        lambda: service.validate_policy({"revision": "2"}),
    ):
        try:
            operation()
        except AdminFeatureUnavailable:
            pass
        else:
            raise AssertionError("optional operation must fail closed")
