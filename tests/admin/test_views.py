from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from devpi_guardian.admin.service import GuardianAdminService
from devpi_guardian.admin.views import (
    ADMIN_SERVICE_REGISTRY_KEY,
    approve_artifact,
    inspect_artifact,
    list_quarantine,
)
from devpi_guardian.verdicts.db import ConnectionFactory, migrate
from devpi_guardian.verdicts.errors import ArtifactNotFound, StoreUnavailable, TransitionConflict
from devpi_guardian.verdicts.models import (
    ArtifactInput,
    ArtifactState,
    Decision,
    ReleaseInput,
    VerdictInput,
)
from devpi_guardian.verdicts.reader import SQLiteVerdictReader
from devpi_guardian.verdicts.store import SQLiteArtifactStore

SHA256 = "a" * 64


class Service:
    def list_quarantine(self, *, states, limit, offset):
        self.list_call = states, limit, offset
        return SimpleNamespace(items=(), total=0, limit=limit, offset=offset)

    def inspect(self, sha256):
        self.inspect_call = sha256
        if sha256 == "b" * 64:
            raise ArtifactNotFound(sha256)
        return SimpleNamespace(summary=SimpleNamespace(sha256=sha256))

    def approve(self, sha256, *, actor, reason):
        self.approve_call = sha256, actor, reason
        if reason == "conflict":
            raise TransitionConflict(sha256)


def request(service, *, sha256=SHA256, params=None, body=None, actor="root"):
    return SimpleNamespace(
        registry={ADMIN_SERVICE_REGISTRY_KEY: service},
        matchdict={"sha256": sha256},
        params=params or {},
        json_body=body or {},
        authenticated_userid=actor,
    )


def test_list_quarantine_validates_filters_and_serializes_page() -> None:
    service = Service()
    response = list_quarantine(
        request(
            service,
            params={"state": "REVIEW,DENY", "limit": "20", "offset": "5"},
        )
    )

    assert response.status_code == 200
    assert response.json_body == {"items": [], "total": 0, "limit": 20, "offset": 5}
    assert service.list_call == (
        (ArtifactState.REVIEW, ArtifactState.DENY),
        20,
        5,
    )


def test_inspect_maps_missing_artifact_to_stable_404() -> None:
    response = inspect_artifact(request(Service(), sha256="b" * 64))

    assert response.status_code == 404
    assert response.json_body["error"]["code"] == "artifact_not_found"


def test_approve_uses_authenticated_actor_and_requires_reason() -> None:
    service = Service()
    response = approve_artifact(
        request(service, body={"reason": "reviewed"}, actor="guardian-admin")
    )

    assert response.status_code == 200
    assert service.approve_call == (SHA256, "guardian-admin", "reviewed")

    invalid = approve_artifact(request(service, body={"reason": ""}))
    assert invalid.status_code == 400
    assert invalid.json_body["error"]["code"] == "invalid_request"


def test_approve_maps_state_conflict_to_409() -> None:
    response = approve_artifact(request(Service(), body={"reason": "conflict"}))

    assert response.status_code == 409
    assert response.json_body["error"]["code"] == "transition_conflict"


def test_admin_view_maps_audit_failure_to_503_and_rolls_back(tmp_path: Path) -> None:
    now = datetime(2026, 8, 24, tzinfo=UTC)
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)

    class FailingAuditWriter:
        def append_in_transaction(self, _connection, _event) -> None:
            raise StoreUnavailable("forced audit failure")

    class WorkingAuditWriter:
        def append_in_transaction(self, connection, event) -> None:
            from devpi_guardian.audit import SQLiteAuditWriter

            SQLiteAuditWriter().append_in_transaction(connection, event)

    store = SQLiteArtifactStore(factory, WorkingAuditWriter(), now=lambda: now)
    sha256 = "a" * 64
    store.discover_artifact(
        ArtifactInput(sha256=sha256, size_bytes=12, discovered_at=now),
        ReleaseInput(
            stage="root/pypi",
            project="demo",
            version="1.0",
            filename="demo-1.0.tar.gz",
            sha256=sha256,
            origin_url="https://example.test/demo-1.0.tar.gz",
            discovered_at=now,
        ),
    )
    claim = store.claim_next("worker", now + timedelta(minutes=5))
    assert claim is not None
    store.record_verdict(
        claim,
        VerdictInput(
            sha256=sha256,
            decision=Decision.REVIEW,
            score=50,
            policy_version="policy-1",
            analyzer_version="analyzer-1",
            baseline_sha256=None,
            baseline_tier=None,
            created_at=now,
        ),
        (),
    )
    store._audit_writer = FailingAuditWriter()
    service = GuardianAdminService(
        reader=SQLiteVerdictReader(factory, now=lambda: now),
        store=store,
        now=lambda: now,
    )

    response = approve_artifact(
        request(service, sha256=sha256, body={"reason": "forced failure"}, actor="admin")
    )

    assert response.status_code == 503
    assert response.json_body["error"]["code"] == "store_unavailable"
    with factory.connect() as connection:
        artifact = connection.execute(
            "SELECT state FROM artifacts WHERE sha256 = ?", (sha256,)
        ).fetchone()
        overrides = connection.execute(
            "SELECT COUNT(*) FROM manual_overrides WHERE sha256 = ?", (sha256,)
        ).fetchone()
    assert artifact[0] == "REVIEW"
    assert overrides[0] == 0
