import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from devpi_guardian.verdicts.errors import TransitionConflict
from devpi_guardian.verdicts.models import (
    ArtifactAdminDetails,
    ArtifactAdminSummary,
    ArtifactState,
    Decision,
    EvidenceRecord,
    QuarantinePage,
    ReleaseArtifact,
    VerdictInput,
)
from devpi_guardian.verdicts.reader import SQLiteVerdictReader
from tests.verdicts.test_store_claims import artifact, make_store, release

SHA = "a" * 64
NOW = datetime(2026, 8, 17, tzinfo=UTC)


def _verdict(**changes):
    values = {
        "sha256": SHA,
        "decision": Decision.ALLOW,
        "score": 100.0,
        "policy_version": "policy-1",
        "analyzer_version": "analyzer-1",
        "baseline_sha256": None,
        "baseline_tier": None,
        "created_at": NOW,
    }
    values.update(changes)
    return VerdictInput(**values)


def test_verdict_cooldown_requires_future_allow_window() -> None:
    with pytest.raises(ValueError, match="cooldown requires an ALLOW"):
        _verdict(decision=Decision.REVIEW, cooldown_until=NOW + timedelta(hours=1))
    with pytest.raises(ValueError, match="cooldown_until must be later"):
        _verdict(cooldown_until=NOW)


def test_verdict_models_and_reader_api_are_available(tmp_path, audit_writer) -> None:
    assert ReleaseArtifact.__dataclass_fields__["size_bytes"]
    assert ArtifactAdminSummary.__dataclass_fields__["cooldown_until"]
    assert EvidenceRecord.__dataclass_fields__["details"]
    assert ArtifactAdminDetails.__dataclass_fields__["evidence"]
    assert QuarantinePage.__dataclass_fields__["items"]

    store = make_store(tmp_path, audit_writer, now=lambda: NOW)
    store.discover_artifact(artifact(), release())
    claim = store.claim_next("worker", NOW + timedelta(hours=1))
    assert claim is not None
    store.record_verdict(
        claim,
        _verdict(cooldown_until=NOW + timedelta(hours=1)),
        (),
    )
    reader = SQLiteVerdictReader(store.connection_factory, now=lambda: NOW)
    decision = reader.get_effective_decision(SHA)
    assert decision.allowed is False
    assert decision.cooldown_finished is False
    assert decision.cooldown_until == NOW + timedelta(hours=1)
    assert reader.get_artifact_releases(SHA)
    assert reader.list_release_artifacts("DEMO_PACKAGE", "1.0.0")
    assert reader.list_quarantine(states=(ArtifactState.REVIEW,), limit=10, offset=0).total == 0
    assert reader.get_artifact_details(SHA).summary.sha256 == SHA
    assert reader.health()["schema_version"] == 6


def test_allow_cooldown_exact_finish_boundary_is_allowed(tmp_path, audit_writer) -> None:
    store = make_store(tmp_path, audit_writer, now=lambda: NOW)
    store.discover_artifact(artifact(), release())
    claim = store.claim_next("worker", NOW + timedelta(hours=2))
    assert claim is not None
    cooldown_until = NOW + timedelta(hours=1)
    store.record_verdict(claim, _verdict(cooldown_until=cooldown_until), ())

    before = SQLiteVerdictReader(
        store.connection_factory,
        now=lambda: cooldown_until - timedelta(microseconds=1),
    ).get_effective_decision(SHA)
    exact = SQLiteVerdictReader(
        store.connection_factory,
        now=lambda: cooldown_until,
    ).get_effective_decision(SHA)
    after = SQLiteVerdictReader(
        store.connection_factory,
        now=lambda: cooldown_until + timedelta(microseconds=1),
    ).get_effective_decision(SHA)

    assert before.allowed is False
    assert exact.allowed is True
    assert after.allowed is True


def test_baseline_eligibility_requires_allow_and_is_a_public_store_api(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer, now=lambda: NOW)
    store.discover_artifact(artifact(), release())
    with pytest.raises(TransitionConflict):
        store.set_baseline_eligibility(
            SHA,
            enabled=True,
            actor="admin",
            reason="trusted",
        )


def test_baseline_eligibility_history_and_release_exclusion(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer, now=lambda: NOW)
    store.discover_artifact(artifact(), release())
    claim = store.claim_next("worker", NOW + timedelta(hours=1))
    assert claim is not None
    store.record_verdict(claim, _verdict(), ())
    audit_writer.events.clear()

    store.set_baseline_eligibility(
        SHA,
        enabled=True,
        actor="admin",
        reason="trusted release",
    )
    assert SQLiteVerdictReader(store.connection_factory, now=lambda: NOW).list_allowed_releases(
        "demo-package"
    )
    store.set_baseline_eligibility(
        SHA,
        enabled=False,
        actor="admin",
        reason="remove trust",
    )
    reader = SQLiteVerdictReader(store.connection_factory, now=lambda: NOW)
    assert reader.list_allowed_releases("demo-package") == ()
    rows = []
    with store.connection_factory.connect() as connection:
        rows = connection.execute(
            "SELECT enabled, is_current FROM baseline_overrides ORDER BY id"
        ).fetchall()
    assert [tuple(row) for row in rows] == [(1, 0), (0, 1)]
    assert [event.action for event in audit_writer.events] == [
        "baseline.added",
        "baseline.removed",
    ]
    with store.connection_factory.connect() as connection, connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE baseline_overrides SET reason = 'changed' WHERE id = 1")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM baseline_overrides WHERE id = 1")

    audit_writer.fail = True
    with pytest.raises(RuntimeError, match="audit unavailable"):
        store.set_baseline_eligibility(
            SHA,
            enabled=True,
            actor="admin",
            reason="failed transaction",
        )
    audit_writer.fail = False
    with store.connection_factory.connect() as connection:
        rows = connection.execute(
            "SELECT enabled, is_current FROM baseline_overrides ORDER BY id"
        ).fetchall()
    assert [tuple(row) for row in rows] == [(1, 0), (0, 1)]
