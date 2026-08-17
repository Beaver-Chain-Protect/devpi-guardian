from __future__ import annotations

import math
import sqlite3
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from devpi_guardian.verdicts.db import ConnectionFactory, migrate
from devpi_guardian.verdicts.errors import (
    ArtifactNotFound,
    InvalidSha256,
    StoreUnavailable,
    TransitionConflict,
)
from devpi_guardian.verdicts.models import (
    ArtifactState,
    Decision,
    EvidenceInput,
    VerdictInput,
)
from devpi_guardian.verdicts.store import SQLiteArtifactStore
from tests.verdicts.test_store_claims import SHA as SHA256
from tests.verdicts.test_store_claims import (
    WrappingFactory,
    artifact,
    fetchall,
    make_store,
    release,
)

NOW = datetime(2026, 8, 17, 0, 0, tzinfo=UTC)
BASELINE_SHA256 = "b" * 64
MISSING_SHA256 = "c" * 64


def verdict(**changes: Any) -> VerdictInput:
    values = {
        "sha256": SHA256,
        "decision": Decision.REVIEW,
        "score": 40.0,
        "policy_version": "policy-1",
        "analyzer_version": "analyzer-1",
        "baseline_sha256": None,
        "created_at": NOW,
    }
    values.update(changes)
    return VerdictInput(**values)


def evidence(**changes: Any) -> EvidenceInput:
    values = {
        "rule_id": "new-network-call",
        "action": Decision.REVIEW,
        "file_path": "demo/client.py",
        "line": 12,
        "message": "new outbound request",
        "details": {"callee": "requests.post"},
    }
    values.update(changes)
    return EvidenceInput(**values)


def unchecked_verdict(**changes: Any) -> VerdictInput:
    valid = verdict()
    values = {
        "sha256": valid.sha256,
        "decision": valid.decision,
        "score": valid.score,
        "policy_version": valid.policy_version,
        "analyzer_version": valid.analyzer_version,
        "baseline_sha256": valid.baseline_sha256,
        "created_at": valid.created_at,
    }
    values.update(changes)
    value = object.__new__(VerdictInput)
    for field_name, field_value in values.items():
        object.__setattr__(value, field_name, field_value)
    return value


def unchecked_evidence(**changes: Any) -> EvidenceInput:
    valid = evidence()
    values = {
        "rule_id": valid.rule_id,
        "action": valid.action,
        "file_path": valid.file_path,
        "line": valid.line,
        "message": valid.message,
        "details": valid.details,
    }
    values.update(changes)
    value = object.__new__(EvidenceInput)
    for field_name, field_value in values.items():
        object.__setattr__(value, field_name, field_value)
    return value


def prepare_scanning(tmp_path, audit_writer) -> SQLiteArtifactStore:
    store = make_store(tmp_path, audit_writer, now=lambda: NOW)
    store.discover_artifact(artifact(), release())
    claimed = store.claim_next("worker", NOW + timedelta(minutes=5))
    assert claimed is not None
    audit_writer.events.clear()
    return store


def install_trigger(store: SQLiteArtifactStore, sql: str) -> None:
    with closing(store.connection_factory.connect()) as connection, connection:
        connection.execute(sql)


def assert_scanning_without_verdict(store: SQLiteArtifactStore) -> None:
    row = fetchall(
        store,
        """
        SELECT state, lease_owner, lease_expires_at, last_error
        FROM artifacts WHERE sha256 = ?
        """,
        (SHA256,),
    )[0]
    assert tuple(row) == (
        ArtifactState.SCANNING.value,
        "worker",
        (NOW + timedelta(minutes=5)).isoformat(),
        None,
    )
    assert fetchall(store, "SELECT COUNT(*) FROM verdicts")[0][0] == 0
    assert fetchall(store, "SELECT COUNT(*) FROM evidence")[0][0] == 0


class NeverConnectFactory:
    def __init__(self, path: Path) -> None:
        self.path = path

    def connect(self):
        raise AssertionError("invalid input opened SQLite")


def test_record_verdict_persists_current_verdict_evidence_and_terminal_state(
    tmp_path,
    audit_writer,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)
    created_at = datetime(
        2026,
        8,
        17,
        9,
        30,
        tzinfo=timezone(timedelta(hours=9)),
    )

    store.record_verdict(
        verdict(created_at=created_at),
        [evidence(details={"z": [2, 1], "a": {"enabled": True}})],
    )

    artifact_row = fetchall(
        store,
        """
        SELECT state, lease_owner, lease_expires_at, last_error, updated_at
        FROM artifacts WHERE sha256 = ?
        """,
        (SHA256,),
    )[0]
    assert tuple(artifact_row) == (
        ArtifactState.REVIEW.value,
        None,
        None,
        None,
        NOW.isoformat(),
    )
    verdict_row = fetchall(
        store,
        """
        SELECT sha256, decision, score, policy_version, analyzer_version,
               baseline_sha256, is_current, created_at
        FROM verdicts
        """,
    )[0]
    assert tuple(verdict_row) == (
        SHA256,
        Decision.REVIEW.value,
        40.0,
        "policy-1",
        "analyzer-1",
        None,
        1,
        NOW.replace(hour=0, minute=30).isoformat(),
    )
    evidence_row = fetchall(
        store,
        """
        SELECT rule_id, action, file_path, line, message, details_json
        FROM evidence
        """,
    )[0]
    assert tuple(evidence_row) == (
        "new-network-call",
        Decision.REVIEW.value,
        "demo/client.py",
        12,
        "new outbound request",
        '{"a":{"enabled":true},"z":[2,1]}',
    )


@pytest.mark.parametrize(
    ("decision", "effective"),
    [
        (Decision.ALLOW, Decision.ALLOW),
        (Decision.REVIEW, Decision.DENY),
        (Decision.DENY, Decision.DENY),
    ],
)
def test_record_verdict_audits_effective_transition_and_versions(
    tmp_path,
    audit_writer,
    decision,
    effective,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)

    store.record_verdict(verdict(decision=decision), ())

    assert len(audit_writer.events) == 1
    event = audit_writer.events[0]
    assert (
        event.actor,
        event.action,
        event.sha256,
        event.previous_decision,
        event.new_decision,
        event.reason,
        event.policy_version,
        event.analyzer_version,
        event.occurred_at,
    ) == (
        "guardian-policy",
        "artifact.verdict_recorded",
        SHA256,
        Decision.DENY,
        effective,
        "automated policy decision",
        "policy-1",
        "analyzer-1",
        NOW,
    )


def test_record_verdict_requires_existing_scanning_artifact(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer, now=lambda: NOW)
    store.discover_artifact(artifact(), release())
    audit_writer.events.clear()

    with pytest.raises(TransitionConflict):
        store.record_verdict(verdict(), ())
    with pytest.raises(TransitionConflict):
        store.record_verdict(verdict(sha256=MISSING_SHA256), ())

    assert fetchall(store, "SELECT COUNT(*) FROM verdicts")[0][0] == 0
    row = fetchall(
        store,
        "SELECT state FROM artifacts WHERE sha256 = ?",
        (SHA256,),
    )[0]
    assert row[0] == ArtifactState.DISCOVERED.value
    assert audit_writer.events == []


def test_duplicate_verdict_submission_rolls_back_cleanly(
    tmp_path,
    audit_writer,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)
    store.record_verdict(verdict(decision=Decision.ALLOW), ())
    original_events = list(audit_writer.events)

    with pytest.raises(TransitionConflict):
        store.record_verdict(verdict(decision=Decision.DENY), [evidence()])

    row = fetchall(
        store,
        "SELECT decision, is_current FROM verdicts WHERE sha256 = ?",
        (SHA256,),
    )[0]
    assert tuple(row) == (Decision.ALLOW.value, 1)
    assert fetchall(store, "SELECT COUNT(*) FROM verdicts")[0][0] == 1
    assert fetchall(store, "SELECT COUNT(*) FROM evidence")[0][0] == 0
    assert audit_writer.events == original_events


def test_racing_verdict_submissions_have_one_winner(
    tmp_path,
    audit_writer,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)

    def submit(decision: Decision) -> Decision | None:
        try:
            store.record_verdict(verdict(decision=decision), ())
        except TransitionConflict:
            return None
        return decision

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(submit, (Decision.ALLOW, Decision.DENY)))

    assert len([result for result in results if result is not None]) == 1
    assert fetchall(store, "SELECT COUNT(*) FROM verdicts")[0][0] == 1
    assert len(audit_writer.events) == 1


def test_record_verdict_preserves_history_and_replaces_only_current_marker(
    tmp_path,
    audit_writer,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)
    with closing(store.connection_factory.connect()) as connection, connection:
        old_cursor = connection.execute(
            """
            INSERT INTO verdicts(
                sha256, decision, score, policy_version, analyzer_version,
                baseline_sha256, is_current, created_at
            ) VALUES (?, 'DENY', 99, 'policy-old', 'analyzer-old', NULL, 1, ?)
            """,
            (SHA256, (NOW - timedelta(days=1)).isoformat()),
        )
        connection.execute(
            """
            INSERT INTO evidence(
                verdict_id, rule_id, action, file_path, line, message,
                details_json
            ) VALUES (?, 'old-rule', 'DENY', NULL, NULL, 'old evidence', '{}')
            """,
            (old_cursor.lastrowid,),
        )

    store.record_verdict(verdict(decision=Decision.REVIEW), [evidence()])

    verdict_rows = fetchall(
        store,
        """
        SELECT decision, score, policy_version, analyzer_version, is_current
        FROM verdicts ORDER BY id
        """,
    )
    assert [tuple(row) for row in verdict_rows] == [
        (Decision.DENY.value, 99.0, "policy-old", "analyzer-old", 0),
        (Decision.REVIEW.value, 40.0, "policy-1", "analyzer-1", 1),
    ]
    evidence_rows = fetchall(
        store,
        "SELECT rule_id, message FROM evidence ORDER BY id",
    )
    assert [tuple(row) for row in evidence_rows] == [
        ("old-rule", "old evidence"),
        ("new-network-call", "new outbound request"),
    ]


def test_record_verdict_accepts_existing_baseline_foreign_key(
    tmp_path,
    audit_writer,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)
    store.discover_artifact(
        artifact(sha256=BASELINE_SHA256),
        release(
            sha256=BASELINE_SHA256,
            version="0.9.0",
            filename="demo_package-0.9.0.whl",
        ),
    )
    audit_writer.events.clear()

    store.record_verdict(verdict(baseline_sha256=BASELINE_SHA256), ())

    row = fetchall(store, "SELECT baseline_sha256 FROM verdicts")[0]
    assert row[0] == BASELINE_SHA256


def test_record_verdict_rejects_missing_baseline_without_changes(
    tmp_path,
    audit_writer,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)

    with pytest.raises(ArtifactNotFound):
        store.record_verdict(verdict(baseline_sha256=BASELINE_SHA256), ())

    assert_scanning_without_verdict(store)
    assert audit_writer.events == []


@pytest.mark.parametrize(
    ("changes", "error_type"),
    [
        ({"sha256": "A" * 64}, InvalidSha256),
        ({"decision": "ALLOW"}, ValueError),
        ({"score": True}, ValueError),
        ({"score": math.nan}, ValueError),
        ({"score": "40"}, ValueError),
        ({"score": 2**2000}, ValueError),
        ({"policy_version": None}, ValueError),
        ({"policy_version": " "}, ValueError),
        ({"policy_version": "policy\x00unsafe"}, ValueError),
        ({"policy_version": "p" * 4097}, ValueError),
        ({"analyzer_version": None}, ValueError),
        ({"analyzer_version": "a" * 4097}, ValueError),
        ({"baseline_sha256": "invalid"}, InvalidSha256),
        ({"created_at": NOW.replace(tzinfo=None)}, ValueError),
        ({"created_at": "2026-08-17"}, ValueError),
    ],
)
def test_record_verdict_validates_mutated_dto_before_connecting(
    tmp_path,
    audit_writer,
    changes,
    error_type,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(error_type):
        store.record_verdict(unchecked_verdict(**changes), ())

    assert audit_writer.events == []


def test_record_verdict_requires_exact_verdict_dto_before_connecting(
    tmp_path,
    audit_writer,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(ValueError, match="VerdictInput"):
        store.record_verdict(object(), ())


@pytest.mark.parametrize("bad_evidence", [None, "text", b"bytes", 123])
def test_record_verdict_rejects_non_sequence_evidence_before_connecting(
    tmp_path,
    audit_writer,
    bad_evidence,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(ValueError, match="sequence"):
        store.record_verdict(verdict(), bad_evidence)


def test_record_verdict_rejects_iterator_evidence_before_connecting(
    tmp_path,
    audit_writer,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )
    iterator: Iterator[EvidenceInput] = iter([evidence()])

    with pytest.raises(ValueError, match="sequence"):
        store.record_verdict(verdict(), iterator)


def test_record_verdict_requires_actual_evidence_dto_before_connecting(
    tmp_path,
    audit_writer,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(ValueError, match="EvidenceInput"):
        store.record_verdict(verdict(), [{}])


@pytest.mark.parametrize(
    "changes",
    [
        {"rule_id": None},
        {"rule_id": " "},
        {"rule_id": "rule\x00unsafe"},
        {"rule_id": "r" * 4097},
        {"action": "REVIEW"},
        {"file_path": 123},
        {"file_path": " "},
        {"file_path": "path\x00unsafe"},
        {"file_path": "p" * 4097},
        {"line": True},
        {"line": 0},
        {"line": 1.5},
        {"line": 2**63},
        {"message": None},
        {"message": " "},
        {"message": "message\x00unsafe"},
        {"message": "m" * 4097},
        {"details": {2: "non-string key"}},
        {"details": {"not_finite": math.inf}},
        {"details": {"unsupported": object()}},
    ],
)
def test_record_verdict_validates_mutated_evidence_before_connecting(
    tmp_path,
    audit_writer,
    changes,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(ValueError):
        store.record_verdict(verdict(), [unchecked_evidence(**changes)])


@pytest.mark.parametrize(
    "trigger_sql",
    [
        """
        CREATE TRIGGER ignore_verdict_insert BEFORE INSERT ON verdicts
        BEGIN SELECT RAISE(IGNORE); END
        """,
        """
        CREATE TRIGGER ignore_evidence_insert BEFORE INSERT ON evidence
        BEGIN SELECT RAISE(IGNORE); END
        """,
        """
        CREATE TRIGGER ignore_terminal_update
        BEFORE UPDATE OF state ON artifacts
        WHEN OLD.state = 'SCANNING'
        BEGIN SELECT RAISE(IGNORE); END
        """,
    ],
)
def test_record_verdict_rejects_ignored_state_changing_writes(
    tmp_path,
    audit_writer,
    trigger_sql,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)
    install_trigger(store, trigger_sql)

    with pytest.raises(TransitionConflict):
        store.record_verdict(verdict(), [evidence()])

    assert_scanning_without_verdict(store)
    assert audit_writer.events == []


def test_record_verdict_rejects_ignored_current_verdict_update(
    tmp_path,
    audit_writer,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)
    with closing(store.connection_factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO verdicts(
                sha256, decision, score, policy_version, analyzer_version,
                baseline_sha256, is_current, created_at
            ) VALUES (?, 'DENY', 99, 'policy-old', 'analyzer-old', NULL, 1, ?)
            """,
            (SHA256, (NOW - timedelta(days=1)).isoformat()),
        )
        connection.execute(
            """
            CREATE TRIGGER ignore_current_verdict_update
            BEFORE UPDATE OF is_current ON verdicts
            WHEN OLD.is_current = 1
            BEGIN SELECT RAISE(IGNORE); END
            """
        )

    with pytest.raises(TransitionConflict):
        store.record_verdict(verdict(), ())

    rows = fetchall(store, "SELECT decision, is_current FROM verdicts")
    assert [tuple(row) for row in rows] == [(Decision.DENY.value, 1)]
    artifact_row = fetchall(
        store,
        "SELECT state, lease_owner FROM artifacts WHERE sha256 = ?",
        (SHA256,),
    )[0]
    assert tuple(artifact_row) == (ArtifactState.SCANNING.value, "worker")
    assert audit_writer.events == []


def test_record_verdict_checks_final_artifact_state(
    tmp_path,
    audit_writer,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)
    install_trigger(
        store,
        """
        CREATE TRIGGER rewrite_terminal_state
        AFTER UPDATE OF state ON artifacts
        WHEN NEW.state = 'ALLOW'
        BEGIN
            UPDATE artifacts SET state = 'DENY' WHERE sha256 = NEW.sha256;
        END
        """,
    )

    with pytest.raises(TransitionConflict):
        store.record_verdict(verdict(decision=Decision.ALLOW), [evidence()])

    assert_scanning_without_verdict(store)
    assert audit_writer.events == []


def test_audit_failure_rolls_back_verdict_evidence_and_state(
    tmp_path,
    audit_writer,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)
    audit_writer.fail = True

    with pytest.raises(RuntimeError, match="audit unavailable"):
        store.record_verdict(verdict(), [evidence()])

    assert_scanning_without_verdict(store)


def test_commit_failure_rolls_back_verdict_evidence_and_state(
    tmp_path,
    audit_writer,
) -> None:
    base_factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(base_factory)
    base_store = SQLiteArtifactStore(
        base_factory,
        audit_writer,
        now=lambda: NOW,
    )
    base_store.discover_artifact(artifact(), release())
    base_store.claim_next("worker", NOW + timedelta(minutes=5))
    audit_writer.events.clear()
    wrapping_factory = WrappingFactory(base_factory, fail_commit=True)
    store = SQLiteArtifactStore(
        wrapping_factory,
        audit_writer,
        now=lambda: NOW,
    )

    with pytest.raises(StoreUnavailable) as error:
        store.record_verdict(verdict(), [evidence()])

    assert isinstance(error.value.__cause__, sqlite3.OperationalError)
    assert str(error.value.__cause__) == "commit failed"
    assert wrapping_factory.last_connection.rollback_called is True
    with closing(base_factory.connect()) as connection:
        artifact_row = connection.execute(
            "SELECT state, lease_owner FROM artifacts WHERE sha256 = ?",
            (SHA256,),
        ).fetchone()
        verdict_query = "SELECT COUNT(*) FROM verdicts"
        evidence_query = "SELECT COUNT(*) FROM evidence"
        verdict_count = connection.execute(verdict_query).fetchone()[0]
        evidence_count = connection.execute(evidence_query).fetchone()[0]
    assert tuple(artifact_row) == (ArtifactState.SCANNING.value, "worker")
    assert verdict_count == 0
    assert evidence_count == 0


def test_unexpected_sqlite_error_recording_verdict_maps_to_store_unavailable(
    tmp_path,
    audit_writer,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)
    install_trigger(
        store,
        """
        CREATE TRIGGER abort_verdict_insert BEFORE INSERT ON verdicts
        BEGIN SELECT RAISE(ABORT, 'verdict storage failed'); END
        """,
    )

    with pytest.raises(StoreUnavailable) as error:
        store.record_verdict(verdict(), ())

    assert isinstance(error.value.__cause__, sqlite3.IntegrityError)
    assert_scanning_without_verdict(store)
    assert audit_writer.events == []


def test_analysis_error_is_terminal_sanitized_and_audited(
    tmp_path,
    audit_writer,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)
    raw_error = "line one\nline two\x00\t" + "x" * 5000 + "TAIL-SECRET"

    store.mark_analysis_error(SHA256, raw_error)

    row = fetchall(
        store,
        """
        SELECT state, lease_owner, lease_expires_at, last_error, updated_at
        FROM artifacts WHERE sha256 = ?
        """,
        (SHA256,),
    )[0]
    assert row["state"] == ArtifactState.ERROR.value
    assert row["lease_owner"] is None
    assert row["lease_expires_at"] is None
    assert row["updated_at"] == NOW.isoformat()
    assert len(row["last_error"]) == 4096
    assert "\n" not in row["last_error"]
    assert "\x00" not in row["last_error"]
    assert "\t" not in row["last_error"]
    assert "TAIL-SECRET" not in row["last_error"]
    assert len(audit_writer.events) == 1
    event = audit_writer.events[0]
    assert (
        event.actor,
        event.action,
        event.sha256,
        event.previous_decision,
        event.new_decision,
        event.reason,
        event.policy_version,
        event.analyzer_version,
        event.occurred_at,
    ) == (
        "guardian-worker",
        "artifact.analysis_error",
        SHA256,
        Decision.DENY,
        Decision.DENY,
        "analysis failed",
        None,
        None,
        NOW,
    )


def test_analysis_error_requires_existing_scanning_artifact(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer, now=lambda: NOW)
    store.discover_artifact(artifact(), release())
    audit_writer.events.clear()

    with pytest.raises(TransitionConflict):
        store.mark_analysis_error(SHA256, "failed")
    with pytest.raises(TransitionConflict):
        store.mark_analysis_error(MISSING_SHA256, "failed")

    row = fetchall(
        store,
        "SELECT state, last_error FROM artifacts WHERE sha256 = ?",
        (SHA256,),
    )[0]
    assert tuple(row) == (ArtifactState.DISCOVERED.value, None)
    assert audit_writer.events == []


@pytest.mark.parametrize(
    ("sha256", "error_value", "error_type"),
    [
        ("A" * 64, "failed", InvalidSha256),
        (SHA256, None, ValueError),
        (SHA256, 123, ValueError),
        (SHA256, b"failed", ValueError),
    ],
)
def test_analysis_error_validates_inputs_before_connecting(
    tmp_path,
    audit_writer,
    sha256,
    error_value,
    error_type,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(error_type):
        store.mark_analysis_error(sha256, error_value)

    assert audit_writer.events == []


def test_analysis_error_replaces_unsafe_unicode_deterministically(
    tmp_path,
    audit_writer,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)

    store.mark_analysis_error(SHA256, "bad\ud800value\x7f")

    row = fetchall(
        store,
        "SELECT last_error FROM artifacts WHERE sha256 = ?",
        (SHA256,),
    )[0]
    assert row[0] == "bad value "


def test_ignored_analysis_error_update_fails_closed(
    tmp_path,
    audit_writer,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)
    install_trigger(
        store,
        """
        CREATE TRIGGER ignore_analysis_error
        BEFORE UPDATE OF state ON artifacts
        WHEN NEW.state = 'ERROR'
        BEGIN SELECT RAISE(IGNORE); END
        """,
    )

    with pytest.raises(TransitionConflict):
        store.mark_analysis_error(SHA256, "failed")

    assert_scanning_without_verdict(store)
    assert audit_writer.events == []


def test_analysis_error_checks_final_artifact_state(
    tmp_path,
    audit_writer,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)
    install_trigger(
        store,
        """
        CREATE TRIGGER rewrite_error_state
        AFTER UPDATE OF state ON artifacts
        WHEN NEW.state = 'ERROR'
        BEGIN
            UPDATE artifacts
            SET state = 'DISCOVERED', lease_owner = NULL,
                lease_expires_at = NULL
            WHERE sha256 = NEW.sha256;
        END
        """,
    )

    with pytest.raises(TransitionConflict):
        store.mark_analysis_error(SHA256, "failed")

    assert_scanning_without_verdict(store)
    assert audit_writer.events == []


def test_audit_failure_rolls_back_analysis_error(
    tmp_path,
    audit_writer,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)
    audit_writer.fail = True

    with pytest.raises(RuntimeError, match="audit unavailable"):
        store.mark_analysis_error(SHA256, "failed")

    assert_scanning_without_verdict(store)


def test_commit_failure_rolls_back_analysis_error(
    tmp_path,
    audit_writer,
) -> None:
    base_factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(base_factory)
    base_store = SQLiteArtifactStore(
        base_factory,
        audit_writer,
        now=lambda: NOW,
    )
    base_store.discover_artifact(artifact(), release())
    base_store.claim_next("worker", NOW + timedelta(minutes=5))
    audit_writer.events.clear()
    wrapping_factory = WrappingFactory(base_factory, fail_commit=True)
    store = SQLiteArtifactStore(
        wrapping_factory,
        audit_writer,
        now=lambda: NOW,
    )

    with pytest.raises(StoreUnavailable) as error:
        store.mark_analysis_error(SHA256, "failed")

    assert isinstance(error.value.__cause__, sqlite3.OperationalError)
    assert str(error.value.__cause__) == "commit failed"
    assert wrapping_factory.last_connection.rollback_called is True
    with closing(base_factory.connect()) as connection:
        row = connection.execute(
            """
            SELECT state, lease_owner, lease_expires_at, last_error
            FROM artifacts WHERE sha256 = ?
            """,
            (SHA256,),
        ).fetchone()
    assert tuple(row) == (
        ArtifactState.SCANNING.value,
        "worker",
        (NOW + timedelta(minutes=5)).isoformat(),
        None,
    )


def test_unexpected_sqlite_error_marking_analysis_error_maps_to_unavailable(
    tmp_path,
    audit_writer,
) -> None:
    store = prepare_scanning(tmp_path, audit_writer)
    install_trigger(
        store,
        """
        CREATE TRIGGER abort_analysis_error
        BEFORE UPDATE OF state ON artifacts
        WHEN NEW.state = 'ERROR'
        BEGIN SELECT RAISE(ABORT, 'analysis error storage failed'); END
        """,
    )

    with pytest.raises(StoreUnavailable) as error:
        store.mark_analysis_error(SHA256, "failed")

    assert isinstance(error.value.__cause__, sqlite3.IntegrityError)
    assert_scanning_without_verdict(store)
    assert audit_writer.events == []
