from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone

import pytest

from devpi_guardian.audit import (
    AuditVerificationResult,
    SQLiteAuditWriter,
    verify_audit_chain,
)
from devpi_guardian.audit.writer import _event_hash
from devpi_guardian.policy import PolicyConfig, PolicyEngine
from devpi_guardian.verdicts import ConnectionFactory, Decision, migrate
from devpi_guardian.verdicts import db as verdicts_db
from devpi_guardian.verdicts.errors import StoreUnavailable
from devpi_guardian.verdicts.models import AuditEventInput, VerdictInput
from devpi_guardian.verdicts.store import SQLiteArtifactStore

SHA = "a" * 64
NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)


def _event(number: int = 0, *, when: datetime = NOW) -> AuditEventInput:
    return AuditEventInput(
        actor="worker-unicode-✓",
        action=f"artifact.action.{number}",
        sha256=SHA,
        previous_decision=Decision.REVIEW,
        new_decision=Decision.ALLOW,
        reason="unicode ✓ reason",
        policy_version="policy/1",
        analyzer_version="analyzer/1",
        occurred_at=when,
    )


def _db(tmp_path):
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    with closing(factory.connect()) as connection, connection:
        timestamp = NOW.isoformat()
        connection.execute(
            """
            INSERT INTO artifacts(sha256, size_bytes, state, discovered_at, updated_at)
            VALUES (?, 1, 'DISCOVERED', ?, ?)
            """,
            (SHA, timestamp, timestamp),
        )
    return factory


def _exact_update_guard_sql() -> str:
    migration = verdicts_db._read_migration(5)
    start = migration.index("CREATE TRIGGER audit_events_update_guard")
    end = migration.index("END;", start) + len("END;")
    return migration[start:end]


def test_writer_requires_transaction_and_preserves_outer_commit(tmp_path):
    factory = _db(tmp_path)
    writer = SQLiteAuditWriter()
    with closing(factory.connect()) as connection:
        with pytest.raises(ValueError, match="transaction"):
            writer.append_in_transaction(connection, _event())
        connection.execute("BEGIN IMMEDIATE")
        writer.append_in_transaction(connection, _event())
        assert connection.in_transaction is True
        connection.commit()
    result = verify_audit_chain(factory)
    assert result == AuditVerificationResult(True, 1, result.head, None, None)
    assert result.head is not None


class _NoFetchallCursor:
    def __init__(self, cursor):
        self._cursor = cursor

    def __iter__(self):
        return iter(self._cursor)

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        raise AssertionError("audit verification must stream rows")


class _NoFetchallConnection:
    def __init__(self, connection):
        self._connection = connection

    def execute(self, *args, **kwargs):
        return _NoFetchallCursor(self._connection.execute(*args, **kwargs))

    @property
    def in_transaction(self):
        return self._connection.in_transaction

    def rollback(self):
        return self._connection.rollback()

    def close(self):
        return self._connection.close()


class _NoFetchallFactory:
    def __init__(self, factory):
        self._factory = factory
        self.path = factory.path

    def connect(self):
        return _NoFetchallConnection(self._factory.connect())


class _CountMismatchConnection(_NoFetchallConnection):
    def __init__(self, connection, count):
        super().__init__(connection)
        self._count = count

    def execute(self, sql, *args, **kwargs):
        if "SELECT COUNT(*) FROM audit_events" in sql:
            return _CountCursor(self._count)
        return super().execute(sql, *args, **kwargs)


class _CountCursor:
    def __init__(self, count):
        self._count = count

    def fetchone(self):
        return (self._count,)


class _CountMismatchFactory:
    def __init__(self, factory, count):
        self._factory = factory
        self.path = factory.path
        self._count = count

    def connect(self):
        return _CountMismatchConnection(self._factory.connect(), self._count)


class _CleanupFailureConnection(_NoFetchallConnection):
    def rollback(self):
        raise sqlite3.OperationalError("rollback failed")

    def close(self):
        raise sqlite3.OperationalError("close failed")


class _ProcessCleanupConnection(_CleanupFailureConnection):
    def close(self):
        raise KeyboardInterrupt("close interrupted")


class _PrimaryProcessCleanupConnection(_ProcessCleanupConnection):
    def execute(self, _sql, *_args, **_kwargs):
        raise sqlite3.OperationalError("primary failed")


class _CleanupFailureFactory:
    def __init__(self, factory, *, primary=False):
        self._factory = factory
        self.path = factory.path
        self._primary = primary

    def connect(self):
        connection = _CleanupFailureConnection(self._factory.connect())
        if self._primary:
            connection.execute = self._execute_primary
        return connection

    @staticmethod
    def _execute_primary(_sql, *_args, **_kwargs):
        raise sqlite3.OperationalError("primary failed")


class _ProcessCleanupFactory(_CleanupFailureFactory):
    def connect(self):
        return _ProcessCleanupConnection(self._factory.connect())


class _PrimaryProcessCleanupFactory(_CleanupFailureFactory):
    def connect(self):
        return _PrimaryProcessCleanupConnection(self._factory.connect())


class _TraceFactory:
    def __init__(self, factory):
        self._factory = factory
        self.path = factory.path
        self.statements = []

    def connect(self):
        connection = self._factory.connect()
        connection.set_trace_callback(self.statements.append)
        return connection


def test_verifier_streams_audit_cursor_without_fetchall(tmp_path):
    factory = _db(tmp_path)
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        writer = SQLiteAuditWriter()
        writer.append_in_transaction(connection, _event(1))
        writer.append_in_transaction(connection, _event(2))
        connection.commit()
    result = verify_audit_chain(_NoFetchallFactory(factory))
    assert result.valid is True and result.count == 2


@pytest.mark.parametrize("count", [0, 2])
def test_verifier_rejects_count_mismatch_without_false_valid(tmp_path, count):
    factory = _db(tmp_path)
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        SQLiteAuditWriter().append_in_transaction(connection, _event())
        connection.commit()
    result = verify_audit_chain(_CountMismatchFactory(factory, count))
    assert result.valid is False
    assert "count" in (result.reason or "")


@pytest.mark.parametrize("primary", [False, True])
def test_verifier_cleanup_failures_are_not_suppressed(tmp_path, primary):
    factory = _db(tmp_path)
    with pytest.raises(StoreUnavailable):
        verify_audit_chain(_CleanupFailureFactory(factory, primary=primary))


def test_verifier_does_not_hide_process_control_cleanup_failure(tmp_path):
    factory = _db(tmp_path)
    with pytest.raises(KeyboardInterrupt, match="close interrupted"):
        verify_audit_chain(_ProcessCleanupFactory(factory))


def test_verifier_cleanup_process_control_wins_over_primary_error(tmp_path):
    factory = _db(tmp_path)
    with pytest.raises(KeyboardInterrupt, match="close interrupted"):
        verify_audit_chain(_PrimaryProcessCleanupFactory(factory))


def test_writer_rejects_same_name_noop_trigger_before_using_cache(tmp_path):
    factory = _db(tmp_path)
    with closing(factory.connect()) as connection:
        connection.execute("DROP TRIGGER audit_events_update_guard")
        connection.execute(
            """
            CREATE TRIGGER audit_events_update_guard
            BEFORE UPDATE ON audit_events
            BEGIN SELECT 1; END
            """
        )
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(StoreUnavailable):
            SQLiteAuditWriter().append_in_transaction(connection, _event())


def test_writer_rejects_lookalike_audit_table_without_constraints(tmp_path):
    factory = _db(tmp_path)
    with closing(factory.connect()) as connection:
        connection.execute("DROP TABLE audit_events")
        migration = verdicts_db._read_migration(5)
        table_end = migration.index(");") + 2
        connection.executescript(
            """
            CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY,
                event_version INTEGER NOT NULL,
                canonicalization_version INTEGER NOT NULL,
                occurred_at TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                previous_decision TEXT NOT NULL,
                new_decision TEXT NOT NULL,
                reason TEXT NOT NULL,
                policy_version TEXT,
                analyzer_version TEXT,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            );
            """
        )
        connection.executescript(migration[table_end:])
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(StoreUnavailable):
            SQLiteAuditWriter().append_in_transaction(connection, _event())


@pytest.mark.parametrize(
    "index_sql",
    [
        "CREATE UNIQUE INDEX audit_events_event_hash_unique_idx ON audit_events(sha256)",
        (
            "CREATE UNIQUE INDEX audit_events_event_hash_unique_idx "
            "ON audit_events(event_hash) WHERE id > 0"
        ),
    ],
)
def test_writer_rejects_spoofed_unique_hash_index(tmp_path, index_sql):
    factory = _db(tmp_path)
    with closing(factory.connect()) as connection:
        connection.execute("DROP INDEX audit_events_event_hash_unique_idx")
        connection.execute(index_sql)
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(StoreUnavailable):
            SQLiteAuditWriter().append_in_transaction(connection, _event())


def test_writer_cache_verifies_one_new_row_per_sequential_append(tmp_path):
    traced = _TraceFactory(_db(tmp_path))
    writer = SQLiteAuditWriter()
    with closing(traced.connect()) as connection:
        for number in range(4):
            connection.execute("BEGIN IMMEDIATE")
            writer.append_in_transaction(connection, _event(number))
            connection.commit()
    full_scans = sum(
        "FROM audit_events ORDER BY id" in statement and "WHERE" not in statement
        for statement in traced.statements
    )
    suffix_scans = sum(
        "FROM audit_events WHERE id >" in statement for statement in traced.statements
    )
    assert full_scans == 1
    assert suffix_scans == 3


def test_writer_cache_stays_connection_local_across_fresh_connections(tmp_path):
    traced = _TraceFactory(_db(tmp_path))
    writer = SQLiteAuditWriter()
    for number in range(4):
        with closing(traced.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            writer.append_in_transaction(connection, _event(number))
            connection.commit()
    full_scans = sum(
        "FROM audit_events ORDER BY id" in statement and "WHERE" not in statement
        for statement in traced.statements
    )
    suffix_scans = sum(
        "FROM audit_events WHERE id >" in statement for statement in traced.statements
    )
    assert full_scans == 4
    assert suffix_scans == 0


def test_writer_does_not_share_cache_for_raw_sqlite_connections(tmp_path):
    factory = _db(tmp_path)
    writer = SQLiteAuditWriter()
    statements = []
    for number in range(2):
        with closing(sqlite3.connect(factory.path)) as connection:
            connection.set_trace_callback(statements.append)
            connection.execute("BEGIN IMMEDIATE")
            writer.append_in_transaction(connection, _event(number))
            connection.commit()
    full_scans = sum(
        "FROM audit_events ORDER BY id" in statement and "WHERE" not in statement
        for statement in statements
    )
    assert full_scans == 2


def test_writer_cache_regression_after_outer_rollback_is_repaired(tmp_path):
    factory = _db(tmp_path)
    writer = SQLiteAuditWriter()
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        writer.append_in_transaction(connection, _event(1))
        writer.append_in_transaction(connection, _event(2))
        connection.rollback()
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        writer.append_in_transaction(connection, _event(3))
        connection.commit()
    assert verify_audit_chain(factory).valid is True


def test_cold_writer_detects_mid_chain_corruption_before_append(tmp_path):
    factory = _db(tmp_path)
    writer = SQLiteAuditWriter()
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        writer.append_in_transaction(connection, _event(1))
        writer.append_in_transaction(connection, _event(2))
        connection.commit()
        connection.execute("DROP TRIGGER audit_events_update_guard")
        connection.execute("UPDATE audit_events SET actor = 'tampered' WHERE id = 1")
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(StoreUnavailable):
            SQLiteAuditWriter().append_in_transaction(connection, _event(3))


def test_cached_writer_rejects_tampered_history_after_exact_trigger_restore(tmp_path):
    factory = _db(tmp_path)
    writer = SQLiteAuditWriter()
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        writer.append_in_transaction(connection, _event(1))
        writer.append_in_transaction(connection, _event(2))
        connection.commit()
        connection.execute("DROP TRIGGER audit_events_update_guard")
        connection.execute("UPDATE audit_events SET actor = 'tampered' WHERE id = 1")
        connection.execute(_exact_update_guard_sql())
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(StoreUnavailable):
            writer.append_in_transaction(connection, _event(3))


def test_persisted_fields_are_exact_and_expected_head_succeeds(tmp_path):
    factory = _db(tmp_path)
    input_event = replace(
        _event(),
        occurred_at=datetime(2026, 8, 24, 21, 0, tzinfo=timezone(timedelta(hours=9))),
    )
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        SQLiteAuditWriter().append_in_transaction(connection, input_event)
        row = connection.execute(
            """
            SELECT id, event_version, canonicalization_version, occurred_at,
                   actor, action, sha256, previous_decision, new_decision,
                   reason, policy_version, analyzer_version, previous_hash,
                   event_hash
            FROM audit_events
            """
        ).fetchone()
        connection.commit()
    assert tuple(row[:13]) == (
        1,
        1,
        1,
        "2026-08-24T12:00:00+00:00",
        "worker-unicode-✓",
        "artifact.action.0",
        SHA,
        "REVIEW",
        "ALLOW",
        "unicode ✓ reason",
        "policy/1",
        "analyzer/1",
        "0" * 64,
    )
    result = verify_audit_chain(factory, expected_head=row[13])
    assert result.valid is True


def test_first_event_hash_matches_independent_canonical_fixture(tmp_path):
    factory = _db(tmp_path)
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        SQLiteAuditWriter().append_in_transaction(connection, _event())
        row = connection.execute(
            "SELECT previous_hash, event_hash FROM audit_events WHERE id = 1"
        ).fetchone()
        connection.commit()
    assert tuple(row) == (
        "0" * 64,
        "552caa3095e6a3427a02f20db449f8bcec3663c511d692d0c8129ebe0a1a9977",
    )


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("actor", "", "nonblank"),
        ("actor", "\x00bad", "control"),
        ("actor", "x" * 4097, "too long"),
        ("action", "", "nonblank"),
        ("reason", "\x01bad", "control"),
        ("reason", "x" * 4097, "too long"),
        ("policy_version", "", "nonblank"),
        ("analyzer_version", "x" * 4097, "too long"),
        ("actor", "actor\x7f", "control"),
        ("reason", "reason\u0080", "control"),
        ("policy_version", "policy\ud800", "control"),
        ("sha256", "A" * 64, "A"),
        ("occurred_at", datetime(2026, 1, 1), "timezone"),
    ],
)
def test_writer_rejects_parameterized_invalid_dtos(tmp_path, field, value, match):
    factory = _db(tmp_path)
    invalid = replace(_event(), **{field: value})
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(ValueError, match=match):
            SQLiteAuditWriter().append_in_transaction(connection, invalid)


def test_writer_uses_utf8_byte_bounds_for_text_fields(tmp_path):
    factory = _db(tmp_path)
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        SQLiteAuditWriter().append_in_transaction(connection, replace(_event(), actor="é" * 2048))
        with pytest.raises(ValueError, match="too long"):
            SQLiteAuditWriter().append_in_transaction(
                connection, replace(_event(1), actor="é" * 2049)
            )


def test_writer_rejects_wrong_event_type_and_decision_type(tmp_path):
    factory = _db(tmp_path)
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        writer = SQLiteAuditWriter()
        with pytest.raises(ValueError, match="AuditEventInput"):
            writer.append_in_transaction(connection, object())
        with pytest.raises(ValueError, match="Decision"):
            writer.append_in_transaction(
                connection,
                replace(_event(), previous_decision="REVIEW"),
            )


def test_writer_accepts_f4_maximum_text_lengths_and_long_policy_version(tmp_path):
    factory = _db(tmp_path)
    policy_version = PolicyEngine(PolicyConfig(name="n" * 300)).policy_version
    assert 256 < len(policy_version) <= 4096
    input_event = replace(
        _event(),
        actor="a" * 4096,
        policy_version=policy_version,
        analyzer_version="v" * 4096,
        reason="r" * 4096,
    )
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        SQLiteAuditWriter().append_in_transaction(connection, input_event)
        connection.commit()
        stored_policy_version = connection.execute(
            "SELECT policy_version FROM audit_events WHERE id = 1"
        ).fetchone()[0]
    assert stored_policy_version == policy_version
    result = verify_audit_chain(factory)
    assert result.valid is True and result.count == 1


def test_writer_outer_rollback_discards_event(tmp_path):
    factory = _db(tmp_path)
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        SQLiteAuditWriter().append_in_transaction(connection, _event())
        connection.rollback()
    result = verify_audit_chain(factory)
    assert result.valid is True and result.count == 0 and result.head is None


def test_verdict_and_audit_failure_roll_back_as_one_transaction(tmp_path):
    factory = _db(tmp_path)
    store = SQLiteArtifactStore(factory, SQLiteAuditWriter(), now=lambda: NOW)
    claim = store.claim_next("worker", NOW + timedelta(minutes=5))
    assert claim is not None

    class FailingAuditWriter:
        def append_in_transaction(self, connection, event):
            raise RuntimeError("audit unavailable")

    store._audit_writer = FailingAuditWriter()
    with pytest.raises(RuntimeError, match="audit unavailable"):
        store.record_verdict(
            claim,
            VerdictInput(
                sha256=SHA,
                decision=Decision.ALLOW,
                score=0,
                policy_version="policy/1",
                analyzer_version="analyzer/1",
                baseline_sha256=None,
                baseline_tier=None,
                created_at=NOW,
            ),
            (),
        )

    with closing(factory.connect()) as connection:
        state = connection.execute(
            "SELECT state FROM artifacts WHERE sha256 = ?", (SHA,)
        ).fetchone()[0]
        verdict_count = connection.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]
        audit_count = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    assert state == "SCANNING"
    assert verdict_count == 0
    assert audit_count == 1


def test_writer_rejects_invalid_inputs(tmp_path):
    factory = _db(tmp_path)
    writer = SQLiteAuditWriter()
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        invalid = AuditEventInput(
            actor="\x00bad",
            action="x",
            sha256=SHA,
            previous_decision=Decision.REVIEW,
            new_decision=Decision.ALLOW,
            reason="ok",
            policy_version=None,
            analyzer_version=None,
            occurred_at=NOW,
        )
        with pytest.raises(ValueError, match="control"):
            writer.append_in_transaction(connection, invalid)
        with pytest.raises(ValueError, match="Decision"):
            writer.append_in_transaction(
                connection,
                AuditEventInput(
                    actor="actor",
                    action="x",
                    sha256=SHA,
                    previous_decision="REVIEW",  # type: ignore[arg-type]
                    new_decision=Decision.ALLOW,
                    reason="ok",
                    policy_version=None,
                    analyzer_version=None,
                    occurred_at=NOW,
                ),
            )


def test_update_delete_and_forked_head_are_rejected(tmp_path):
    factory = _db(tmp_path)
    writer = SQLiteAuditWriter()
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        writer.append_in_transaction(connection, _event())
        connection.commit()
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE audit_events SET reason = 'changed'")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM audit_events")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("INSERT OR REPLACE INTO audit_events SELECT * FROM audit_events")

    # Corruption is visible to the verifier and prevents further append.
    with closing(factory.connect()) as connection:
        connection.execute("DROP TRIGGER audit_events_update_guard")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE audit_events SET event_hash = ?",
            ("b" * 64,),
        )
        connection.commit()
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(StoreUnavailable):
            writer.append_in_transaction(connection, _event(1))

    result = verify_audit_chain(factory)
    assert result.valid is False
    assert result.first_invalid_id == 1


def test_verifier_detects_scalar_tamper_and_expected_tail(tmp_path):
    factory = _db(tmp_path)
    writer = SQLiteAuditWriter()
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        writer.append_in_transaction(connection, _event(1))
        writer.append_in_transaction(connection, _event(2, when=NOW + timedelta(seconds=1)))
        connection.commit()
    complete = verify_audit_chain(factory)
    assert complete.valid and complete.head

    with closing(factory.connect()) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("DROP TRIGGER audit_events_delete_guard")
        connection.execute("DELETE FROM audit_events WHERE id = 2")
    result = verify_audit_chain(factory, expected_head=complete.head)
    assert result.valid is False
    assert "expected head" in (result.reason or "")


@pytest.mark.parametrize(
    ("column", "value", "reason"),
    [
        ("actor", "forged", "event hash"),
        ("previous_hash", "f" * 64, "previous hash"),
        ("event_hash", "f" * 64, "event hash"),
    ],
)
def test_verifier_reports_first_invalid_id_for_tamper(tmp_path, column, value, reason):
    factory = _db(tmp_path)
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        SQLiteAuditWriter().append_in_transaction(connection, _event())
        connection.execute("DROP TRIGGER audit_events_update_guard")
        connection.execute(f"UPDATE audit_events SET {column} = ? WHERE id = 1", (value,))
        connection.commit()
    result = verify_audit_chain(factory)
    assert result.valid is False
    assert result.first_invalid_id == 1
    assert reason in (result.reason or "")


def test_recomputed_hash_cannot_hide_invalid_persisted_text(tmp_path):
    factory = _db(tmp_path)
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        SQLiteAuditWriter().append_in_transaction(connection, _event())
        connection.execute("DROP TRIGGER audit_events_update_guard")
        row = connection.execute(
            """
            SELECT id, occurred_at, actor, action, sha256, previous_decision,
                   new_decision, reason, policy_version, analyzer_version,
                   previous_hash, event_hash
            FROM audit_events
            """
        ).fetchone()
        values = {
            "occurred_at": row[1],
            "actor": "\x00forged",
            "action": row[3],
            "sha256": row[4],
            "previous_decision": row[5],
            "new_decision": row[6],
            "reason": row[7],
            "policy_version": row[8],
            "analyzer_version": row[9],
        }
        forged_hash = _event_hash(row[10], row[0], values)
        connection.execute(
            "UPDATE audit_events SET actor = ?, event_hash = ? WHERE id = 1",
            (values["actor"], forged_hash),
        )
        connection.commit()
    result = verify_audit_chain(factory)
    assert result.valid is False
    assert result.first_invalid_id == 1
    assert "control" in (result.reason or "")
    with closing(factory.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(StoreUnavailable):
            SQLiteAuditWriter().append_in_transaction(connection, _event(1))


def test_schema_has_audit_indexes_and_middle_gap_is_detected(tmp_path):
    factory = _db(tmp_path)
    with closing(factory.connect()) as connection:
        indexes = {
            row[1]
            for row in connection.execute(
                "SELECT type, name FROM sqlite_master WHERE type = 'index'"
            )
        }
        assert {
            "audit_events_sha256_occurred_at_idx",
            "audit_events_action_occurred_at_idx",
            "audit_events_event_hash_unique_idx",
        } <= indexes
        connection.execute("BEGIN IMMEDIATE")
        writer = SQLiteAuditWriter()
        writer.append_in_transaction(connection, _event(1))
        writer.append_in_transaction(connection, _event(2, when=NOW + timedelta(seconds=1)))
        writer.append_in_transaction(connection, _event(3, when=NOW + timedelta(seconds=2)))
        connection.commit()
        connection.execute("DROP TRIGGER audit_events_delete_guard")
        connection.execute("DELETE FROM audit_events WHERE id = 2")
    result = verify_audit_chain(factory)
    assert result.valid is False
    assert result.first_invalid_id == 2


def test_concurrent_writers_form_one_linear_chain(tmp_path):
    factory = _db(tmp_path)

    def append(number):
        connection = factory.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            SQLiteAuditWriter().append_in_transaction(connection, _event(number))
            connection.commit()
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(append, (1, 2)))
    result = verify_audit_chain(factory)
    assert result.valid is True and result.count == 2
