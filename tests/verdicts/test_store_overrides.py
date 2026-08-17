from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
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
    ManualOverrideInput,
    VerdictInput,
)
from devpi_guardian.verdicts.reader import SQLiteVerdictReader
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
MISSING_SHA256 = "b" * 64


def manual_override(**changes: Any) -> ManualOverrideInput:
    values = {
        "sha256": SHA256,
        "decision": Decision.ALLOW,
        "actor": "admin@example.test",
        "reason": "reviewed by an administrator",
        "created_at": NOW,
        "expires_at": None,
    }
    values.update(changes)
    return ManualOverrideInput(**values)


def unchecked_manual_override(**changes: Any) -> ManualOverrideInput:
    valid = manual_override()
    values = {
        "sha256": valid.sha256,
        "decision": valid.decision,
        "actor": valid.actor,
        "reason": valid.reason,
        "created_at": valid.created_at,
        "expires_at": valid.expires_at,
    }
    values.update(changes)
    value = object.__new__(ManualOverrideInput)
    for field_name, field_value in values.items():
        object.__setattr__(value, field_name, field_value)
    return value


class NeverConnectFactory:
    def __init__(self, path: Path) -> None:
        self.path = path

    def connect(self):
        raise AssertionError("invalid input opened SQLite")


def database_snapshot(store: SQLiteArtifactStore) -> tuple[list[tuple], ...]:
    return tuple(
        [tuple(row) for row in fetchall(store, query)]
        for query in (
            "SELECT * FROM artifacts ORDER BY sha256",
            "SELECT * FROM verdicts ORDER BY id",
            "SELECT * FROM evidence ORDER BY id",
            "SELECT * FROM manual_overrides ORDER BY id",
        )
    )


def install_trigger(store: SQLiteArtifactStore, sql: str) -> None:
    with closing(store.connection_factory.connect()) as connection, connection:
        connection.execute(sql)


def terminal_store(
    tmp_path,
    audit_writer,
    decision: Decision = Decision.REVIEW,
    *,
    now=lambda: NOW,
) -> SQLiteArtifactStore:
    store = make_store(tmp_path, audit_writer, now=now)
    store.discover_artifact(artifact(), release())
    claim = store.claim_next("worker", NOW + timedelta(minutes=5))
    assert claim is not None
    store.record_verdict(
        claim,
        VerdictInput(
            sha256=SHA256,
            decision=decision,
            score=1.0,
            policy_version="policy-1",
            analyzer_version="analyzer-1",
            baseline_sha256=None,
            created_at=NOW,
        ),
        (),
    )
    audit_writer.events.clear()
    return store


def error_store(tmp_path, audit_writer) -> SQLiteArtifactStore:
    store = make_store(tmp_path, audit_writer, now=lambda: NOW)
    store.discover_artifact(artifact(), release())
    claim = store.claim_next("worker", NOW + timedelta(minutes=5))
    assert claim is not None
    store.mark_analysis_error(claim, "analysis failed")
    audit_writer.events.clear()
    return store


@pytest.mark.parametrize("decision", [Decision.ALLOW, Decision.DENY])
def test_set_manual_override_changes_effective_decision_and_audits(
    tmp_path,
    audit_writer,
    decision: Decision,
) -> None:
    store = terminal_store(tmp_path, audit_writer, Decision.REVIEW)
    override = manual_override(decision=decision)

    store.set_manual_override(override)

    result = SQLiteVerdictReader(
        store.connection_factory,
        now=lambda: NOW,
    ).get_effective_decision(SHA256)
    assert result.effective_decision is decision
    assert result.allowed is (decision is Decision.ALLOW)
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
        override.actor,
        "artifact.override_set",
        SHA256,
        Decision.DENY,
        decision,
        override.reason,
        None,
        None,
        NOW,
    )


def test_replacing_override_preserves_history_and_audits_actual_previous(
    tmp_path,
    audit_writer,
) -> None:
    store = terminal_store(tmp_path, audit_writer, Decision.DENY)
    first = manual_override(decision=Decision.ALLOW, reason="first review")
    store.set_manual_override(first)
    audit_writer.events.clear()
    replacement = manual_override(
        decision=Decision.DENY,
        actor="security@example.test",
        reason="risk confirmed",
        created_at=NOW + timedelta(seconds=1),
    )

    store.set_manual_override(replacement)

    rows = fetchall(
        store,
        """
        SELECT decision, actor, reason, is_current
        FROM manual_overrides ORDER BY id
        """,
    )
    assert [tuple(row) for row in rows] == [
        (Decision.ALLOW.value, first.actor, first.reason, 0),
        (Decision.DENY.value, replacement.actor, replacement.reason, 1),
    ]
    assert len(audit_writer.events) == 1
    event = audit_writer.events[0]
    assert event.previous_decision is Decision.ALLOW
    assert event.new_decision is Decision.DENY


def test_expired_override_falls_back_to_automated_decision(
    tmp_path,
    audit_writer,
) -> None:
    store = terminal_store(tmp_path, audit_writer, Decision.ALLOW)
    expires_at = NOW + timedelta(minutes=1)
    store.set_manual_override(
        manual_override(decision=Decision.DENY, expires_at=expires_at),
    )

    result = SQLiteVerdictReader(
        store.connection_factory,
        now=lambda: expires_at,
    ).get_effective_decision(SHA256)

    assert result.allowed is True
    assert result.effective_decision is Decision.ALLOW


@pytest.mark.parametrize(
    ("automated", "override_decision", "expected"),
    [
        (Decision.ALLOW, Decision.DENY, Decision.ALLOW),
        (Decision.REVIEW, Decision.ALLOW, Decision.DENY),
        (Decision.DENY, Decision.ALLOW, Decision.DENY),
    ],
)
def test_revoke_deactivates_current_override_and_uses_automated_fallback(
    tmp_path,
    audit_writer,
    automated: Decision,
    override_decision: Decision,
    expected: Decision,
) -> None:
    store = terminal_store(tmp_path, audit_writer, automated)
    store.set_manual_override(manual_override(decision=override_decision))
    audit_writer.events.clear()

    store.revoke_manual_override(
        SHA256,
        "admin@example.test",
        "override withdrawn",
    )

    current_count = fetchall(
        store,
        "SELECT COUNT(*) FROM manual_overrides WHERE is_current = 1",
    )[0][0]
    assert current_count == 0
    result = SQLiteVerdictReader(
        store.connection_factory,
        now=lambda: NOW,
    ).get_effective_decision(SHA256)
    assert result.effective_decision is expected
    assert len(audit_writer.events) == 1
    event = audit_writer.events[0]
    assert (
        event.actor,
        event.action,
        event.sha256,
        event.previous_decision,
        event.new_decision,
        event.reason,
        event.occurred_at,
    ) == (
        "admin@example.test",
        "artifact.override_revoked",
        SHA256,
        override_decision,
        expected,
        "override withdrawn",
        NOW,
    )


@pytest.mark.parametrize(
    "state",
    [
        ArtifactState.ALLOW,
        ArtifactState.REVIEW,
        ArtifactState.DENY,
        ArtifactState.ERROR,
    ],
)
def test_rescan_from_every_terminal_state_clears_transient_state_and_override(
    tmp_path,
    audit_writer,
    state: ArtifactState,
) -> None:
    store = (
        error_store(tmp_path, audit_writer)
        if state is ArtifactState.ERROR
        else terminal_store(tmp_path, audit_writer, Decision(state.value))
    )
    store.set_manual_override(manual_override(decision=Decision.ALLOW))
    audit_writer.events.clear()

    store.request_rescan(
        SHA256,
        "admin@example.test",
        "policy changed",
    )

    artifact_row = fetchall(
        store,
        """
        SELECT state, lease_owner, lease_expires_at, lease_token, last_error,
               updated_at
        FROM artifacts WHERE sha256 = ?
        """,
        (SHA256,),
    )[0]
    assert tuple(artifact_row) == (
        ArtifactState.DISCOVERED.value,
        None,
        None,
        None,
        None,
        NOW.isoformat(),
    )
    assert (
        fetchall(
            store,
            "SELECT COUNT(*) FROM manual_overrides WHERE is_current = 1",
        )[0][0]
        == 0
    )
    verdict_rows = fetchall(
        store,
        "SELECT decision, is_current FROM verdicts",
    )
    expected_verdicts = []
    if state is not ArtifactState.ERROR:
        expected_verdicts = [(state.value, 1)]
    assert [tuple(row) for row in verdict_rows] == expected_verdicts
    result = SQLiteVerdictReader(
        store.connection_factory,
        now=lambda: NOW,
    ).get_effective_decision(SHA256)
    assert result.allowed is False
    assert result.artifact_state is ArtifactState.DISCOVERED
    assert len(audit_writer.events) == 1
    event = audit_writer.events[0]
    assert (
        event.actor,
        event.action,
        event.sha256,
        event.previous_decision,
        event.new_decision,
        event.reason,
        event.occurred_at,
    ) == (
        "admin@example.test",
        "artifact.rescan_requested",
        SHA256,
        Decision.ALLOW,
        Decision.DENY,
        "policy changed",
        NOW,
    )


@pytest.mark.parametrize("operation", ["set", "revoke", "rescan"])
def test_administrator_commands_distinguish_missing_artifacts(
    tmp_path,
    audit_writer,
    operation: str,
) -> None:
    store = make_store(tmp_path, audit_writer, now=lambda: NOW)

    with pytest.raises(ArtifactNotFound):
        if operation == "set":
            store.set_manual_override(manual_override(sha256=MISSING_SHA256))
        elif operation == "revoke":
            store.revoke_manual_override(
                MISSING_SHA256,
                "admin@example.test",
                "withdrawn",
            )
        else:
            store.request_rescan(
                MISSING_SHA256,
                "admin@example.test",
                "retry",
            )

    assert audit_writer.events == []


@pytest.mark.parametrize("operation", ["set", "rescan"])
@pytest.mark.parametrize(
    "state",
    [ArtifactState.DISCOVERED, ArtifactState.SCANNING],
)
def test_override_and_rescan_reject_nonterminal_artifact_states(
    tmp_path,
    audit_writer,
    operation: str,
    state: ArtifactState,
) -> None:
    store = make_store(tmp_path, audit_writer, now=lambda: NOW)
    store.discover_artifact(artifact(), release())
    if state is ArtifactState.SCANNING:
        claimed = store.claim_next("worker", NOW + timedelta(minutes=5))
        assert claimed is not None
    audit_writer.events.clear()
    before = database_snapshot(store)

    with pytest.raises(TransitionConflict):
        if operation == "set":
            store.set_manual_override(manual_override())
        else:
            store.request_rescan(
                SHA256,
                "admin@example.test",
                "retry",
            )

    assert database_snapshot(store) == before
    assert audit_writer.events == []


def test_revoke_requires_a_current_override(tmp_path, audit_writer) -> None:
    store = terminal_store(tmp_path, audit_writer)

    with pytest.raises(TransitionConflict):
        store.revoke_manual_override(
            SHA256,
            "admin@example.test",
            "nothing to revoke",
        )

    assert audit_writer.events == []


def test_rescan_without_override_uses_actual_automated_previous_decision(
    tmp_path,
    audit_writer,
) -> None:
    store = terminal_store(tmp_path, audit_writer, Decision.ALLOW)

    store.request_rescan(
        SHA256,
        "admin@example.test",
        "policy changed",
    )

    assert len(audit_writer.events) == 1
    event = audit_writer.events[0]
    assert event.previous_decision is Decision.ALLOW
    assert event.new_decision is Decision.DENY


@pytest.mark.parametrize(
    "changes",
    [
        {"actor": None},
        {"reason": 123},
        {"created_at": "2026-08-17"},
        {"expires_at": "2026-08-18"},
    ],
)
def test_manual_override_dto_rejects_wrong_runtime_types_as_value_errors(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        manual_override(**changes)


def test_set_requires_exact_manual_override_dto_before_connecting(
    tmp_path,
    audit_writer,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(ValueError, match="ManualOverrideInput"):
        store.set_manual_override(object())


@pytest.mark.parametrize(
    ("changes", "error_type"),
    [
        ({"sha256": "A" * 64}, InvalidSha256),
        ({"decision": "ALLOW"}, ValueError),
        ({"decision": Decision.REVIEW}, ValueError),
        ({"actor": None}, ValueError),
        ({"actor": " "}, ValueError),
        ({"actor": "admin\x00unsafe"}, ValueError),
        ({"actor": "a" * 4097}, ValueError),
        ({"reason": None}, ValueError),
        ({"reason": " "}, ValueError),
        ({"reason": "reason\x00unsafe"}, ValueError),
        ({"reason": "r" * 4097}, ValueError),
        ({"created_at": NOW.replace(tzinfo=None)}, ValueError),
        ({"created_at": "2026-08-17"}, ValueError),
        ({"expires_at": NOW.replace(tzinfo=None)}, ValueError),
        ({"expires_at": "2026-08-18"}, ValueError),
        ({"expires_at": NOW}, ValueError),
    ],
)
def test_set_validates_mutated_override_before_connecting(
    tmp_path,
    audit_writer,
    changes: dict[str, object],
    error_type: type[Exception],
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(error_type):
        store.set_manual_override(unchecked_manual_override(**changes))

    assert audit_writer.events == []


@pytest.mark.parametrize("operation", ["revoke", "rescan"])
@pytest.mark.parametrize(
    ("field", "value", "error_type"),
    [
        ("sha256", "A" * 64, InvalidSha256),
        ("sha256", None, InvalidSha256),
        ("actor", None, ValueError),
        ("actor", " ", ValueError),
        ("actor", "admin\x00unsafe", ValueError),
        ("actor", "a" * 4097, ValueError),
        ("reason", None, ValueError),
        ("reason", " ", ValueError),
        ("reason", "r" * 4097, ValueError),
    ],
)
def test_admin_command_validates_input_before_connecting(
    tmp_path,
    audit_writer,
    operation: str,
    field: str,
    value: object,
    error_type: type[Exception],
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )
    values = {
        "sha256": SHA256,
        "actor": "admin@example.test",
        "reason": "reviewed",
    }
    values[field] = value

    with pytest.raises(error_type):
        if operation == "revoke":
            store.revoke_manual_override(**values)
        else:
            store.request_rescan(**values)

    assert audit_writer.events == []


def test_set_rejects_override_expired_at_writer_lock_time(
    tmp_path,
    audit_writer,
) -> None:
    clock = [NOW]
    store = terminal_store(
        tmp_path,
        audit_writer,
        Decision.REVIEW,
        now=lambda: clock[0],
    )
    expires_at = NOW + timedelta(minutes=1)
    override = manual_override(expires_at=expires_at)
    clock[0] = expires_at

    with pytest.raises(ValueError, match="future"):
        store.set_manual_override(override)

    assert fetchall(store, "SELECT COUNT(*) FROM manual_overrides")[0][0] == 0
    assert audit_writer.events == []


@pytest.mark.parametrize("operation", ["set", "revoke", "rescan"])
def test_admin_command_reads_now_once_after_acquiring_writer_lock(
    tmp_path,
    audit_writer,
    operation: str,
) -> None:
    factory = ConnectionFactory(
        tmp_path / f"{operation}.db",
        busy_timeout_ms=1,
    )
    migrate(factory)
    setup = SQLiteArtifactStore(factory, audit_writer, now=lambda: NOW)
    setup.discover_artifact(artifact(), release())
    claim = setup.claim_next("worker", NOW + timedelta(minutes=5))
    assert claim is not None
    setup.record_verdict(
        claim,
        VerdictInput(
            SHA256,
            Decision.REVIEW,
            1.0,
            "policy-1",
            "analyzer-1",
            None,
            NOW,
        ),
        (),
    )
    if operation in {"revoke", "rescan"}:
        setup.set_manual_override(manual_override())
    audit_writer.events.clear()
    calls = 0

    def now_under_writer_lock() -> datetime:
        nonlocal calls
        calls += 1
        with (
            closing(factory.connect()) as probe,
            pytest.raises(sqlite3.OperationalError),
        ):
            probe.execute("BEGIN IMMEDIATE")
        return NOW

    store = SQLiteArtifactStore(
        factory,
        audit_writer,
        now=now_under_writer_lock,
    )

    if operation == "set":
        store.set_manual_override(manual_override())
    elif operation == "revoke":
        store.revoke_manual_override(SHA256, "admin", "withdrawn")
    else:
        store.request_rescan(SHA256, "admin", "policy changed")

    assert calls == 1


@pytest.mark.parametrize("operation", ["set", "revoke"])
def test_expired_current_override_audits_automated_effective_previous(
    tmp_path,
    audit_writer,
    operation: str,
) -> None:
    clock = [NOW]
    store = terminal_store(
        tmp_path,
        audit_writer,
        Decision.ALLOW,
        now=lambda: clock[0],
    )
    expires_at = NOW + timedelta(minutes=1)
    store.set_manual_override(
        manual_override(decision=Decision.DENY, expires_at=expires_at),
    )
    clock[0] = expires_at
    audit_writer.events.clear()

    if operation == "set":
        store.set_manual_override(
            manual_override(
                decision=Decision.DENY,
                created_at=expires_at,
            ),
        )
    else:
        store.revoke_manual_override(SHA256, "admin", "expired override")

    assert len(audit_writer.events) == 1
    event = audit_writer.events[0]
    assert event.previous_decision is Decision.ALLOW
    expected = Decision.DENY if operation == "set" else Decision.ALLOW
    assert event.new_decision is expected


def prepare_admin_operation(
    tmp_path,
    audit_writer,
    operation: str,
) -> SQLiteArtifactStore:
    store = terminal_store(tmp_path, audit_writer, Decision.REVIEW)
    if operation in {"revoke", "rescan"}:
        store.set_manual_override(manual_override())
    audit_writer.events.clear()
    return store


def perform_admin_operation(
    store: SQLiteArtifactStore,
    operation: str,
) -> None:
    if operation == "set":
        store.set_manual_override(manual_override())
    elif operation == "revoke":
        store.revoke_manual_override(SHA256, "admin", "withdrawn")
    else:
        store.request_rescan(SHA256, "admin", "policy changed")


@pytest.mark.parametrize("operation", ["set", "revoke", "rescan"])
def test_audit_failure_rolls_back_every_admin_transition(
    tmp_path,
    audit_writer,
    operation: str,
) -> None:
    store = prepare_admin_operation(tmp_path, audit_writer, operation)
    before = database_snapshot(store)
    audit_writer.fail = True

    with pytest.raises(RuntimeError, match="audit unavailable"):
        perform_admin_operation(store, operation)

    assert database_snapshot(store) == before


@pytest.mark.parametrize("operation", ["set", "revoke", "rescan"])
def test_commit_failure_rolls_back_every_admin_transition(
    tmp_path,
    audit_writer,
    operation: str,
) -> None:
    base_store = prepare_admin_operation(tmp_path, audit_writer, operation)
    before = database_snapshot(base_store)
    wrapping_factory = WrappingFactory(
        base_store.connection_factory,
        fail_commit=True,
    )
    store = SQLiteArtifactStore(
        wrapping_factory,
        audit_writer,
        now=lambda: NOW,
    )

    with pytest.raises(StoreUnavailable) as error:
        perform_admin_operation(store, operation)

    assert isinstance(error.value.__cause__, sqlite3.OperationalError)
    assert str(error.value.__cause__) == "commit failed"
    assert wrapping_factory.last_connection.rollback_called is True
    assert database_snapshot(base_store) == before


@pytest.mark.parametrize(
    ("operation", "trigger_sql"),
    [
        (
            "set",
            """
            CREATE TRIGGER abort_override_insert
            BEFORE INSERT ON manual_overrides
            BEGIN SELECT RAISE(ABORT, 'override insert failed'); END
            """,
        ),
        (
            "revoke",
            """
            CREATE TRIGGER abort_override_revoke
            BEFORE UPDATE OF is_current ON manual_overrides
            BEGIN SELECT RAISE(ABORT, 'override revoke failed'); END
            """,
        ),
        (
            "rescan",
            """
            CREATE TRIGGER abort_rescan
            BEFORE UPDATE OF state ON artifacts
            BEGIN SELECT RAISE(ABORT, 'rescan failed'); END
            """,
        ),
    ],
)
def test_sqlite_failure_rolls_back_and_maps_to_store_unavailable(
    tmp_path,
    audit_writer,
    operation: str,
    trigger_sql: str,
) -> None:
    store = prepare_admin_operation(tmp_path, audit_writer, operation)
    before = database_snapshot(store)
    install_trigger(store, trigger_sql)

    with pytest.raises(StoreUnavailable) as error:
        perform_admin_operation(store, operation)

    assert isinstance(error.value.__cause__, sqlite3.IntegrityError)
    assert database_snapshot(store) == before
    assert audit_writer.events == []


@pytest.mark.parametrize(
    "trigger_sql",
    [
        """
        CREATE TRIGGER ignore_override_insert
        BEFORE INSERT ON manual_overrides
        BEGIN SELECT RAISE(IGNORE); END
        """,
        """
        CREATE TRIGGER rewrite_override_insert
        AFTER INSERT ON manual_overrides
        BEGIN
            UPDATE manual_overrides
            SET reason = 'trigger changed history' WHERE id = NEW.id;
        END
        """,
    ],
)
def test_set_detects_ignored_or_rewritten_insert_and_rolls_back(
    tmp_path,
    audit_writer,
    trigger_sql: str,
) -> None:
    store = terminal_store(tmp_path, audit_writer)
    before = database_snapshot(store)
    install_trigger(store, trigger_sql)

    with pytest.raises(TransitionConflict):
        store.set_manual_override(manual_override())

    assert database_snapshot(store) == before
    assert audit_writer.events == []


def test_replacing_override_detects_ignored_current_marker_update(
    tmp_path,
    audit_writer,
) -> None:
    store = terminal_store(tmp_path, audit_writer)
    store.set_manual_override(manual_override())
    audit_writer.events.clear()
    before = database_snapshot(store)
    install_trigger(
        store,
        """
        CREATE TRIGGER ignore_override_deactivation
        BEFORE UPDATE OF is_current ON manual_overrides
        WHEN OLD.is_current = 1
        BEGIN SELECT RAISE(IGNORE); END
        """,
    )

    with pytest.raises(TransitionConflict):
        store.set_manual_override(
            manual_override(
                decision=Decision.DENY,
                reason="replacement",
            ),
        )

    assert database_snapshot(store) == before
    assert audit_writer.events == []


@pytest.mark.parametrize("operation", ["revoke", "rescan"])
def test_override_removal_detects_after_trigger_reactivation(
    tmp_path,
    audit_writer,
    operation: str,
) -> None:
    store = prepare_admin_operation(tmp_path, audit_writer, operation)
    before = database_snapshot(store)
    install_trigger(
        store,
        """
        CREATE TRIGGER reactivate_override
        AFTER UPDATE OF is_current ON manual_overrides
        WHEN NEW.is_current = 0
        BEGIN
            UPDATE manual_overrides SET is_current = 1 WHERE id = NEW.id;
        END
        """,
    )

    with pytest.raises(TransitionConflict):
        perform_admin_operation(store, operation)

    assert database_snapshot(store) == before
    assert audit_writer.events == []


@pytest.mark.parametrize(
    "trigger_sql",
    [
        """
        CREATE TRIGGER ignore_rescan
        BEFORE UPDATE OF state ON artifacts
        WHEN NEW.state = 'DISCOVERED'
        BEGIN SELECT RAISE(IGNORE); END
        """,
        """
        CREATE TRIGGER rewrite_rescan
        AFTER UPDATE OF state ON artifacts
        WHEN NEW.state = 'DISCOVERED'
        BEGIN
            UPDATE artifacts SET state = 'DENY' WHERE sha256 = NEW.sha256;
        END
        """,
        """
        CREATE TRIGGER rewrite_verdict_during_rescan
        AFTER UPDATE OF state ON artifacts
        WHEN NEW.state = 'DISCOVERED'
        BEGIN
            UPDATE verdicts SET decision = 'DENY' WHERE sha256 = NEW.sha256;
        END
        """,
    ],
)
def test_rescan_checks_final_artifact_and_verdict_state(
    tmp_path,
    audit_writer,
    trigger_sql: str,
) -> None:
    store = prepare_admin_operation(tmp_path, audit_writer, "rescan")
    before = database_snapshot(store)
    install_trigger(store, trigger_sql)

    with pytest.raises(TransitionConflict):
        store.request_rescan(SHA256, "admin", "policy changed")

    assert database_snapshot(store) == before
    assert audit_writer.events == []


@pytest.mark.parametrize("operation", ["set", "revoke", "rescan"])
def test_admin_transitions_reject_duplicate_current_overrides(
    tmp_path,
    audit_writer,
    operation: str,
) -> None:
    store = terminal_store(tmp_path, audit_writer)
    store.set_manual_override(manual_override())
    with closing(store.connection_factory.connect()) as connection, connection:
        connection.execute("DROP INDEX manual_overrides_one_current_idx")
        connection.execute(
            """
            INSERT INTO manual_overrides(
                sha256, decision, actor, reason, created_at, expires_at,
                is_current
            ) VALUES (?, 'DENY', 'other-admin', 'duplicate', ?, NULL, 1)
            """,
            (SHA256, NOW.isoformat()),
        )
    audit_writer.events.clear()
    before = database_snapshot(store)

    with pytest.raises(TransitionConflict):
        perform_admin_operation(store, operation)

    assert database_snapshot(store) == before
    assert audit_writer.events == []


def test_concurrent_override_replacements_are_serialized(
    tmp_path,
    audit_writer,
) -> None:
    store = terminal_store(tmp_path, audit_writer, Decision.REVIEW)
    store.set_manual_override(manual_override(reason="initial"))
    audit_writer.events.clear()
    replacements = (
        manual_override(
            decision=Decision.ALLOW,
            reason="replacement allow",
            created_at=NOW + timedelta(seconds=1),
        ),
        manual_override(
            decision=Decision.DENY,
            reason="replacement deny",
            created_at=NOW + timedelta(seconds=2),
        ),
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(store.set_manual_override, replacements))

    query = """
        SELECT decision, reason, is_current
        FROM manual_overrides ORDER BY id
    """
    rows = fetchall(store, query)
    assert len(rows) == 3
    assert sum(row["is_current"] for row in rows) == 1
    assert rows[-1]["reason"] in {
        "replacement allow",
        "replacement deny",
    }
    assert len(audit_writer.events) == 2


@pytest.mark.parametrize("operation", ["revoke", "rescan"])
def test_concurrent_override_removal_or_rescan_has_one_winner(
    tmp_path,
    audit_writer,
    operation: str,
) -> None:
    store = prepare_admin_operation(tmp_path, audit_writer, operation)

    def attempt(_number: int) -> bool:
        try:
            perform_admin_operation(store, operation)
        except TransitionConflict:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, (1, 2)))

    assert results.count(True) == 1
    assert results.count(False) == 1
    assert (
        fetchall(
            store,
            "SELECT COUNT(*) FROM manual_overrides WHERE is_current = 1",
        )[0][0]
        == 0
    )
    artifact_state = fetchall(
        store,
        "SELECT state FROM artifacts WHERE sha256 = ?",
        (SHA256,),
    )[0][0]
    expected_state = ArtifactState.REVIEW.value
    if operation == "rescan":
        expected_state = ArtifactState.DISCOVERED.value
    assert artifact_state == expected_state
    assert len(audit_writer.events) == 1


def test_revoke_rejects_current_override_on_nonterminal_artifact(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer, now=lambda: NOW)
    store.discover_artifact(artifact(), release())
    with closing(store.connection_factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO manual_overrides(
                sha256, decision, actor, reason, created_at, expires_at,
                is_current
            ) VALUES (?, 'ALLOW', 'admin', 'invalid state seed', ?, NULL, 1)
            """,
            (SHA256, NOW.isoformat()),
        )
    audit_writer.events.clear()
    before = database_snapshot(store)

    with pytest.raises(TransitionConflict):
        store.revoke_manual_override(SHA256, "admin", "withdrawn")

    assert database_snapshot(store) == before
    assert audit_writer.events == []


@pytest.mark.parametrize("operation", ["set", "revoke", "rescan"])
def test_admin_transitions_reject_duplicate_current_verdicts(
    tmp_path,
    audit_writer,
    operation: str,
) -> None:
    store = prepare_admin_operation(tmp_path, audit_writer, operation)
    with closing(store.connection_factory.connect()) as connection, connection:
        connection.execute("DROP INDEX verdicts_one_current_idx")
        connection.execute(
            """
            INSERT INTO verdicts(
                sha256, decision, score, policy_version, analyzer_version,
                baseline_sha256, is_current, created_at
            ) VALUES (?, 'ALLOW', 1, 'duplicate', 'duplicate', NULL, 1, ?)
            """,
            (SHA256, NOW.isoformat()),
        )
    audit_writer.events.clear()
    before = database_snapshot(store)

    with pytest.raises(TransitionConflict):
        perform_admin_operation(store, operation)

    assert database_snapshot(store) == before
    assert audit_writer.events == []


def test_audit_callback_runs_inside_the_immediate_transaction(
    tmp_path,
    audit_writer,
) -> None:
    store = terminal_store(tmp_path, audit_writer)
    probe_factory = ConnectionFactory(
        store.connection_factory.path,
        busy_timeout_ms=1,
    )
    original_append = audit_writer.append_in_transaction
    observations: list[bool] = []

    def append_in_transaction(connection, event) -> None:
        observations.append(connection.in_transaction)
        with (
            closing(probe_factory.connect()) as probe,
            pytest.raises(sqlite3.OperationalError),
        ):
            probe.execute("BEGIN IMMEDIATE")
        original_append(connection, event)

    audit_writer.append_in_transaction = append_in_transaction

    store.set_manual_override(manual_override())

    assert observations == [True]


@pytest.mark.parametrize(
    ("operation", "trigger_sql"),
    [
        (
            "set",
            """
            CREATE TRIGGER mutate_artifact_after_override_insert
            AFTER INSERT ON manual_overrides
            BEGIN
                UPDATE artifacts
                SET state = 'DISCOVERED' WHERE sha256 = NEW.sha256;
            END
            """,
        ),
        (
            "revoke",
            """
            CREATE TRIGGER mutate_verdict_after_override_revoke
            AFTER UPDATE OF is_current ON manual_overrides
            WHEN NEW.is_current = 0
            BEGIN
                UPDATE verdicts
                SET decision = 'DENY' WHERE sha256 = NEW.sha256;
            END
            """,
        ),
    ],
)
def test_set_and_revoke_detect_after_trigger_changes_outside_override_row(
    tmp_path,
    audit_writer,
    operation: str,
    trigger_sql: str,
) -> None:
    store = prepare_admin_operation(tmp_path, audit_writer, operation)
    before = database_snapshot(store)
    install_trigger(store, trigger_sql)

    with pytest.raises(TransitionConflict):
        perform_admin_operation(store, operation)

    assert database_snapshot(store) == before
    assert audit_writer.events == []


@pytest.mark.parametrize("operation", ["set", "revoke", "rescan"])
def test_admin_transitions_preserve_all_older_override_history(
    tmp_path,
    audit_writer,
    operation: str,
) -> None:
    store = terminal_store(tmp_path, audit_writer)
    store.set_manual_override(manual_override(reason="old history"))
    store.set_manual_override(
        manual_override(decision=Decision.DENY, reason="current override"),
    )
    audit_writer.events.clear()
    before = database_snapshot(store)
    install_trigger(
        store,
        """
        CREATE TRIGGER mutate_old_override_history
        AFTER INSERT ON manual_overrides
        BEGIN
            UPDATE manual_overrides
            SET reason = 'tampered history'
            WHERE sha256 = NEW.sha256 AND id != NEW.id AND is_current = 0;
        END
        """,
    )
    if operation in {"revoke", "rescan"}:
        install_trigger(
            store,
            """
            CREATE TRIGGER mutate_old_history_on_deactivation
            AFTER UPDATE OF is_current ON manual_overrides
            WHEN NEW.is_current = 0
            BEGIN
                UPDATE manual_overrides
                SET reason = 'tampered history'
                WHERE sha256 = NEW.sha256 AND id != NEW.id
                  AND is_current = 0;
            END
            """,
        )

    with pytest.raises(TransitionConflict):
        perform_admin_operation(store, operation)

    assert database_snapshot(store) == before
    assert audit_writer.events == []


def test_admin_transition_preserves_immutable_evidence_history(
    tmp_path,
    audit_writer,
) -> None:
    store = terminal_store(tmp_path, audit_writer)
    with closing(store.connection_factory.connect()) as connection, connection:
        verdict_id = connection.execute(
            "SELECT id FROM verdicts WHERE sha256 = ? AND is_current = 1",
            (SHA256,),
        ).fetchone()[0]
        connection.execute(
            """
            INSERT INTO evidence(
                verdict_id, rule_id, action, file_path, line, message,
                details_json
            ) VALUES (?, 'RULE-1', 'REVIEW', NULL, NULL, 'original', '{}')
            """,
            (verdict_id,),
        )
    audit_writer.events.clear()
    before = database_snapshot(store)
    install_trigger(
        store,
        """
        CREATE TRIGGER mutate_evidence_after_override_insert
        AFTER INSERT ON manual_overrides
        BEGIN
            UPDATE evidence SET message = 'tampered evidence';
        END
        """,
    )

    with pytest.raises(TransitionConflict):
        store.set_manual_override(manual_override())

    assert database_snapshot(store) == before
    assert audit_writer.events == []


@pytest.mark.parametrize(
    "expires_at",
    ["not-a-timestamp", NOW.replace(tzinfo=None).isoformat()],
)
def test_corrupt_stored_override_expiry_maps_to_store_unavailable(
    tmp_path,
    audit_writer,
    expires_at: str,
) -> None:
    store = terminal_store(tmp_path, audit_writer)
    with closing(store.connection_factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO manual_overrides(
                sha256, decision, actor, reason, created_at, expires_at,
                is_current
            ) VALUES (?, 'ALLOW', 'admin', 'seed', ?, ?, 1)
            """,
            (SHA256, NOW.isoformat(), expires_at),
        )
    audit_writer.events.clear()
    before = database_snapshot(store)

    with pytest.raises(StoreUnavailable) as error:
        store.revoke_manual_override(SHA256, "admin", "withdrawn")

    assert isinstance(error.value.__cause__, ValueError)
    assert database_snapshot(store) == before
    assert audit_writer.events == []
