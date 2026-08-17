from __future__ import annotations

import re
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from devpi_guardian.verdicts import store as store_module
from devpi_guardian.verdicts.db import ConnectionFactory, migrate
from devpi_guardian.verdicts.errors import StoreUnavailable, TransitionConflict
from devpi_guardian.verdicts.models import (
    ArtifactInput,
    ArtifactState,
    Decision,
    ReleaseInput,
)
from devpi_guardian.verdicts.store import SQLiteArtifactStore

SHA = "a" * 64
NOW = datetime(2026, 8, 17, 0, 0, tzinfo=UTC)


def make_store(tmp_path, audit_writer, *, now=lambda: NOW):
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    return SQLiteArtifactStore(factory, audit_writer, now=now)


def artifact(*, sha256: str = SHA, size_bytes: int = 123) -> ArtifactInput:
    return ArtifactInput(
        sha256=sha256,
        size_bytes=size_bytes,
        discovered_at=NOW,
    )


def unchecked_artifact(size_bytes) -> ArtifactInput:
    value = object.__new__(ArtifactInput)
    object.__setattr__(value, "sha256", SHA)
    object.__setattr__(value, "size_bytes", size_bytes)
    object.__setattr__(value, "discovered_at", NOW)
    return value


def release(
    *,
    stage: str = "root/pypi",
    sha256: str = SHA,
    project: str = "demo-package",
    version: str = "1.0.0",
    filename: str = "demo_package-1.0.0-py3-none-any.whl",
    origin_url: str = "https://pypi.org/packages/demo_package-1.0.0.whl",
) -> ReleaseInput:
    return ReleaseInput(
        stage=stage,
        project=project,
        version=version,
        filename=filename,
        sha256=sha256,
        origin_url=origin_url,
        discovered_at=NOW,
    )


def fetchall(store, query: str, parameters: tuple[Any, ...] = ()):
    with closing(store.connection_factory.connect()) as connection:
        return connection.execute(query, parameters).fetchall()


def seed_scanning(
    store,
    *,
    sha256: str,
    owner: str,
    expires_at: datetime,
) -> None:
    timestamp = NOW.isoformat()
    with closing(store.connection_factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at,
                lease_owner, lease_expires_at, lease_token
            ) VALUES (?, 123, 'SCANNING', ?, ?, ?, ?, ?)
            """,
            (
                sha256,
                timestamp,
                timestamp,
                owner,
                expires_at.isoformat(),
                sha256,
            ),
        )


def test_discovery_is_idempotent(tmp_path, audit_writer) -> None:
    store = make_store(tmp_path, audit_writer)

    store.discover_artifact(artifact(), release())
    store.discover_artifact(artifact(), release())

    assert fetchall(store, "SELECT COUNT(*) FROM artifacts")[0][0] == 1
    assert fetchall(store, "SELECT COUNT(*) FROM release_mappings")[0][0] == 1
    assert len(audit_writer.events) == 1


def test_concurrent_workers_have_exactly_one_claim_winner(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer)
    store.discover_artifact(artifact(), release())
    lease_until = NOW + timedelta(minutes=5)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda worker: store.claim_next(worker, lease_until),
                ("worker-1", "worker-2"),
            )
        )

    winners = [claimed for claimed in results if claimed is not None]
    assert len(winners) == 1
    assert winners[0].worker_id in {"worker-1", "worker-2"}


def test_claim_tokens_are_unique_canonical_and_not_audited(
    tmp_path,
    audit_writer,
) -> None:
    clock = [NOW]
    store = make_store(tmp_path, audit_writer, now=lambda: clock[0])
    store.discover_artifact(artifact(), release())

    claim_a = store.claim_next("worker-a", NOW + timedelta(minutes=1))
    assert claim_a is not None
    clock[0] = NOW + timedelta(minutes=2)
    assert store.recover_expired_claims(clock[0]) == 1
    claim_b = store.claim_next("worker-b", NOW + timedelta(minutes=5))
    assert claim_b is not None

    assert claim_a.lease_token != claim_b.lease_token
    assert re.fullmatch(r"[0-9a-f]{64}", claim_a.lease_token)
    assert re.fullmatch(r"[0-9a-f]{64}", claim_b.lease_token)
    assert claim_a.lease_token not in repr(claim_a)
    assert claim_b.lease_token not in repr(claim_b)
    audit_snapshot = repr(audit_writer.events)
    assert claim_a.lease_token not in audit_snapshot
    assert claim_b.lease_token not in audit_snapshot


def test_expired_claim_recovers_and_can_be_claimed_by_another_worker(
    tmp_path, audit_writer
) -> None:
    store = make_store(tmp_path, audit_writer)
    seed_scanning(
        store,
        sha256=SHA,
        owner="worker-old",
        expires_at=NOW - timedelta(seconds=1),
    )

    recovered = store.recover_expired_claims(NOW)
    claimed = store.claim_next("worker-new", NOW + timedelta(minutes=5))

    assert recovered == 1
    assert claimed is not None
    assert claimed.worker_id == "worker-new"
    recovered_row = fetchall(
        store,
        """
        SELECT lease_owner, lease_expires_at, lease_token
        FROM artifacts WHERE sha256 = ?
        """,
        (SHA,),
    )[0]
    assert tuple(recovered_row) == (
        claimed.worker_id,
        claimed.lease_expires_at.isoformat(),
        claimed.lease_token,
    )
    audit_payloads = [
        (
            event.actor,
            event.action,
            event.sha256,
            event.previous_decision,
            event.new_decision,
            event.reason,
        )
        for event in audit_writer.events
    ]
    assert audit_payloads == [
        (
            "worker-old",
            "artifact.lease_expired",
            SHA,
            Decision.DENY,
            Decision.DENY,
            "analysis lease expired",
        ),
        (
            "worker-new",
            "artifact.claimed",
            SHA,
            Decision.DENY,
            Decision.DENY,
            "analysis lease acquired",
        ),
    ]


def test_discovery_rejects_sha_mismatch_without_side_effects(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer)

    with pytest.raises(ValueError):
        store.discover_artifact(artifact(), release(sha256="b" * 64))

    assert fetchall(store, "SELECT COUNT(*) FROM artifacts")[0][0] == 0
    assert fetchall(store, "SELECT COUNT(*) FROM release_mappings")[0][0] == 0
    assert audit_writer.events == []


def test_existing_sha_with_different_size_conflicts_without_changes(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer)
    store.discover_artifact(artifact(), release())
    original_events = list(audit_writer.events)

    with pytest.raises(TransitionConflict):
        changed_artifact = artifact(size_bytes=999)
        store.discover_artifact(changed_artifact, release(version="2.0.0"))

    row = fetchall(
        store,
        "SELECT size_bytes FROM artifacts WHERE sha256 = ?",
        (SHA,),
    )[0]
    assert row[0] == 123
    assert fetchall(store, "SELECT COUNT(*) FROM release_mappings")[0][0] == 1
    assert audit_writer.events == original_events


@pytest.mark.parametrize("size_bytes", [True, 1.5, 2**63, -1])
def test_discovery_rejects_invalid_runtime_size_without_side_effects(
    tmp_path,
    audit_writer,
    size_bytes,
) -> None:
    store = make_store(tmp_path, audit_writer)

    with pytest.raises(ValueError):
        store.discover_artifact(unchecked_artifact(size_bytes), release())

    assert fetchall(store, "SELECT COUNT(*) FROM artifacts")[0][0] == 0
    assert fetchall(store, "SELECT COUNT(*) FROM release_mappings")[0][0] == 0
    assert audit_writer.events == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("stage", None),
        ("stage", []),
        ("stage", 123),
        ("project", 123),
        ("version", 123),
        ("filename", 123),
        ("origin_url", 123),
    ],
)
def test_discovery_rejects_invalid_release_field_types_without_side_effects(
    tmp_path,
    audit_writer,
    field,
    value,
) -> None:
    store = make_store(tmp_path, audit_writer)
    invalid_release = release(**{field: value})

    with pytest.raises(ValueError):
        store.discover_artifact(artifact(), invalid_release)

    assert fetchall(store, "SELECT COUNT(*) FROM artifacts")[0][0] == 0
    assert fetchall(store, "SELECT COUNT(*) FROM release_mappings")[0][0] == 0
    assert audit_writer.events == []


def test_discovery_normalizes_project_and_sanitizes_ipv6_origin_url(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer)
    raw_url = "/".join(
        [
            "https://user:secret@[2001:db8::1]:8443",
            "files/pkg.whl?token=x#digest",
        ]
    )

    store.discover_artifact(
        artifact(),
        release(project="Demo_Package", origin_url=raw_url),
    )

    query = "SELECT project, origin_url FROM release_mappings"
    row = fetchall(store, query)[0]
    assert tuple(row) == (
        "demo-package",
        "https://[2001:db8::1]:8443/files/pkg.whl",
    )


def test_malformed_origin_is_rejected_without_leaking_credentials(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer)
    secret = "do-not-leak"
    raw_url = f"https://user:{secret}@example.test:bad/file?token=x"

    with pytest.raises(ValueError) as error:
        store.discover_artifact(
            artifact(),
            release(origin_url=raw_url),
        )

    assert secret not in str(error.value)
    assert error.value.__cause__ is None
    assert fetchall(store, "SELECT COUNT(*) FROM artifacts")[0][0] == 0
    assert audit_writer.events == []


def test_duplicate_mapping_with_different_origin_conflicts(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer)
    store.discover_artifact(artifact(), release())
    original_events = list(audit_writer.events)

    with pytest.raises(TransitionConflict):
        store.discover_artifact(
            artifact(),
            release(origin_url="https://mirror.example.test/demo.whl"),
        )

    rows = fetchall(store, "SELECT origin_url FROM release_mappings")
    assert [row["origin_url"] for row in rows] == [
        "https://pypi.org/packages/demo_package-1.0.0.whl"
    ]
    assert audit_writer.events == original_events


def test_ignored_mapping_without_existing_row_fails_closed(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer)
    with closing(store.connection_factory.connect()) as connection, connection:
        connection.execute(
            """
            CREATE TRIGGER ignore_release_mapping
            BEFORE INSERT ON release_mappings
            BEGIN
                SELECT RAISE(IGNORE);
            END
            """
        )

    with pytest.raises(TransitionConflict):
        store.discover_artifact(artifact(), release())

    assert fetchall(store, "SELECT COUNT(*) FROM artifacts")[0][0] == 0
    assert fetchall(store, "SELECT COUNT(*) FROM release_mappings")[0][0] == 0
    assert audit_writer.events == []


def test_ignored_artifact_without_existing_row_fails_closed(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer)
    with closing(store.connection_factory.connect()) as connection, connection:
        connection.execute(
            """
            CREATE TRIGGER ignore_artifact
            BEFORE INSERT ON artifacts
            BEGIN
                SELECT RAISE(IGNORE);
            END
            """
        )

    with pytest.raises(TransitionConflict):
        store.discover_artifact(artifact(), release())

    assert fetchall(store, "SELECT COUNT(*) FROM artifacts")[0][0] == 0
    assert fetchall(store, "SELECT COUNT(*) FROM release_mappings")[0][0] == 0
    assert audit_writer.events == []


def test_new_mapping_for_existing_artifact_is_persisted_and_audited(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer)
    store.discover_artifact(artifact(), release())
    store.discover_artifact(artifact(), release())

    store.discover_artifact(
        artifact(),
        release(version="2.0.0", filename="demo_package-2.0.0.whl"),
    )

    assert fetchall(store, "SELECT COUNT(*) FROM artifacts")[0][0] == 1
    assert fetchall(store, "SELECT COUNT(*) FROM release_mappings")[0][0] == 2
    assert len(audit_writer.events) == 2
    audit_fields = {
        (
            event.actor,
            event.action,
            event.previous_decision,
            event.new_decision,
            event.reason,
        )
        for event in audit_writer.events
    }
    assert audit_fields == {
        (
            "guardian-discovery",
            "artifact.discovered",
            Decision.DENY,
            Decision.DENY,
            "release mapping discovered",
        )
    }


def test_empty_queue_returns_none(tmp_path, audit_writer) -> None:
    store = make_store(tmp_path, audit_writer)

    assert store.claim_next("worker", NOW + timedelta(minutes=5)) is None
    assert audit_writer.events == []


@pytest.mark.parametrize("worker_id", [None, 123, "", "   "])
def test_claim_rejects_invalid_worker_id(
    tmp_path,
    audit_writer,
    worker_id,
) -> None:
    store = make_store(tmp_path, audit_writer)

    with pytest.raises(ValueError):
        store.claim_next(worker_id, NOW + timedelta(minutes=5))

    assert audit_writer.events == []


@pytest.mark.parametrize(
    "lease_until",
    [NOW - timedelta(microseconds=1), NOW],
    ids=["past", "equal"],
)
def test_claim_rejects_nonfuture_lease_without_side_effects(
    tmp_path,
    audit_writer,
    lease_until,
) -> None:
    store = make_store(tmp_path, audit_writer, now=lambda: NOW)
    store.discover_artifact(artifact(), release())
    original_events = list(audit_writer.events)

    with pytest.raises(ValueError, match="future"):
        store.claim_next("worker", lease_until)

    row = fetchall(
        store,
        """
        SELECT state, lease_owner, lease_expires_at, lease_token
        FROM artifacts WHERE sha256 = ?
        """,
        (SHA,),
    )[0]
    assert tuple(row) == (ArtifactState.DISCOVERED.value, None, None, None)
    assert audit_writer.events == original_events


def test_claim_evaluates_now_after_acquiring_writer_lock(
    tmp_path,
    audit_writer,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db", busy_timeout_ms=1)
    migrate(factory)
    setup_store = SQLiteArtifactStore(factory, audit_writer, now=lambda: NOW)
    setup_store.discover_artifact(artifact(), release())

    def now_under_writer_lock() -> datetime:
        with closing(factory.connect()) as probe:  # noqa: SIM117
            with pytest.raises(sqlite3.OperationalError):
                probe.execute("BEGIN IMMEDIATE")
        return NOW

    store = SQLiteArtifactStore(
        factory,
        audit_writer,
        now=now_under_writer_lock,
    )

    claimed = store.claim_next("worker", NOW + timedelta(minutes=5))

    assert claimed is not None


@pytest.mark.parametrize("operation", ["claim", "recover"])
@pytest.mark.parametrize("timestamp", [None, "2026-08-17", 123])
def test_lease_operations_reject_non_datetime_before_side_effects(
    tmp_path,
    audit_writer,
    operation,
    timestamp,
) -> None:
    store = make_store(tmp_path, audit_writer)

    with pytest.raises(ValueError):
        if operation == "claim":
            store.claim_next("worker", timestamp)
        else:
            store.recover_expired_claims(timestamp)

    assert fetchall(store, "SELECT COUNT(*) FROM artifacts")[0][0] == 0
    assert audit_writer.events == []


@pytest.mark.parametrize("operation", ["claim", "recover"])
def test_lease_operations_reject_naive_timestamp_before_mutation(
    tmp_path, audit_writer, operation
) -> None:
    store = make_store(tmp_path, audit_writer)
    store.discover_artifact(artifact(), release())
    original_events = list(audit_writer.events)
    naive = NOW.replace(tzinfo=None)

    with pytest.raises(ValueError):
        if operation == "claim":
            store.claim_next("worker", naive)
        else:
            store.recover_expired_claims(naive)

    row = fetchall(
        store,
        """
        SELECT state, lease_owner, lease_expires_at, lease_token
        FROM artifacts WHERE sha256 = ?
        """,
        (SHA,),
    )[0]
    assert tuple(row) == (ArtifactState.DISCOVERED.value, None, None, None)
    assert audit_writer.events == original_events


def test_audit_failure_rolls_back_discovery(tmp_path, audit_writer) -> None:
    store = make_store(tmp_path, audit_writer)
    audit_writer.fail = True

    with pytest.raises(RuntimeError, match="audit unavailable"):
        store.discover_artifact(artifact(), release())

    assert fetchall(store, "SELECT COUNT(*) FROM artifacts")[0][0] == 0
    assert fetchall(store, "SELECT COUNT(*) FROM release_mappings")[0][0] == 0


def test_audit_failure_rolls_back_claim(tmp_path, audit_writer) -> None:
    store = make_store(tmp_path, audit_writer)
    store.discover_artifact(artifact(), release())
    audit_writer.fail = True

    with pytest.raises(RuntimeError, match="audit unavailable"):
        store.claim_next("worker", NOW + timedelta(minutes=5))

    row = fetchall(
        store,
        """
        SELECT state, lease_owner, lease_expires_at, lease_token
        FROM artifacts WHERE sha256 = ?
        """,
        (SHA,),
    )[0]
    assert tuple(row) == (ArtifactState.DISCOVERED.value, None, None, None)


def test_audit_failure_rolls_back_all_recovered_rows(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer)
    seed_scanning(
        store,
        sha256=SHA,
        owner="worker-1",
        expires_at=NOW - timedelta(minutes=2),
    )
    seed_scanning(
        store,
        sha256="b" * 64,
        owner="worker-2",
        expires_at=NOW - timedelta(minutes=1),
    )
    audit_writer.fail = True

    with pytest.raises(RuntimeError, match="audit unavailable"):
        store.recover_expired_claims(NOW)

    query = "SELECT state, lease_owner FROM artifacts ORDER BY sha256"
    rows = fetchall(store, query)
    assert [tuple(row) for row in rows] == [
        (ArtifactState.SCANNING.value, "worker-1"),
        (ArtifactState.SCANNING.value, "worker-2"),
    ]


def test_claim_dto_matches_persisted_lease(tmp_path, audit_writer) -> None:
    store = make_store(tmp_path, audit_writer)
    store.discover_artifact(artifact(), release())
    lease_until = datetime(
        2026,
        8,
        17,
        9,
        30,
        tzinfo=timezone(timedelta(hours=9)),
    )

    claimed = store.claim_next("worker", lease_until)

    assert claimed is not None
    persisted = fetchall(
        store,
        """
        SELECT lease_owner, lease_expires_at, lease_token
        FROM artifacts WHERE sha256 = ?
        """,
        (SHA,),
    )[0]
    assert claimed.sha256 == SHA
    assert claimed.size_bytes == 123
    assert claimed.worker_id == persisted["lease_owner"] == "worker"
    assert claimed.lease_expires_at.tzinfo is UTC
    persisted_expiry = persisted["lease_expires_at"]
    assert claimed.lease_expires_at.isoformat() == persisted_expiry
    assert claimed.lease_token == persisted["lease_token"]


def test_claim_rejects_unexpected_final_persisted_token(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer)
    store.discover_artifact(artifact(), release())
    original_events = list(audit_writer.events)
    with closing(store.connection_factory.connect()) as connection, connection:
        connection.execute(
            """
            CREATE TRIGGER rewrite_claim_token
            AFTER UPDATE OF state ON artifacts
            WHEN NEW.state = 'SCANNING'
            BEGIN
                UPDATE artifacts
                SET lease_token =
                    'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' ||
                    'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
                WHERE sha256 = NEW.sha256;
            END
            """
        )

    with pytest.raises(TransitionConflict):
        store.claim_next("worker", NOW + timedelta(minutes=5))

    row = fetchall(
        store,
        """
        SELECT state, lease_owner, lease_expires_at, lease_token
        FROM artifacts WHERE sha256 = ?
        """,
        (SHA,),
    )[0]
    assert tuple(row) == (ArtifactState.DISCOVERED.value, None, None, None)
    assert audit_writer.events == original_events


def test_claim_token_is_not_disclosed_when_audit_fails(
    tmp_path,
    audit_writer,
    monkeypatch,
) -> None:
    token = "d" * 64
    store = make_store(tmp_path, audit_writer)
    store.discover_artifact(artifact(), release())
    audit_writer.fail = True
    monkeypatch.setattr(store_module.secrets, "token_hex", lambda _size: token)

    with pytest.raises(RuntimeError, match="audit unavailable") as error:
        store.claim_next("worker", NOW + timedelta(minutes=5))

    assert token not in str(error.value)
    row = fetchall(
        store,
        """
        SELECT state, lease_owner, lease_expires_at, lease_token
        FROM artifacts WHERE sha256 = ?
        """,
        (SHA,),
    )[0]
    assert tuple(row) == (ArtifactState.DISCOVERED.value, None, None, None)


class FailingConnection:
    def __init__(self, *, fail_begin: bool = False) -> None:
        self.fail_begin = fail_begin
        self.in_transaction = False
        self.closed = False
        self.rollback_called = False

    def execute(self, sql: str, parameters=()):
        if sql == "BEGIN IMMEDIATE":
            if self.fail_begin:
                raise sqlite3.OperationalError("begin failed")
            self.in_transaction = True
            return self
        raise sqlite3.IntegrityError("select failed")

    def rollback(self) -> None:
        self.rollback_called = True
        self.in_transaction = False

    def commit(self) -> None:
        raise AssertionError("commit must not be called")

    def close(self) -> None:
        self.closed = True


class FailingFactory:
    def __init__(self, path: Path, connection: FailingConnection) -> None:
        self.path = path
        self.connection = connection

    def connect(self):
        return self.connection


class ConnectionWrapper:
    def __init__(
        self,
        connection,
        *,
        fail_commit: bool = False,
    ) -> None:
        self.connection = connection
        self.fail_commit = fail_commit
        self.closed = False
        self.rollback_called = False

    @property
    def in_transaction(self):
        return self.connection.in_transaction

    def execute(self, sql: str, parameters=()):
        return self.connection.execute(sql, parameters)

    def commit(self) -> None:
        if self.fail_commit:
            raise sqlite3.OperationalError("commit failed")
        self.connection.commit()

    def rollback(self) -> None:
        self.rollback_called = True
        self.connection.rollback()

    def close(self) -> None:
        self.closed = True
        self.connection.close()
        raise sqlite3.OperationalError("close failed")


class WrappingFactory:
    def __init__(
        self,
        factory: ConnectionFactory,
        *,
        fail_commit: bool = False,
    ) -> None:
        self.path = factory.path
        self._factory = factory
        self.fail_commit = fail_commit
        self.last_connection = None

    def connect(self):
        self.last_connection = ConnectionWrapper(
            self._factory.connect(),
            fail_commit=self.fail_commit,
        )
        return self.last_connection


def test_sqlite_write_error_maps_to_store_unavailable_and_closes(
    tmp_path,
    audit_writer,
) -> None:
    connection = FailingConnection(fail_begin=True)
    factory = FailingFactory(tmp_path / "guardian.db", connection)
    store = SQLiteArtifactStore(factory, audit_writer, now=lambda: NOW)

    with pytest.raises(StoreUnavailable) as error:
        store.claim_next("worker", NOW + timedelta(minutes=5))

    assert isinstance(error.value.__cause__, sqlite3.OperationalError)
    assert connection.closed is True


def test_close_failure_after_successful_commit_does_not_reverse_success(
    tmp_path,
    audit_writer,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    wrapping_factory = WrappingFactory(factory)
    store = SQLiteArtifactStore(
        wrapping_factory,
        audit_writer,
        now=lambda: NOW,
    )

    store.discover_artifact(artifact(), release())

    count_query = "SELECT COUNT(*) FROM artifacts"
    with closing(factory.connect()) as connection:
        count = connection.execute(count_query).fetchone()[0]
    assert count == 1
    assert wrapping_factory.last_connection.closed is True
    assert len(audit_writer.events) == 1


def test_commit_failure_remains_primary_when_close_also_fails(
    tmp_path,
    audit_writer,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    wrapping_factory = WrappingFactory(factory, fail_commit=True)
    store = SQLiteArtifactStore(
        wrapping_factory,
        audit_writer,
        now=lambda: NOW,
    )

    with pytest.raises(StoreUnavailable) as error:
        store.discover_artifact(artifact(), release())

    assert isinstance(error.value.__cause__, sqlite3.OperationalError)
    assert str(error.value.__cause__) == "commit failed"
    assert wrapping_factory.last_connection.rollback_called is True
    assert wrapping_factory.last_connection.closed is True
    count_query = "SELECT COUNT(*) FROM artifacts"
    with closing(factory.connect()) as connection:
        count = connection.execute(count_query).fetchone()[0]
    assert count == 0


def test_rollback_and_close_failures_do_not_mask_sqlite_error(
    tmp_path,
    audit_writer,
) -> None:
    connection = FailingConnection()

    def bad_rollback() -> None:
        connection.rollback_called = True
        raise RuntimeError("rollback failed")

    def bad_close() -> None:
        connection.closed = True
        raise RuntimeError("close failed")

    connection.rollback = bad_rollback
    connection.close = bad_close
    factory = FailingFactory(tmp_path / "guardian.db", connection)
    store = SQLiteArtifactStore(factory, audit_writer, now=lambda: NOW)

    with pytest.raises(StoreUnavailable) as error:
        store.claim_next("worker", NOW + timedelta(minutes=5))

    assert isinstance(error.value.__cause__, sqlite3.IntegrityError)
    assert connection.rollback_called is True
    assert connection.closed is True
