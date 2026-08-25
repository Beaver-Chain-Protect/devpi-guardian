import os
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from devpi_guardian.verdicts import db
from devpi_guardian.verdicts.db import ConnectionFactory, migrate, trusted_connection_identity
from devpi_guardian.verdicts.errors import MigrationError, StoreUnavailable


class PragmaCursor:
    def __init__(self, row=None) -> None:
        self.row = row

    def fetchone(self):
        return self.row


class PragmaConnection:
    def __init__(
        self,
        recursive_result=(1,),
        *,
        fail_set=False,
        setup_error: Exception | None = None,
        close_error: Exception | None = None,
    ) -> None:
        self.recursive_result = recursive_result
        self.fail_set = fail_set
        self.setup_error = setup_error
        self.close_error = close_error
        self.closed = False
        self.row_factory = None

    def execute(self, statement: str):
        if statement == "PRAGMA foreign_keys=ON" and self.setup_error:
            raise self.setup_error
        if statement == "PRAGMA recursive_triggers=ON" and self.fail_set:
            raise sqlite3.OperationalError("recursive triggers unavailable")
        if statement == "PRAGMA recursive_triggers":
            return PragmaCursor(self.recursive_result)
        return PragmaCursor()

    def close(self) -> None:
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class CloseFailingMigrationConnection:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.rollback_calls = 0
        self.close_calls = 0

    def __getattr__(self, name: str) -> object:
        return getattr(self.connection, name)

    def rollback(self) -> None:
        self.rollback_calls += 1
        self.connection.rollback()

    def close(self) -> None:
        self.close_calls += 1
        self.connection.close()
        raise sqlite3.OperationalError(
            "close secret",
        )


class MigrationConnectionFactory:
    def __init__(
        self,
        path: Path,
        connection: CloseFailingMigrationConnection,
    ):
        self.path = path
        self.connection = connection

    def connect(self) -> CloseFailingMigrationConnection:
        return self.connection


def test_migrate_creates_schema_and_is_idempotent(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    migrate(factory)
    with closing(factory.connect()) as connection:
        table_query = "SELECT name FROM sqlite_master WHERE type = 'table'"
        tables = {row[0] for row in connection.execute(table_query)}
        trigger_query = "SELECT name FROM sqlite_master WHERE type = 'trigger'"
        triggers = {row[0] for row in connection.execute(trigger_query)}
        version_query = "SELECT MAX(version) FROM schema_migrations"
        version = connection.execute(version_query).fetchone()[0]
    expected_tables = {
        "artifacts",
        "release_mappings",
        "verdicts",
        "evidence",
        "manual_overrides",
        "guardian_activation",
    }
    expected_triggers = {
        "artifacts_identity_immutable",
        "artifacts_identity_delete_guard",
        "release_mappings_history_insert_guard",
        "release_mappings_history_update_guard",
        "release_mappings_history_delete_guard",
        "verdicts_history_insert_guard",
        "verdicts_history_update_guard",
        "verdicts_history_delete_guard",
        "verdicts_baseline_pair_insert_guard",
        "evidence_history_insert_guard",
        "evidence_history_update_guard",
        "evidence_history_delete_guard",
        "manual_overrides_history_insert_guard",
        "manual_overrides_history_update_guard",
        "manual_overrides_history_delete_guard",
        "guardian_activation_immutable_update_guard",
        "guardian_activation_immutable_delete_guard",
        "artifacts_cooldown_pair_insert_guard",
        "artifacts_cooldown_update_guard",
        "audit_events_chain_insert_guard",
        "audit_events_update_guard",
        "audit_events_delete_guard",
        "baseline_overrides_history_update_guard",
        "baseline_overrides_history_delete_guard",
        "baseline_overrides_history_insert_guard",
        "audit_events_history_insert_guard",
    }
    assert expected_tables <= tables
    assert triggers == expected_triggers
    assert version == 6
    assert {"guardian_activation", "audit_events", "baseline_overrides"} <= tables


def test_guardian_activation_row_is_immutable(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)

    with closing(factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO guardian_activation(
                singleton, devpi_uuid, activated_at, activation_version
            ) VALUES (1, 'devpi-uuid', '2026-08-24T00:00:00+00:00', 1)
            """
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                UPDATE guardian_activation SET devpi_uuid = 'changed'
                """
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM guardian_activation")


def test_replace_cannot_bypass_baseline_or_audit_history_guards(tmp_path) -> None:
    path = tmp_path / "guardian.db"
    factory = ConnectionFactory(path)
    migrate(factory)
    sha256 = "a" * 64
    timestamp = "2026-08-24T00:00:00+00:00"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(
            "INSERT INTO artifacts(sha256, size_bytes, state, discovered_at, updated_at) "
            "VALUES (?, 1, 'ALLOW', ?, ?)",
            (sha256, timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO baseline_overrides "
            "(id, sha256, enabled, actor, reason, created_at, is_current) "
            "VALUES (1, ?, 1, 'admin', 'original', ?, 1)",
            (sha256, timestamp),
        )
        connection.execute(
            "INSERT INTO audit_events "
            "(id, event_version, canonicalization_version, occurred_at, actor, action, "
            "sha256, previous_decision, new_decision, reason, policy_version, "
            "analyzer_version, previous_hash, event_hash) "
            "VALUES (1, 1, 1, ?, 'admin', 'seed', ?, 'DENY', 'ALLOW', 'original', "
            "NULL, NULL, ?, ?)",
            (timestamp, sha256, "0" * 64, "f" * 64),
        )
        connection.execute("PRAGMA recursive_triggers = OFF")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT OR REPLACE INTO baseline_overrides "
                "(id, sha256, enabled, actor, reason, created_at, is_current) "
                "VALUES (1, ?, 0, 'attacker', 'replaced', ?, 1)",
                (sha256, timestamp),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT OR REPLACE INTO audit_events "
                "(id, event_version, canonicalization_version, occurred_at, actor, action, "
                "sha256, previous_decision, new_decision, reason, policy_version, "
                "analyzer_version, previous_hash, event_hash) "
                "VALUES (1, 1, 1, ?, 'attacker', 'replace', ?, 'DENY', 'ALLOW', "
                "'replaced', NULL, NULL, ?, ?)",
                (timestamp, sha256, "0" * 64, "f" * 64),
            )
        baseline = connection.execute(
            "SELECT actor, reason FROM baseline_overrides WHERE id = 1"
        ).fetchone()
        audit = connection.execute("SELECT actor, reason FROM audit_events WHERE id = 1").fetchone()
    assert tuple(baseline) == ("admin", "original")
    assert tuple(audit) == ("admin", "original")


def test_migrate_applied_v3_preserves_guardian_activation_row(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    with closing(sqlite3.connect(factory.path)) as connection, connection:
        connection.executescript(
            "\n".join(_packaged_migration_sql(version) for version in (1, 2, 3))
        )
        connection.executemany(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            ((version, "2026-08-24T00:00:00+00:00") for version in (1, 2, 3)),
        )
        connection.execute(
            """
            INSERT INTO guardian_activation(
                singleton, devpi_uuid, activated_at, activation_version
            ) VALUES (1, 'v3-uuid', '2026-08-24T00:00:00+00:00', 1)
            """
        )

    migrate(factory)

    with closing(factory.connect()) as connection:
        versions = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
        activation = connection.execute(
            "SELECT singleton, devpi_uuid, activated_at, activation_version "
            "FROM guardian_activation"
        ).fetchone()
    assert [row[0] for row in versions] == [1, 2, 3, 4, 5, 6]
    assert tuple(activation) == (1, "v3-uuid", "2026-08-24T00:00:00+00:00", 1)


def test_migrate_v3_failure_rolls_back_and_retry_succeeds(
    tmp_path,
    monkeypatch,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    _seed_version_two_schema(factory.path)

    real_read_migration = db._read_migration

    def failing_read_migration(version: int) -> str:
        if version == 3:
            return real_read_migration(version) + "\nTHIS IS INVALID SQL;\n"
        return real_read_migration(version)

    monkeypatch.setattr(db, "_read_migration", failing_read_migration)
    with pytest.raises(MigrationError):
        migrate(factory)

    with closing(factory.connect()) as connection:
        versions = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version",
        ).fetchall()
        activation_objects = connection.execute(
            """
            SELECT type, name FROM sqlite_master
            WHERE name IN (
                'guardian_activation',
                'guardian_activation_immutable_update_guard',
                'guardian_activation_immutable_delete_guard'
            )
            """
        ).fetchall()
    assert [version[0] for version in versions] == [1, 2]
    assert activation_objects == []

    monkeypatch.setattr(db, "_read_migration", real_read_migration)
    migrate(factory)

    with closing(factory.connect()) as connection:
        versions = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version",
        ).fetchall()
    assert [version[0] for version in versions] == [1, 2, 3, 4, 5, 6]


def test_migrate_close_failure_does_not_mask_primary_migration_error(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "guardian.db"
    _seed_version_two_schema(path)
    connection = CloseFailingMigrationConnection(
        ConnectionFactory(path).connect(),
    )
    factory = MigrationConnectionFactory(path, connection)
    primary = MigrationError(str(path))
    real_validate_catalog = db._validate_catalog
    calls = 0

    def fail_after_current_catalog(*args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise primary
        real_validate_catalog(*args, **kwargs)

    monkeypatch.setattr(db, "_validate_catalog", fail_after_current_catalog)
    with pytest.raises(MigrationError) as error:
        migrate(factory)

    assert error.value is primary
    assert str(error.value) == str(path)
    assert "close secret" not in str(error.value)
    assert connection.rollback_calls == 1
    assert connection.close_calls == 1


def test_standalone_migration_close_failure_is_sanitized(tmp_path) -> None:
    path = tmp_path / "guardian.db"
    underlying = ConnectionFactory(path).connect()
    connection = CloseFailingMigrationConnection(underlying)
    factory = MigrationConnectionFactory(path, connection)

    with pytest.raises(MigrationError) as error:
        migrate(factory)

    assert str(error.value) == str(path)
    assert "close secret" not in str(error.value)
    assert isinstance(error.value.__cause__, sqlite3.OperationalError)
    assert connection.close_calls == 1


def test_connection_enables_required_pragmas(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db", busy_timeout_ms=4321)
    migrate(factory)
    with closing(factory.connect()) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 4321
        recursive = connection.execute("PRAGMA recursive_triggers").fetchone()
        assert recursive[0] == 1


def test_connection_captures_trusted_identity_for_new_database(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "new.db")
    connection = factory.connect()
    try:
        identity = trusted_connection_identity(connection)
    finally:
        connection.close()
    assert identity is not None
    assert identity[0] == "file"
    assert identity[1] == str(factory.path.resolve())
    assert type(identity[2]) is int
    assert type(identity[3]) is int


def test_connection_rejects_path_replacement_during_open(tmp_path, monkeypatch) -> None:
    path = tmp_path / "guardian.db"
    replacement = tmp_path / "replacement.db"
    with closing(sqlite3.connect(replacement)) as connection:
        connection.execute("CREATE TABLE marker(value INTEGER)")
        connection.commit()
    real_connect = db.sqlite3.connect

    def swapping_connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        os.replace(replacement, path)
        return connection

    monkeypatch.setattr(db.sqlite3, "connect", swapping_connect)
    with pytest.raises(StoreUnavailable):
        ConnectionFactory(path).connect()


def test_two_live_connections_keep_rotation_rejected_after_one_closes(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    first = factory.connect()
    second = factory.connect()
    replacement = tmp_path / "replacement.db"
    with closing(sqlite3.connect(replacement)) as connection:
        connection.execute("CREATE TABLE marker(value INTEGER)")
        connection.commit()
    first.close()
    os.replace(replacement, factory.path)
    try:
        with pytest.raises(StoreUnavailable):
            factory.connect()
    finally:
        second.close()


def test_concurrent_connection_lifecycle_does_not_leave_stale_registry(tmp_path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    factory = ConnectionFactory(tmp_path / "guardian.db")

    def open_and_close(_number: int) -> None:
        connection = factory.connect()
        connection.close()

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(open_and_close, range(32)))
    connection = factory.connect()
    connection.close()


@pytest.mark.parametrize(
    "recursive_result",
    [None, (0,), (True,)],
    ids=["missing", "disabled", "non-integer"],
)
def test_connection_rejects_wrong_recursive_trigger_result(
    tmp_path,
    monkeypatch,
    recursive_result,
) -> None:
    connection = PragmaConnection(recursive_result)
    monkeypatch.setattr(
        db.sqlite3,
        "connect",
        lambda *args, **kwargs: connection,
    )

    with pytest.raises(StoreUnavailable) as error:
        ConnectionFactory(tmp_path / "guardian.db").connect()

    assert isinstance(error.value.__cause__, sqlite3.OperationalError)
    assert connection.closed is True


def test_connection_maps_recursive_trigger_setup_failure_and_closes(
    tmp_path,
    monkeypatch,
) -> None:
    connection = PragmaConnection(fail_set=True)
    monkeypatch.setattr(
        db.sqlite3,
        "connect",
        lambda *args, **kwargs: connection,
    )

    with pytest.raises(StoreUnavailable) as error:
        ConnectionFactory(tmp_path / "guardian.db").connect()

    assert isinstance(error.value.__cause__, sqlite3.OperationalError)
    assert connection.closed is True


@pytest.mark.parametrize(
    "setup_error",
    [OSError("setup failed"), sqlite3.OperationalError("setup failed")],
    ids=["os-error", "sqlite-error"],
)
def test_connection_close_failure_does_not_mask_setup_error(
    tmp_path,
    monkeypatch,
    setup_error: Exception,
) -> None:
    connection = PragmaConnection(
        setup_error=setup_error,
        close_error=sqlite3.OperationalError("close failed"),
    )
    monkeypatch.setattr(
        db.sqlite3,
        "connect",
        lambda *args, **kwargs: connection,
    )

    with pytest.raises(StoreUnavailable) as error:
        ConnectionFactory(tmp_path / "guardian.db").connect()

    assert error.value.__cause__ is setup_error
    assert connection.closed is True


def test_schema_rejects_invalid_sha256(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    timestamp = "2026-08-17T00:00:00Z"
    with closing(factory.connect()) as connection, connection:
        try:
            connection.execute(
                """
                INSERT INTO artifacts(
                    sha256, size_bytes, state, discovered_at, updated_at
                ) VALUES (?, 1, 'DISCOVERED', ?, ?)
                """,
                ("NOT-A-SHA", timestamp, timestamp),
            )
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("invalid SHA-256 was accepted")


@pytest.mark.parametrize(
    "invalid_sha256",
    [
        None,
        sqlite3.Binary(b"a" * 64),
        "A" * 64,
        "é" + "a" * 63,
        "a" * 63,
        "a" * 65,
    ],
    ids=["null", "blob", "uppercase", "non-ascii", "short", "long"],
)
def test_schema_rejects_bad_sha_storage(tmp_path, invalid_sha256) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)

    integrity_error = pytest.raises(sqlite3.IntegrityError)
    with closing(factory.connect()) as connection, integrity_error:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at
            ) VALUES (?, 1, 'DISCOVERED', ?, ?)
            """,
            (invalid_sha256, "2026-08-17T00:00:00Z", "2026-08-17T00:00:00Z"),
        )


def test_schema_accepts_canonical_text_sha256(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    sha256 = "a" * 64

    with closing(factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at
            ) VALUES (?, 1, 'DISCOVERED', ?, ?)
            """,
            (sha256, "2026-08-17T00:00:00Z", "2026-08-17T00:00:00Z"),
        )
        query = "SELECT sha256, typeof(sha256) FROM artifacts"
        stored = connection.execute(query).fetchone()

    assert tuple(stored) == (sha256, "text")


def test_schema_rejects_nonnumeric_text_size(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)

    integrity_error = pytest.raises(sqlite3.IntegrityError)
    with closing(factory.connect()) as connection, integrity_error:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at
            ) VALUES (?, ?, 'DISCOVERED', ?, ?)
            """,
            (
                "a" * 64,
                "not-a-number",
                "2026-08-17T00:00:00Z",
                "2026-08-17T00:00:00Z",
            ),
        )


@pytest.mark.parametrize(
    ("state", "owner", "expires_at", "token"),
    [
        ("SCANNING", "worker", "2026-08-17T00:05:00+00:00", None),
        ("SCANNING", None, "2026-08-17T00:05:00+00:00", "b" * 64),
        ("SCANNING", "worker", None, "b" * 64),
        ("DISCOVERED", None, None, "b" * 64),
        ("ALLOW", "worker", "2026-08-17T00:05:00+00:00", "b" * 64),
    ],
)
def test_schema_requires_complete_lease_tuple_only_while_scanning(
    tmp_path,
    state,
    owner,
    expires_at,
    token,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)

    with closing(factory.connect()) as connection:  # noqa: SIM117
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO artifacts(
                    sha256, size_bytes, state, discovered_at, updated_at,
                    lease_owner, lease_expires_at, lease_token
                ) VALUES (?, 1, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "a" * 64,
                    state,
                    "2026-08-17T00:00:00+00:00",
                    "2026-08-17T00:00:00+00:00",
                    owner,
                    expires_at,
                    token,
                ),
            )


@pytest.mark.parametrize(
    "token",
    [
        sqlite3.Binary(b"b" * 64),
        "B" * 64,
        "é" + "b" * 63,
        "b" * 63,
        "b" * 65,
    ],
    ids=["blob", "uppercase", "non-ascii", "short", "long"],
)
def test_schema_rejects_noncanonical_lease_token(tmp_path, token) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)

    with closing(factory.connect()) as connection:  # noqa: SIM117
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO artifacts(
                    sha256, size_bytes, state, discovered_at, updated_at,
                    lease_owner, lease_expires_at, lease_token
                ) VALUES (?, 1, 'SCANNING', ?, ?, 'worker', ?, ?)
                """,
                (
                    "a" * 64,
                    "2026-08-17T00:00:00+00:00",
                    "2026-08-17T00:00:00+00:00",
                    "2026-08-17T00:05:00+00:00",
                    token,
                ),
            )


def test_schema_requires_unique_nonnull_lease_tokens(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    token = "f" * 64
    timestamp = "2026-08-17T00:00:00+00:00"

    with closing(factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at,
                lease_owner, lease_expires_at, lease_token
            ) VALUES (?, 1, 'SCANNING', ?, ?, 'worker-a', ?, ?)
            """,
            ("a" * 64, timestamp, timestamp, timestamp, token),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO artifacts(
                    sha256, size_bytes, state, discovered_at, updated_at,
                    lease_owner, lease_expires_at, lease_token
                ) VALUES (?, 1, 'SCANNING', ?, ?, 'worker-b', ?, ?)
                """,
                ("b" * 64, timestamp, timestamp, timestamp, token),
            )


def _seed_schema_version(path: Path, version: object) -> None:
    version_type = "INTEGER" if type(version) is int else "TEXT"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(
            f"""
            CREATE TABLE schema_migrations (
                version {version_type} PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (version, "2026-08-17T00:00:00Z"),
        )


def test_migrate_rejects_v1_without_schema(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    _seed_schema_version(factory.path, 1)

    with pytest.raises(MigrationError):
        migrate(factory)


def test_migrate_rejects_future_schema_version(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    _seed_schema_version(factory.path, 7)

    with pytest.raises(MigrationError):
        migrate(factory)


def test_migrate_maps_text_version_to_error(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    _seed_schema_version(factory.path, "x")

    with pytest.raises(MigrationError):
        migrate(factory)


@pytest.mark.parametrize(
    "corruption_sql",
    [
        "DROP TABLE evidence",
        "ALTER TABLE artifacts DROP COLUMN last_error",
        "DROP INDEX evidence_verdict_id_idx",
        "DROP INDEX artifacts_lease_token_unique_idx",
        "DROP TRIGGER artifacts_identity_immutable",
    ],
    ids=[
        "missing-table",
        "missing-column",
        "missing-index",
        "missing-lease-token-index",
        "missing-identity-trigger",
    ],
)
def test_migrate_rejects_incomplete(tmp_path, corruption_sql: str) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    with closing(sqlite3.connect(factory.path)) as connection, connection:
        connection.execute(corruption_sql)

    with pytest.raises(MigrationError):
        migrate(factory)


def _packaged_migration_sql(version: int = 1) -> str:
    names = {
        1: "001_initial.sql",
        2: "002_baseline_tier.sql",
        3: "003_guardian_activation.sql",
        4: "004_artifact_cooldown.sql",
        5: "005_audit_events.sql",
        6: "006_baseline_overrides.sql",
    }
    return (
        db.resources.files("devpi_guardian.verdicts.sql")
        .joinpath(names[version])
        .read_text(encoding="utf-8")
    )


def _seed_version_one_schema(path: Path, sql: str) -> None:
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.executescript(sql)
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (1, "2026-08-17T00:00:00Z"),
        )


def _seed_version_two_schema(path: Path) -> None:
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.executescript(
            "\n".join((_packaged_migration_sql(1), _packaged_migration_sql(2)))
        )
        connection.executemany(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            ((1, "2026-08-17T00:00:00Z"), (2, "2026-08-17T00:00:00Z")),
        )


def _seed_legacy_v1_verdict(path: Path) -> tuple[str, str]:
    _seed_version_one_schema(path, _packaged_migration_sql())
    subject_sha256 = "a" * 64
    baseline_sha256 = "b" * 64
    timestamp = "2026-08-17T00:00:00+00:00"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at
            ) VALUES (?, 1, 'REVIEW', ?, ?),
                   (?, 1, 'DISCOVERED', ?, ?)
            """,
            (
                subject_sha256,
                timestamp,
                timestamp,
                baseline_sha256,
                timestamp,
                timestamp,
            ),
        )
        connection.execute(
            """
            INSERT INTO verdicts(
                sha256, decision, score, policy_version, analyzer_version,
                baseline_sha256, is_current, created_at
            ) VALUES (?, 'REVIEW', 1.0, 'policy-1', 'analyzer-1', ?, 1, ?)
            """,
            (subject_sha256, baseline_sha256, timestamp),
        )
    return subject_sha256, baseline_sha256


def _assert_v1_state(
    path: Path,
    subject_sha256: str,
    baseline_sha256: str,
    *,
    has_legacy_row: bool,
) -> None:
    with closing(sqlite3.connect(path)) as connection, connection:
        versions = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version",
        ).fetchall()
        query = "PRAGMA table_info(verdicts)"
        verdict_columns = {row[1] for row in connection.execute(query)}
        trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger' AND name = 'verdicts_history_update_guard'
            """
        ).fetchone()
        assert [row[0] for row in versions] == [1]
        assert "baseline_tier" not in verdict_columns
        assert trigger is not None
        if has_legacy_row:
            row = connection.execute(
                "SELECT baseline_sha256 FROM verdicts WHERE sha256 = ?",
                (subject_sha256,),
            ).fetchone()
            assert tuple(row) == (baseline_sha256,)
        else:
            query = "SELECT COUNT(*) FROM verdicts"
            assert connection.execute(query).fetchone() == (0,)
            timestamp = "2026-08-17T00:00:00+00:00"
            connection.execute(
                """
                INSERT INTO artifacts(
                    sha256, size_bytes, state, discovered_at, updated_at
                ) VALUES (?, 1, 'REVIEW', ?, ?),
                       (?, 1, 'DISCOVERED', ?, ?)
                """,
                (
                    subject_sha256,
                    timestamp,
                    timestamp,
                    baseline_sha256,
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO verdicts(
                    sha256, decision, score, policy_version, analyzer_version,
                    baseline_sha256, is_current, created_at
                ) VALUES (?, 'REVIEW', 1.0, 'policy-1', 'analyzer-1', ?, 1, ?)
                """,
                (subject_sha256, baseline_sha256, timestamp),
            )

        connection.commit()
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE verdicts SET decision = 'DENY'")


@pytest.mark.parametrize("seed_legacy_row", [False, True], ids=["fresh", "v1"])
def test_migrate_v2_failure_rolls_back_and_retry_succeeds(
    tmp_path,
    monkeypatch,
    seed_legacy_row: bool,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    if seed_legacy_row:
        subject_sha256, baseline_sha256 = _seed_legacy_v1_verdict(factory.path)
    else:
        subject_sha256, baseline_sha256 = "a" * 64, "b" * 64

    real_read_migration = db._read_migration

    def failing_read_migration(version: int) -> str:
        sql = real_read_migration(version)
        if version == 2:
            return sql + "\nTHIS IS INVALID SQL;\n"
        return sql

    monkeypatch.setattr(db, "_read_migration", failing_read_migration)
    with pytest.raises(MigrationError):
        migrate(factory)

    _assert_v1_state(
        factory.path,
        subject_sha256,
        baseline_sha256,
        has_legacy_row=seed_legacy_row,
    )

    monkeypatch.setattr(db, "_read_migration", real_read_migration)
    migrate(factory)

    with closing(factory.connect()) as connection:
        versions = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version",
        ).fetchall()
        query = " ".join(
            (
                "SELECT baseline_sha256, baseline_tier FROM verdicts",
                "WHERE sha256 = ?",
            )
        )
        row = connection.execute(
            query,
            (subject_sha256,),
        ).fetchone()
    assert [version[0] for version in versions] == [1, 2, 3, 4, 5, 6]
    assert tuple(row) == (baseline_sha256, None)


def test_migrate_v2_catalog_validation_failure_rolls_back_and_retry_succeeds(
    tmp_path,
    monkeypatch,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    subject_sha256, baseline_sha256 = _seed_legacy_v1_verdict(factory.path)
    real_validate_catalog = db._validate_catalog
    calls = 0

    def fail_after_v2(
        connection: sqlite3.Connection,
        expected: db._Catalog,
        path: Path,
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise MigrationError(str(path))
        real_validate_catalog(connection, expected, path)

    monkeypatch.setattr(db, "_validate_catalog", fail_after_v2)
    with pytest.raises(MigrationError):
        migrate(factory)

    _assert_v1_state(
        factory.path,
        subject_sha256,
        baseline_sha256,
        has_legacy_row=True,
    )

    monkeypatch.setattr(db, "_validate_catalog", real_validate_catalog)
    migrate(factory)
    with closing(factory.connect()) as connection:
        versions = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version",
        ).fetchall()
        query = " ".join(
            (
                "SELECT baseline_sha256, baseline_tier FROM verdicts",
                "WHERE sha256 = ?",
            )
        )
        row = connection.execute(
            query,
            (subject_sha256,),
        ).fetchone()
    assert [version[0] for version in versions] == [1, 2, 3, 4, 5, 6]
    assert tuple(row) == (baseline_sha256, None)


def test_migrate_rejects_constraintless_same_shape_schema(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    sql = _packaged_migration_sql()
    sha_constraint = """    sha256 TEXT NOT NULL PRIMARY KEY
        CHECK(
            typeof(sha256) = 'text'
            AND length(sha256) = 64
            AND sha256 NOT GLOB '*[^0-9a-f]*'
        ),"""
    modified_sql = sql.replace(sha_constraint, "    sha256 TEXT PRIMARY KEY,")
    assert modified_sql != sql
    _seed_version_one_schema(factory.path, modified_sql)

    with pytest.raises(MigrationError):
        migrate(factory)


def test_migrate_upgrades_v1_and_preserves_unclassified_legacy_baseline(
    tmp_path,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    _seed_version_one_schema(factory.path, _packaged_migration_sql())
    timestamp = "2026-08-17T00:00:00+00:00"
    with closing(sqlite3.connect(factory.path)) as connection, connection:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at
            ) VALUES (?, 1, 'REVIEW', ?, ?),
                   (?, 1, 'DISCOVERED', ?, ?)
            """,
            (
                "a" * 64,
                timestamp,
                timestamp,
                "b" * 64,
                timestamp,
                timestamp,
            ),
        )
        connection.execute(
            """
            INSERT INTO verdicts(
                sha256, decision, score, policy_version, analyzer_version,
                baseline_sha256, is_current, created_at
            ) VALUES (?, 'REVIEW', 1.0, 'policy-1', 'analyzer-1', ?, 1, ?)
            """,
            ("a" * 64, "b" * 64, timestamp),
        )

    migrate(factory)
    migrate(factory)

    with closing(factory.connect()) as connection:
        versions = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version",
        ).fetchall()
        row = connection.execute(
            "SELECT baseline_sha256, baseline_tier FROM verdicts",
        ).fetchone()

    assert [version[0] for version in versions] == [1, 2, 3, 4, 5, 6]
    assert tuple(row) == ("b" * 64, None)


@pytest.mark.parametrize(
    ("baseline_sha256", "baseline_tier"),
    [(None, "same_tag"), ("b" * 64, None), ("b" * 64, "unknown")],
    ids=["tier-only", "sha-only", "unknown-tier"],
)
def test_schema_requires_baseline_sha_and_tier_pair(
    tmp_path,
    baseline_sha256,
    baseline_tier,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    timestamp = "2026-08-17T00:00:00+00:00"
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at
            ) VALUES (?, 1, 'REVIEW', ?, ?),
                   (?, 1, 'DISCOVERED', ?, ?)
            """,
            (
                "a" * 64,
                timestamp,
                timestamp,
                "b" * 64,
                timestamp,
                timestamp,
            ),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO verdicts(
                    sha256, decision, score, policy_version, analyzer_version,
                    baseline_sha256, baseline_tier, is_current, created_at
                ) VALUES (?, 'REVIEW', 1.0, 'policy-1', 'analyzer-1', ?, ?,
                1, ?)
                """,
                ("a" * 64, baseline_sha256, baseline_tier, timestamp),
            )


def _seed_classified_verdict(connection: sqlite3.Connection) -> None:
    timestamp = "2026-08-17T00:00:00+00:00"
    connection.execute(
        """
        INSERT INTO artifacts(
            sha256, size_bytes, state, discovered_at, updated_at
        ) VALUES (?, 1, 'REVIEW', ?, ?),
               (?, 1, 'DISCOVERED', ?, ?)
        """,
        (
            "a" * 64,
            timestamp,
            timestamp,
            "b" * 64,
            timestamp,
            timestamp,
        ),
    )
    connection.execute(
        """
        INSERT INTO verdicts(
            sha256, decision, score, policy_version, analyzer_version,
            baseline_sha256, is_current, created_at, baseline_tier
        ) VALUES (?, 'REVIEW', 1.0, 'policy-1', 'analyzer-1', ?, 1, ?,
        'same_tag')
        """,
        ("a" * 64, "b" * 64, timestamp),
    )


@pytest.mark.parametrize(
    "mutation_sql",
    [
        "UPDATE verdicts SET baseline_tier = 'sdist'",
        "UPDATE verdicts SET baseline_tier = 'sdist', is_current = 0",
        "UPDATE verdicts SET baseline_tier = NULL",
        "UPDATE verdicts SET baseline_tier = NULL, is_current = 0",
    ],
)
def test_schema_rejects_classified_verdict_tier_mutation(
    tmp_path,
    mutation_sql: str,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    with closing(factory.connect()) as connection, connection:
        _seed_classified_verdict(connection)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(mutation_sql)

        row = connection.execute(
            "SELECT baseline_sha256, baseline_tier, is_current FROM verdicts",
        ).fetchone()
    assert tuple(row) == ("b" * 64, "same_tag", 1)


def test_schema_allows_only_classified_verdict_current_marker_deactivation(
    tmp_path,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    with closing(factory.connect()) as connection, connection:
        _seed_classified_verdict(connection)
        connection.execute("UPDATE verdicts SET is_current = 0")
        row = connection.execute(
            "SELECT baseline_sha256, baseline_tier, is_current FROM verdicts",
        ).fetchone()

    assert tuple(row) == ("b" * 64, "same_tag", 0)


@pytest.mark.parametrize(
    "baseline_tier",
    [1, True, sqlite3.Binary(b"same_tag")],
    ids=["integer", "boolean", "blob"],
)
def test_schema_rejects_nontext_baseline_tier(
    tmp_path,
    baseline_tier,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    timestamp = "2026-08-17T00:00:00+00:00"
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at
            ) VALUES (?, 1, 'REVIEW', ?, ?),
                   (?, 1, 'DISCOVERED', ?, ?)
            """,
            (
                "a" * 64,
                timestamp,
                timestamp,
                "b" * 64,
                timestamp,
                timestamp,
            ),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO verdicts(
                    sha256, decision, score, policy_version, analyzer_version,
                    baseline_sha256, baseline_tier, is_current, created_at
                ) VALUES (?, 'REVIEW', 1.0, 'policy-1', 'analyzer-1', ?, ?,
                1, ?)
                """,
                ("a" * 64, "b" * 64, baseline_tier, timestamp),
            )


@pytest.mark.parametrize(
    ("baseline_sha256", "baseline_tier"),
    [
        ("b" * 64, "same_tag"),
        ("b" * 64, "universal_wheel"),
        ("b" * 64, "sdist"),
        (None, None),
    ],
    ids=["same-tag", "universal-wheel", "sdist", "both-null"],
)
def test_schema_accepts_exact_baseline_pairs(
    tmp_path,
    baseline_sha256,
    baseline_tier,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    timestamp = "2026-08-17T00:00:00+00:00"
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at
            ) VALUES (?, 1, 'REVIEW', ?, ?),
                   (?, 1, 'DISCOVERED', ?, ?)
            """,
            (
                "a" * 64,
                timestamp,
                timestamp,
                "b" * 64,
                timestamp,
                timestamp,
            ),
        )
        connection.execute(
            """
            INSERT INTO verdicts(
                sha256, decision, score, policy_version, analyzer_version,
                baseline_sha256, baseline_tier, is_current, created_at
            ) VALUES (?, 'REVIEW', 1.0, 'policy-1', 'analyzer-1', ?, ?, 1, ?)
            """,
            ("a" * 64, baseline_sha256, baseline_tier, timestamp),
        )
        row = connection.execute(
            "SELECT baseline_sha256, baseline_tier FROM verdicts",
        ).fetchone()

    assert tuple(row) == (baseline_sha256, baseline_tier)


def test_migrate_rejects_wrong_same_named_index(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    with closing(sqlite3.connect(factory.path)) as connection, connection:
        connection.execute("DROP INDEX verdicts_one_current_idx")
        sql = "CREATE INDEX verdicts_one_current_idx ON evidence(rule_id)"
        connection.execute(sql)

    with pytest.raises(MigrationError):
        migrate(factory)


def test_migrate_rejects_unexpected_trigger(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    with closing(sqlite3.connect(factory.path)) as connection, connection:
        connection.execute(
            """
            CREATE TRIGGER unexpected_guardian_trigger
            AFTER INSERT ON artifacts BEGIN SELECT 1; END
            """
        )

    with pytest.raises(MigrationError):
        migrate(factory)


def test_migrate_rejects_sqlite_lookalike_trigger(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    with closing(sqlite3.connect(factory.path)) as connection, connection:
        connection.execute(
            """
            CREATE TRIGGER sqliteXguardian_bypass
            AFTER INSERT ON artifacts
            BEGIN
                UPDATE artifacts SET state = 'ALLOW' WHERE sha256 = NEW.sha256;
            END
            """
        )

    with pytest.raises(MigrationError):
        migrate(factory)


def _seed_history_rows(connection: sqlite3.Connection) -> None:
    sha256 = "a" * 64
    timestamp = "2026-08-17T00:00:00+00:00"
    connection.execute(
        """
        INSERT INTO artifacts(
            sha256, size_bytes, state, discovered_at, updated_at
        ) VALUES (?, 1, 'REVIEW', ?, ?)
        """,
        (sha256, timestamp, timestamp),
    )
    verdict = connection.execute(
        """
        INSERT INTO verdicts(
            sha256, decision, score, policy_version, analyzer_version,
            baseline_sha256, is_current, created_at
        ) VALUES (?, 'REVIEW', 1.0, 'policy-1', 'analyzer-1', NULL, 1, ?)
        """,
        (sha256, timestamp),
    )
    connection.execute(
        """
        INSERT INTO evidence(
            verdict_id, rule_id, action, file_path, line, message,
            details_json
        ) VALUES (?, 'RULE-1', 'REVIEW', NULL, NULL, 'review', '{}')
        """,
        (verdict.lastrowid,),
    )
    connection.execute(
        """
        INSERT INTO manual_overrides(
            sha256, decision, actor, reason, created_at, expires_at,
            is_current
        ) VALUES (?, 'ALLOW', 'admin', 'reviewed', ?, NULL, 1)
        """,
        (sha256, timestamp),
    )


@pytest.mark.parametrize(
    "mutation_sql",
    [
        "UPDATE artifacts SET size_bytes = 2",
        "UPDATE artifacts SET discovered_at = '2026-08-18T00:00:00+00:00'",
        f"UPDATE artifacts SET sha256 = {'b' * 64!r}",
        "UPDATE verdicts SET decision = 'DENY'",
        "UPDATE verdicts SET decision = 'DENY', is_current = 0",
        "UPDATE verdicts SET baseline_tier = 'sdist'",
        "UPDATE verdicts SET baseline_tier = 'sdist', is_current = 0",
        "DELETE FROM verdicts",
        "UPDATE evidence SET message = 'changed'",
        "DELETE FROM evidence",
        "UPDATE manual_overrides SET reason = 'changed'",
        "UPDATE manual_overrides SET reason = 'changed', is_current = 0",
        "DELETE FROM manual_overrides",
    ],
)
def test_schema_triggers_reject_identity_and_history_mutation(
    tmp_path,
    mutation_sql: str,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    with closing(factory.connect()) as connection, connection:
        _seed_history_rows(connection)

    with closing(factory.connect()) as connection:  # noqa: SIM117
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(mutation_sql)


def test_schema_triggers_allow_only_current_marker_deactivation(
    tmp_path,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    with closing(factory.connect()) as connection, connection:
        _seed_history_rows(connection)
        connection.execute("UPDATE verdicts SET is_current = 0")
        connection.execute("UPDATE manual_overrides SET is_current = 0")

        verdict_marker = connection.execute(
            "SELECT is_current FROM verdicts",
        ).fetchone()[0]
        override_marker = connection.execute(
            "SELECT is_current FROM manual_overrides",
        ).fetchone()[0]

    assert (verdict_marker, override_marker) == (0, 0)


@pytest.mark.parametrize(
    ("mutation_sql", "parameters"),
    [
        ("DELETE FROM artifacts", ()),
        (
            """
            INSERT OR REPLACE INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at
            ) VALUES (?, 999, 'DISCOVERED', ?, ?)
            """,
            (
                "a" * 64,
                "2026-08-18T00:00:00+00:00",
                "2026-08-18T00:00:00+00:00",
            ),
        ),
    ],
    ids=["delete", "replace"],
)
def test_schema_rejects_artifact_delete_and_replacement(
    tmp_path,
    mutation_sql: str,
    parameters: tuple[object, ...],
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    timestamp = "2026-08-17T00:00:00+00:00"
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at
            ) VALUES (?, 1, 'DISCOVERED', ?, ?)
            """,
            ("a" * 64, timestamp, timestamp),
        )
        artifact_row = connection.execute("SELECT * FROM artifacts").fetchone()
        before = tuple(artifact_row)

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(mutation_sql, parameters)

        after = tuple(connection.execute("SELECT * FROM artifacts").fetchone())

    assert after == before


@pytest.mark.parametrize(
    ("recursive_triggers", "mutation_sql", "parameters"),
    [
        (True, "UPDATE release_mappings SET origin_url = 'changed'", ()),
        (True, "DELETE FROM release_mappings", ()),
        (
            False,
            """
            INSERT OR REPLACE INTO release_mappings(
                id, stage, project, version, filename, sha256,
                origin_url, discovered_at
            ) VALUES (1, 'root/pypi', 'demo', '1.0', 'demo.whl', ?,
                      'https://replacement.test/id', ?)
            """,
            ("a" * 64, "2026-08-18T00:00:00+00:00"),
        ),
        (
            True,
            """
            INSERT OR REPLACE INTO release_mappings(
                id, stage, project, version, filename, sha256,
                origin_url, discovered_at
            ) VALUES (2, 'root/pypi', 'demo', '1.0', 'demo.whl', ?,
                      'https://replacement.test/unique', ?)
            """,
            ("a" * 64, "2026-08-18T00:00:00+00:00"),
        ),
    ],
    ids=["update", "delete", "replace-id", "replace-unique"],
)
def test_schema_rejects_release_mapping_mutation(
    tmp_path,
    recursive_triggers: bool,
    mutation_sql: str,
    parameters: tuple[object, ...],
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    timestamp = "2026-08-17T00:00:00+00:00"
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at
            ) VALUES (?, 1, 'DISCOVERED', ?, ?)
            """,
            ("a" * 64, timestamp, timestamp),
        )
        connection.execute(
            """
            INSERT INTO release_mappings(
                stage, project, version, filename, sha256,
                origin_url, discovered_at
            ) VALUES ('root/pypi', 'demo', '1.0', 'demo.whl', ?,
                      'https://origin.test/demo', ?)
            """,
            ("a" * 64, timestamp),
        )
        setting = "ON" if recursive_triggers else "OFF"
        connection.execute(f"PRAGMA recursive_triggers={setting}")
        before = tuple(
            connection.execute("SELECT * FROM release_mappings").fetchone(),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(mutation_sql, parameters)

        after = tuple(
            connection.execute("SELECT * FROM release_mappings").fetchone(),
        )

    assert after == before


@pytest.mark.parametrize(
    ("table", "recursive_triggers", "replacement_sql"),
    [
        (
            "verdicts",
            False,
            """
            INSERT OR REPLACE INTO verdicts(
                id, sha256, decision, score, policy_version,
                analyzer_version, baseline_sha256, is_current, created_at
            ) VALUES (1, ?, 'DENY', 0.0, 'replacement', 'replacement',
                      NULL, 1, ?)
            """,
        ),
        (
            "evidence",
            False,
            """
            INSERT OR REPLACE INTO evidence(
                id, verdict_id, rule_id, action, file_path, line, message,
                details_json
            ) VALUES (1, 1, 'REPLACED', 'DENY', NULL, NULL,
                      'replacement', '{}')
            """,
        ),
        (
            "manual_overrides",
            False,
            """
            INSERT OR REPLACE INTO manual_overrides(
                id, sha256, decision, actor, reason, created_at, expires_at,
                is_current
            ) VALUES (1, ?, 'DENY', 'other', 'replacement', ?, NULL, 1)
            """,
        ),
        (
            "verdicts",
            True,
            """
            INSERT OR REPLACE INTO verdicts(
                id, sha256, decision, score, policy_version,
                analyzer_version, baseline_sha256, is_current, created_at
            ) VALUES (2, ?, 'REVIEW', 1.0, 'replacement', 'replacement',
                      NULL, 1, ?)
            """,
        ),
        (
            "manual_overrides",
            True,
            """
            INSERT OR REPLACE INTO manual_overrides(
                id, sha256, decision, actor, reason, created_at, expires_at,
                is_current
            ) VALUES (2, ?, 'DENY', 'other', 'replacement', ?, NULL, 1)
            """,
        ),
    ],
    ids=[
        "verdict-id",
        "evidence-id",
        "override-id",
        "verdict-current",
        "override-current",
    ],
)
def test_schema_triggers_reject_history_replacement(
    tmp_path,
    table: str,
    recursive_triggers: bool,
    replacement_sql: str,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    timestamp = "2026-08-17T00:00:00+00:00"
    with closing(factory.connect()) as connection, connection:
        _seed_history_rows(connection)
        recursive_setting = "ON" if recursive_triggers else "OFF"
        connection.execute(f"PRAGMA recursive_triggers={recursive_setting}")
        rows = connection.execute(f"SELECT * FROM {table}")
        before = tuple(tuple(row) for row in rows)
        parameters = ()
        if table != "evidence":
            parameters = ("a" * 64, timestamp)

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(replacement_sql, parameters)

        rows = connection.execute(f"SELECT * FROM {table}")
        after = tuple(tuple(row) for row in rows)

    assert after == before


@pytest.mark.parametrize(
    "busy_timeout_ms",
    [True, 1.0, "5000", 0, -1, 2_147_483_648],
    ids=["bool", "float", "string", "zero", "negative", "too-large"],
)
def test_factory_rejects_timeout(tmp_path, busy_timeout_ms: object) -> None:
    path = tmp_path / "guardian.db"
    with pytest.raises(ValueError):
        ConnectionFactory(path, busy_timeout_ms=busy_timeout_ms)


def test_migrate_rejects_database_without_wal_support() -> None:
    with pytest.raises(MigrationError):
        migrate(ConnectionFactory(Path(":memory:")))


@pytest.mark.parametrize(
    "resource_error",
    [
        ImportError("migration package missing"),
        UnicodeError("migration is not UTF-8"),
    ],
)
def test_migrate_maps_packaged_resource_errors(
    tmp_path, monkeypatch, resource_error: Exception
) -> None:
    def fail_to_load_package(_package: str) -> None:
        raise resource_error

    factory = ConnectionFactory(tmp_path / "guardian.db")
    monkeypatch.setattr(db.resources, "files", fail_to_load_package)

    with pytest.raises(MigrationError) as error:
        migrate(factory)

    assert str(factory.path) in str(error.value)
