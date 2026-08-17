import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from devpi_guardian.verdicts import db
from devpi_guardian.verdicts.db import ConnectionFactory, migrate
from devpi_guardian.verdicts.errors import MigrationError


def test_migrate_creates_schema_and_is_idempotent(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    migrate(factory)
    with closing(factory.connect()) as connection:
        table_query = "SELECT name FROM sqlite_master WHERE type = 'table'"
        tables = {row[0] for row in connection.execute(table_query)}
        version_query = "SELECT MAX(version) FROM schema_migrations"
        version = connection.execute(version_query).fetchone()[0]
    expected_tables = {
        "artifacts",
        "release_mappings",
        "verdicts",
        "evidence",
        "manual_overrides",
    }
    assert expected_tables <= tables
    assert version == 1


def test_connection_enables_required_pragmas(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db", busy_timeout_ms=4321)
    migrate(factory)
    with closing(factory.connect()) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 4321


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
    _seed_schema_version(factory.path, 2)

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
    ],
    ids=[
        "missing-table",
        "missing-column",
        "missing-index",
        "missing-lease-token-index",
    ],
)
def test_migrate_rejects_incomplete(tmp_path, corruption_sql: str) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    with closing(sqlite3.connect(factory.path)) as connection, connection:
        connection.execute(corruption_sql)

    with pytest.raises(MigrationError):
        migrate(factory)


def _packaged_migration_sql() -> str:
    return (
        db.resources.files("devpi_guardian.verdicts.sql")
        .joinpath("001_initial.sql")
        .read_text(encoding="utf-8")
    )


def _seed_version_one_schema(path: Path, sql: str) -> None:
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.executescript(sql)
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (1, "2026-08-17T00:00:00Z"),
        )


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
