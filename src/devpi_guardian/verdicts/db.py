from __future__ import annotations

import sqlite3
from contextlib import closing, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path

from .errors import MigrationError, StoreUnavailable

_MAX_BUSY_TIMEOUT_MS = 2_147_483_647
_MIGRATION_FILES = ("001_initial.sql", "002_baseline_tier.sql")
_SUPPORTED_SCHEMA_VERSION = len(_MIGRATION_FILES)
_CATALOG_QUERY = """
    SELECT type, name, tbl_name, sql
    FROM sqlite_master
    WHERE type IN ('table', 'index', 'view', 'trigger')
      AND name NOT GLOB 'sqlite_*'
      AND sql IS NOT NULL
    ORDER BY type, name, tbl_name, sql
"""
_Catalog = tuple[tuple[object, ...], ...]


@dataclass(frozen=True, slots=True)
class ConnectionFactory:
    path: Path
    busy_timeout_ms: int = 5_000

    def __post_init__(self) -> None:
        if (
            type(self.busy_timeout_ms) is not int
            or not 0 < self.busy_timeout_ms <= _MAX_BUSY_TIMEOUT_MS
        ):
            raise ValueError("invalid busy_timeout_ms")

    def connect(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(
                self.path,
                isolation_level=None,
                timeout=self.busy_timeout_ms / 1000,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA recursive_triggers=ON")
            recursive_triggers = connection.execute(
                "PRAGMA recursive_triggers",
            ).fetchone()
            if (
                recursive_triggers is None
                or len(recursive_triggers) != 1
                or type(recursive_triggers[0]) is not int
                or recursive_triggers[0] != 1
            ):
                raise sqlite3.OperationalError(
                    "recursive triggers unavailable",
                )
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            return connection
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                with suppress(OSError, sqlite3.Error):
                    connection.close()
            raise StoreUnavailable(str(self.path)) from exc


def _read_version(connection: sqlite3.Connection, path: Path) -> int:
    query = "SELECT version FROM schema_migrations ORDER BY version"
    rows = connection.execute(query).fetchall()
    versions = [row[0] for row in rows]
    if not versions:
        raise MigrationError(str(path))
    # fmt: off
    if any(
        type(version) is not int
        or not 1 <= version <= _SUPPORTED_SCHEMA_VERSION
        for version in versions
    ):
        # fmt: on
        raise MigrationError(str(path))
    current = versions[-1]
    if versions != list(range(1, current + 1)):
        raise MigrationError(str(path))
    return current


def _read_migration(version: int) -> str:
    filename = _MIGRATION_FILES[version - 1]
    return (
        resources.files("devpi_guardian.verdicts.sql")
        .joinpath(filename)
        .read_text(encoding="utf-8")
    )


def _migration_sql_through(version: int) -> str:
    # fmt: off
    return "\n".join(
        _read_migration(number) for number in range(1, version + 1)
    )
    # fmt: on


def _catalog_fingerprint(connection: sqlite3.Connection) -> _Catalog:
    return tuple(tuple(row) for row in connection.execute(_CATALOG_QUERY))


def _expected_catalog(sql: str) -> _Catalog:
    with closing(sqlite3.connect(":memory:")) as reference:
        reference.executescript(sql)
        return _catalog_fingerprint(reference)


def _validate_catalog(
    connection: sqlite3.Connection,
    expected: _Catalog,
    path: Path,
) -> None:
    if _catalog_fingerprint(connection) != expected:
        raise MigrationError(str(path))


def migrate(factory: ConnectionFactory) -> None:
    connection = factory.connect()
    try:
        journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
        if journal_mode is None or journal_mode[0] != "wal":
            raise MigrationError(str(factory.path))
        has_migrations = connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'schema_migrations'
            """
        ).fetchone()
        if has_migrations:
            current = _read_version(connection, factory.path)
            _validate_catalog(
                connection,
                _expected_catalog(_migration_sql_through(current)),
                factory.path,
            )
        else:
            current = 0

        for version in range(current + 1, _SUPPORTED_SCHEMA_VERSION + 1):
            sql = _read_migration(version)
            connection.executescript("BEGIN IMMEDIATE;\n" + sql)
            # fmt: off
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) "
                "VALUES (?, ?)",
                (version, datetime.now(UTC).isoformat()),
            )
            # fmt: on
            _validate_catalog(
                connection,
                _expected_catalog(_migration_sql_through(version)),
                factory.path,
            )
            connection.commit()
    except MigrationError:
        if connection.in_transaction:
            connection.rollback()
        raise
    except (ImportError, OSError, UnicodeError, sqlite3.Error) as exc:
        if connection.in_transaction:
            connection.rollback()
        raise MigrationError(str(factory.path)) from exc
    finally:
        connection.close()
