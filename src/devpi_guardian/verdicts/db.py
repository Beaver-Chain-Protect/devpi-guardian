from __future__ import annotations

import sqlite3
from contextlib import closing, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path

from .errors import MigrationError, StoreUnavailable

_MAX_BUSY_TIMEOUT_MS = 2_147_483_647
_SUPPORTED_SCHEMA_VERSION = 1
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
    query = "SELECT version FROM schema_migrations"
    rows = connection.execute(query).fetchall()
    versions = [row[0] for row in rows]
    if not versions:
        raise MigrationError(str(path))
    for version in versions:
        is_integer = type(version) is int
        is_supported = is_integer and 1 <= version <= _SUPPORTED_SCHEMA_VERSION
        if not is_supported:
            raise MigrationError(str(path))
    return max(versions)


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
            if current != _SUPPORTED_SCHEMA_VERSION:
                raise MigrationError(str(factory.path))
        sql = (
            resources.files("devpi_guardian.verdicts.sql")
            .joinpath("001_initial.sql")
            .read_text(encoding="utf-8")
        )
        expected_catalog = _expected_catalog(sql)
        if has_migrations:
            _validate_catalog(connection, expected_catalog, factory.path)
            return
        connection.executescript("BEGIN IMMEDIATE;\n" + sql)
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (_SUPPORTED_SCHEMA_VERSION, datetime.now(UTC).isoformat()),
        )
        _validate_catalog(connection, expected_catalog, factory.path)
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
