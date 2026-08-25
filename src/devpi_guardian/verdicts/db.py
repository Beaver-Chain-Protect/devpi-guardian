from __future__ import annotations

import os
import sqlite3
from contextlib import closing, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from threading import RLock

from .errors import MigrationError, StoreUnavailable

_MAX_BUSY_TIMEOUT_MS = 2_147_483_647
_MIGRATION_FILES = (
    "001_initial.sql",
    "002_baseline_tier.sql",
    "003_guardian_activation.sql",
    "004_artifact_cooldown.sql",
    "005_audit_events.sql",
    "006_baseline_overrides.sql",
)
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
# An open trusted connection pins the observed main inode.  A path rotation
# while it is live is rejected before SQLite can combine a new main file with
# the old connection's WAL generation.
_ACTIVE_CONNECTIONS: dict[str, dict[tuple[int, int], int]] = {}
_ACTIVE_CONNECTIONS_LOCK = RLock()


class _TrustedConnection(sqlite3.Connection):
    """Connection carrying identity captured atomically with its open."""

    _devpi_guardian_identity: tuple[object, ...] | None = None
    _devpi_guardian_registered = False

    def close(self) -> None:
        super().close()
        identity = self._devpi_guardian_identity
        if self._devpi_guardian_registered and identity is not None:
            _unregister_connection(identity)
            self._devpi_guardian_registered = False


def trusted_connection_identity(
    connection: sqlite3.Connection,
) -> tuple[object, ...] | None:
    """Return the factory-authenticated file identity, if available."""

    if type(connection) is not _TrustedConnection:
        return None
    identity = connection._devpi_guardian_identity
    if type(identity) is not tuple:
        return None
    return identity


def trusted_connection_generation_current(connection: sqlite3.Connection) -> bool:
    """Return whether a trusted file connection still names the live path."""

    identity = trusted_connection_identity(connection)
    if (
        identity is None
        or len(identity) != 4
        or identity[0] != "file"
        or type(identity[1]) is not str
        or type(identity[2]) is not int
        or type(identity[3]) is not int
    ):
        return False
    try:
        current = os.stat(identity[1])
    except (OSError, ValueError):
        return False
    return (current.st_dev, current.st_ino) == (identity[2], identity[3])


def _open_identity_sentinel(path: str) -> tuple[int, os.stat_result]:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except FileNotFoundError:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    before = os.fstat(descriptor)
    identity = (before.st_dev, before.st_ino)
    with _ACTIVE_CONNECTIONS_LOCK:
        active = _ACTIVE_CONNECTIONS.get(path, {})
        if active and identity not in active:
            os.close(descriptor)
            raise OSError("database main file changed while a connection was open")
    return descriptor, before


def _register_connection(connection: _TrustedConnection, identity: tuple[object, ...]) -> None:
    path = identity[1]
    inode = (identity[2], identity[3])
    with _ACTIVE_CONNECTIONS_LOCK:
        generations = _ACTIVE_CONNECTIONS.setdefault(path, {})
        generations[inode] = generations.get(inode, 0) + 1
    connection._devpi_guardian_registered = True


def _unregister_connection(identity: tuple[object, ...]) -> None:
    path = identity[1]
    inode = (identity[2], identity[3])
    with _ACTIVE_CONNECTIONS_LOCK:
        active = _ACTIVE_CONNECTIONS.get(path)
        if active is None:
            return
        count = active.get(inode)
        if count is None:
            return
        if count > 1:
            active[inode] = count - 1
        else:
            active.pop(inode)
        if not active:
            _ACTIVE_CONNECTIONS.pop(path, None)


def _captured_file_identity(
    path: str, descriptor: int, before: os.stat_result
) -> tuple[object, ...]:
    after = os.stat(path)
    if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
        raise OSError("database path changed while opening")
    return ("file", path, before.st_dev, before.st_ino)


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

    def connect(self, *, check_same_thread: bool = True) -> sqlite3.Connection:
        if type(check_same_thread) is not bool:
            raise ValueError("check_same_thread must be a bool")
        connection: sqlite3.Connection | None = None
        descriptor: int | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            requested_path = os.fspath(self.path)
            if requested_path == ":memory:":
                database_path = requested_path
                before = None
            else:
                database_path = os.path.realpath(os.path.abspath(requested_path))
                descriptor, before = _open_identity_sentinel(database_path)
            connection = sqlite3.connect(
                database_path,
                isolation_level=None,
                timeout=self.busy_timeout_ms / 1000,
                check_same_thread=check_same_thread,
                factory=_TrustedConnection,
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
            if (
                type(connection) is _TrustedConnection
                and descriptor is not None
                and before is not None
            ):
                identity = _captured_file_identity(
                    database_path,
                    descriptor,
                    before,
                )
                connection._devpi_guardian_identity = identity
                _register_connection(connection, identity)
            return connection
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                with suppress(OSError, sqlite3.Error):
                    connection.close()
            raise StoreUnavailable(str(self.path)) from exc
        finally:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)


def _version_out_of_range(version: int) -> bool:
    return version < 1 or version > _SUPPORTED_SCHEMA_VERSION


def _read_version(connection: sqlite3.Connection, path: Path) -> int:
    query = "SELECT version FROM schema_migrations ORDER BY version"
    rows = connection.execute(query).fetchall()
    versions = [row[0] for row in rows]
    if not versions:
        raise MigrationError(str(path))
    if any(type(version) is not int for version in versions) or any(
        _version_out_of_range(version) for version in versions
    ):
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
    migrations = (
        _read_migration(number)
        for number in range(
            1,
            version + 1,
        )
    )
    return "\n".join(migrations)


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
    primary: MigrationError | None = None
    cause: BaseException | None = None
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
            insert_migration = " ".join(
                (
                    "INSERT INTO schema_migrations(version, applied_at)",
                    "VALUES (?, ?)",
                )
            )
            connection.execute(
                insert_migration,
                (version, datetime.now(UTC).isoformat()),
            )
            _validate_catalog(
                connection,
                _expected_catalog(_migration_sql_through(version)),
                factory.path,
            )
            connection.commit()
    except MigrationError as exc:
        primary = exc
    except (ImportError, OSError, UnicodeError, sqlite3.Error) as exc:
        primary = MigrationError(str(factory.path))
        cause = exc
    finally:
        if primary is not None:
            with suppress(Exception):
                if connection.in_transaction:
                    connection.rollback()
        try:
            connection.close()
        except Exception as exc:
            if primary is None:
                primary = MigrationError(str(factory.path))
                cause = exc

    if primary is not None:
        if cause is not None:
            raise primary from cause
        raise primary
