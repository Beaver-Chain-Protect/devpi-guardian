from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from urllib.parse import SplitResult, urlsplit, urlunsplit

from devpi_common.metadata import normalize_name

from .db import ConnectionFactory
from .errors import StoreUnavailable, TransitionConflict
from .interfaces import AuditWriter
from .models import (
    ArtifactInput,
    AuditEventInput,
    ClaimedArtifact,
    Decision,
    ReleaseInput,
    require_utc,
    validate_sha256,
)

_MAX_SQLITE_INTEGER = 2**63 - 1


def _require_datetime(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise ValueError(f"{field_name} must be a datetime")
    return value


def _require_nonblank_string(value: object, field_name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{field_name} must be a nonblank string")
    return value


def _iso(value: datetime, field_name: str) -> str:
    timestamp = _require_datetime(value, field_name)
    return require_utc(timestamp, field_name).isoformat()


def _sanitize_origin_url(value: str) -> str:
    origin_url = _require_nonblank_string(value, "origin_url")
    try:
        parsed = urlsplit(origin_url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError("origin_url must be a valid absolute URL") from None
    if (
        not parsed.scheme
        or not parsed.netloc
        or hostname is None
        or not hostname
        or any(character.isspace() for character in hostname)
    ):
        raise ValueError("origin_url must be a valid absolute URL")

    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host if port is None else f"{host}:{port}"
    sanitized = SplitResult(parsed.scheme, netloc, parsed.path, "", "")
    return urlunsplit(sanitized)


class SQLiteArtifactStore:
    def __init__(
        self,
        factory: ConnectionFactory,
        audit_writer: AuditWriter,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.connection_factory = factory
        self._audit_writer = audit_writer
        self._now = now if now is not None else lambda: datetime.now(UTC)

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        primary: BaseException | None = None
        committed = False
        try:
            connection = self.connection_factory.connect()
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
            committed = True
        except BaseException as exc:
            primary = exc
            if connection is not None:
                try:
                    if connection.in_transaction:
                        connection.rollback()
                except BaseException:
                    pass
        finally:
            if connection is not None:
                try:
                    connection.close()
                except BaseException as exc:
                    # A completed commit cannot be reversed by close failing.
                    if primary is None and not committed:
                        primary = exc

        if primary is not None:
            if isinstance(primary, sqlite3.Error):
                path = str(self.connection_factory.path)
                raise StoreUnavailable(path) from primary
            raise primary.with_traceback(primary.__traceback__)

    def _audit(
        self,
        connection: sqlite3.Connection,
        *,
        actor: str,
        action: str,
        sha256: str,
        reason: str,
        occurred_at: datetime,
    ) -> None:
        self._audit_writer.append_in_transaction(
            connection,
            AuditEventInput(
                actor=actor,
                action=action,
                sha256=sha256,
                previous_decision=Decision.DENY,
                new_decision=Decision.DENY,
                reason=reason,
                policy_version=None,
                analyzer_version=None,
                occurred_at=occurred_at,
            ),
        )

    def discover_artifact(
        self,
        artifact: ArtifactInput,
        release: ReleaseInput,
    ) -> None:
        if type(artifact) is not ArtifactInput:
            raise ValueError("artifact must be an ArtifactInput")
        if type(release) is not ReleaseInput:
            raise ValueError("release must be a ReleaseInput")
        validate_sha256(artifact.sha256)
        validate_sha256(release.sha256)
        if artifact.sha256 != release.sha256:
            raise ValueError("artifact and release sha256 must match")
        if (
            type(artifact.size_bytes) is not int
            or not 0 <= artifact.size_bytes <= _MAX_SQLITE_INTEGER
        ):
            raise ValueError("size_bytes must be a SQLite integer")

        stage = _require_nonblank_string(release.stage, "stage")
        project_input = _require_nonblank_string(release.project, "project")
        version = _require_nonblank_string(release.version, "version")
        filename = _require_nonblank_string(release.filename, "filename")
        release_origin = release.origin_url
        origin_input = _require_nonblank_string(release_origin, "origin_url")

        project = normalize_name(project_input)
        origin_url = _sanitize_origin_url(origin_input)
        artifact_discovered_at = _iso(artifact.discovered_at, "discovered_at")
        release_discovered_at = _iso(release.discovered_at, "discovered_at")
        operation_at = require_utc(
            _require_datetime(self._now(), "now"),
            "now",
        )

        with self._write() as connection:
            artifact_cursor = connection.execute(
                """
                INSERT INTO artifacts(
                    sha256, size_bytes, state, discovered_at, updated_at
                ) VALUES (?, ?, 'DISCOVERED', ?, ?)
                ON CONFLICT(sha256) DO NOTHING
                """,
                (
                    artifact.sha256,
                    artifact.size_bytes,
                    artifact_discovered_at,
                    artifact_discovered_at,
                ),
            )
            stored = connection.execute(
                "SELECT size_bytes FROM artifacts WHERE sha256 = ?",
                (artifact.sha256,),
            ).fetchone()
            if artifact_cursor.rowcount == 0 and stored is None:
                raise TransitionConflict("artifact insert ignored without row")
            if stored is None or stored["size_bytes"] != artifact.size_bytes:
                raise TransitionConflict("artifact size conflict")

            mapping_cursor = connection.execute(
                """
                INSERT INTO release_mappings(
                    stage, project, version, filename, sha256, origin_url,
                    discovered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(stage, project, version, filename, sha256)
                DO NOTHING
                """,
                (
                    stage,
                    project,
                    version,
                    filename,
                    artifact.sha256,
                    origin_url,
                    release_discovered_at,
                ),
            )
            if mapping_cursor.rowcount == 0:
                stored_mapping = connection.execute(
                    """
                    SELECT origin_url
                    FROM release_mappings
                    WHERE stage = ? AND project = ? AND version = ?
                      AND filename = ? AND sha256 = ?
                    """,
                    (
                        stage,
                        project,
                        version,
                        filename,
                        artifact.sha256,
                    ),
                ).fetchone()
                if stored_mapping is None:
                    raise TransitionConflict("release mapping row missing")
                if stored_mapping["origin_url"] != origin_url:
                    raise TransitionConflict("release mapping conflict")
            if artifact_cursor.rowcount == 1 or mapping_cursor.rowcount == 1:
                self._audit(
                    connection,
                    actor="guardian-discovery",
                    action="artifact.discovered",
                    sha256=artifact.sha256,
                    reason="release mapping discovered",
                    occurred_at=operation_at,
                )

    def claim_next(
        self,
        worker_id: str,
        lease_until: datetime,
    ) -> ClaimedArtifact | None:
        if type(worker_id) is not str or not worker_id.strip():
            raise ValueError("worker_id must not be blank")
        lease_timestamp = _require_datetime(lease_until, "lease_until")
        lease_expires_at = require_utc(lease_timestamp, "lease_until")
        lease_text = lease_expires_at.isoformat()
        operation_at = require_utc(
            _require_datetime(self._now(), "now"),
            "now",
        )
        updated_at = operation_at.isoformat()

        with self._write() as connection:
            row = connection.execute(
                """
                SELECT sha256, size_bytes
                FROM artifacts
                WHERE state = 'DISCOVERED'
                ORDER BY discovered_at, sha256
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                return None
            cursor = connection.execute(
                """
                UPDATE artifacts
                SET state = 'SCANNING', lease_owner = ?, lease_expires_at = ?,
                    updated_at = ?, last_error = NULL
                WHERE sha256 = ? AND state = 'DISCOVERED'
                """,
                (worker_id, lease_text, updated_at, row["sha256"]),
            )
            if cursor.rowcount != 1:
                raise TransitionConflict("artifact could not be claimed")
            self._audit(
                connection,
                actor=worker_id,
                action="artifact.claimed",
                sha256=row["sha256"],
                reason="analysis lease acquired",
                occurred_at=operation_at,
            )
            return ClaimedArtifact(
                sha256=row["sha256"],
                size_bytes=row["size_bytes"],
                worker_id=worker_id,
                lease_expires_at=lease_expires_at,
            )

    def recover_expired_claims(self, now: datetime) -> int:
        recovery_timestamp = _require_datetime(now, "now")
        recovered_at = require_utc(recovery_timestamp, "now")
        recovered_text = recovered_at.isoformat()
        recovered_count = 0

        with self._write() as connection:
            rows = connection.execute(
                """
                SELECT sha256, lease_owner, lease_expires_at
                FROM artifacts
                WHERE state = 'SCANNING' AND lease_expires_at <= ?
                ORDER BY lease_expires_at, sha256
                """,
                (recovered_text,),
            ).fetchall()
            for row in rows:
                cursor = connection.execute(
                    """
                    UPDATE artifacts
                    SET state = 'DISCOVERED', lease_owner = NULL,
                        lease_expires_at = NULL, updated_at = ?
                    WHERE sha256 = ? AND state = 'SCANNING'
                      AND lease_owner = ? AND lease_expires_at = ?
                    """,
                    (
                        recovered_text,
                        row["sha256"],
                        row["lease_owner"],
                        row["lease_expires_at"],
                    ),
                )
                if cursor.rowcount != 1:
                    continue
                recovered_count += 1
                self._audit(
                    connection,
                    actor=row["lease_owner"],
                    action="artifact.lease_expired",
                    sha256=row["sha256"],
                    reason="analysis lease expired",
                    occurred_at=recovered_at,
                )

        return recovered_count
