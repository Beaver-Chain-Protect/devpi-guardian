"""Durable request-to-worker handoff for newly observed Simple links."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
from collections.abc import Callable, Iterable
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from devpi_guardian.verdicts.models import require_utc, validate_sha256

_DISCOVERY_SINK_XOM_ATTRIBUTE = "_devpi_guardian_discovery_sink"
_ACTIVE_STATES = ("PENDING", "PROCESSING")
_ALL_STATES = frozenset((*_ACTIVE_STATES, "COMPLETED", "FAILED"))
_REQUIRED_DISCOVERY_COLUMNS = frozenset(
    {
        "job_id",
        "candidate_json",
        "state",
        "attempt_count",
        "available_at",
        "lease_owner",
        "lease_expires_at",
        "lease_token",
        "last_error",
        "created_at",
        "updated_at",
    }
)
_DISCOVERY_COLUMN_TYPES = {
    "job_id": ("TEXT", 0, 1),
    "candidate_json": ("TEXT", 1, 0),
    "state": ("TEXT", 1, 0),
    "attempt_count": ("INTEGER", 1, 0),
    "available_at": ("TEXT", 1, 0),
    "lease_owner": ("TEXT", 0, 0),
    "lease_expires_at": ("TEXT", 0, 0),
    "lease_token": ("TEXT", 0, 0),
    "last_error": ("TEXT", 0, 0),
    "created_at": ("TEXT", 1, 0),
    "updated_at": ("TEXT", 1, 0),
}
_MAX_CLAIM_CORRUPT_ROWS = 32
_CLAIM_BATCH_SIZE = 64
_SCRUB_BATCH_SIZE = 32


def _validate_claim(claim: DiscoveryClaim) -> None:
    if type(claim) is not DiscoveryClaim:
        raise ValueError("claim must be a DiscoveryClaim")
    if not isinstance(claim.worker_id, str) or not claim.worker_id.strip():
        raise ValueError("claim worker_id must be a nonblank string")
    if "\x00" in claim.worker_id:
        raise ValueError("claim worker_id must be safe")
    if type(claim.job_id) is not str or re.fullmatch(r"[0-9a-f]{64}", claim.job_id) is None:
        raise ValueError("claim job_id must be canonical")
    if type(claim.attempt_count) is not int or claim.attempt_count < 1:
        raise ValueError("claim attempt_count must be positive")
    if _job_id(claim.candidate) != claim.job_id:
        raise ValueError("claim candidate does not match job_id")
    expiry = require_utc(claim.lease_expires_at, "lease_expires_at")
    if expiry.isoformat() != claim.lease_expires_at.isoformat():
        raise ValueError("claim lease_expires_at must be canonical")
    token = claim.lease_token
    if (
        type(token) is not str
        or len(token) != 64
        or any(character not in "0123456789abcdef" for character in token)
    ):
        raise ValueError("claim lease_token must be a canonical token")


class DiscoveryUnavailable(RuntimeError):
    """Discovery metadata could not be durably registered or consumed."""


class DiscoveryQueueFull(DiscoveryUnavailable):
    """The configured discovery queue capacity has been reached."""


@dataclass(frozen=True, slots=True)
class DiscoveryCandidate:
    """Untrusted Simple-link metadata captured before downloading bytes.

    ``stage`` is the Guardian stage that observed the link.  The source stage
    used by F4 is derived from the validated ``link_href`` by the consumer.
    """

    stage: str
    project: str
    filename: str
    sha256: str
    link_href: str

    def __post_init__(self) -> None:
        for field_name in ("stage", "project", "filename", "link_href"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip() or "\x00" in value:
                raise ValueError(f"{field_name} must be a nonblank safe string")
            object.__setattr__(self, field_name, str(value))
        validate_sha256(self.sha256)


@dataclass(frozen=True, slots=True)
class DiscoveryClaim:
    job_id: str
    candidate: DiscoveryCandidate
    worker_id: str
    attempt_count: int
    lease_expires_at: datetime
    lease_token: str


class DiscoverySink(Protocol):
    def discover(self, candidate: DiscoveryCandidate) -> None: ...

    def discover_many(self, candidates: Iterable[DiscoveryCandidate]) -> None: ...


def _candidate_payload(candidate: DiscoveryCandidate) -> str:
    return json.dumps(
        asdict(candidate),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _job_id(candidate: DiscoveryCandidate) -> str:
    return hashlib.sha256(_candidate_payload(candidate).encode("utf-8")).hexdigest()


def _validate_catalog(connection: sqlite3.Connection) -> None:
    table = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'discovery_jobs'"
    ).fetchone()
    rows = connection.execute("PRAGMA table_info(discovery_jobs)").fetchall()
    actual = {row[1]: (row[2].upper(), row[3], row[5]) for row in rows}
    if actual != _DISCOVERY_COLUMN_TYPES:
        raise DiscoveryUnavailable("incompatible discovery schema: column contract mismatch")
    defaults = {row[1]: row[4] for row in rows}
    if defaults["attempt_count"] != "0":
        raise DiscoveryUnavailable("incompatible discovery schema: attempt_count default")
    sql = "" if table is None or table[0] is None else " ".join(table[0].upper().split())
    required_fragments = (
        "PRIMARY KEY",
        "CANDIDATE_JSON TEXT NOT NULL",
        "STATE TEXT NOT NULL CHECK",
        "ATTEMPT_COUNT INTEGER NOT NULL DEFAULT 0 CHECK",
        "CHECK(",
        "LEASE_TOKEN IS NOT NULL",
        "LEASE_TOKEN IS NULL",
    )
    if any(fragment not in sql for fragment in required_fragments):
        raise DiscoveryUnavailable("incompatible discovery schema: constraint contract mismatch")
    indexes = connection.execute("PRAGMA index_list(discovery_jobs)").fetchall()
    names = {row[1] for row in indexes}
    if "discovery_jobs_ready_idx" not in names:
        raise DiscoveryUnavailable("incompatible discovery schema: ready index missing")
    ready = connection.execute("PRAGMA index_info(discovery_jobs_ready_idx)").fetchall()
    if [row[2] for row in sorted(ready, key=lambda row: row[0])] != [
        "state",
        "available_at",
        "created_at",
        "job_id",
    ]:
        raise DiscoveryUnavailable("incompatible discovery schema: ready index mismatch")
    lease_index = next(
        (row for row in indexes if row[1] == "discovery_jobs_processing_lease_idx"), None
    )
    if lease_index is None or lease_index[2] != 1:
        raise DiscoveryUnavailable("incompatible discovery schema: lease index missing")
    lease_sql = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'index' "
        "AND name = 'discovery_jobs_processing_lease_idx'"
    ).fetchone()[0]
    lease_columns = connection.execute(
        "PRAGMA index_info(discovery_jobs_processing_lease_idx)"
    ).fetchall()
    if [row[2] for row in lease_columns] != [
        "lease_token"
    ] or "WHERE LEASE_TOKEN IS NOT NULL" not in lease_sql.upper():
        raise DiscoveryUnavailable("incompatible discovery schema: lease index mismatch")
    integrity_columns = connection.execute(
        "PRAGMA index_info(discovery_jobs_integrity_idx)"
    ).fetchall()
    if [row[2] for row in integrity_columns] != ["state", "job_id"]:
        raise DiscoveryUnavailable("incompatible discovery schema: integrity index mismatch")
    probe_candidate = DiscoveryCandidate(
        stage="schema-probe",
        project="probe",
        filename="probe-1.0.tar.gz",
        sha256="a" * 64,
        link_href="https://example.invalid/probe-1.0.tar.gz",
    )
    probe_payload = _candidate_payload(probe_candidate)
    probe_job_id = _job_id(probe_candidate)
    probe_timestamp = "2026-01-01T00:00:00+00:00"
    probe_values = (
        probe_job_id,
        probe_payload,
        "PENDING",
        0,
        probe_timestamp,
        None,
        None,
        None,
        None,
        probe_timestamp,
        probe_timestamp,
    )
    probe_sql = """
        INSERT INTO discovery_jobs(
            job_id, candidate_json, state, attempt_count, available_at,
            lease_owner, lease_expires_at, lease_token, last_error,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    connection.execute("SAVEPOINT discovery_schema_probe")
    try:
        probes = (
            ("invalid state", (*probe_values[:2], "BROKEN", *probe_values[3:])),
            ("negative attempt", (*probe_values[:3], -1, *probe_values[4:])),
            ("pending lease", (*probe_values[:5], "worker", None, "token", *probe_values[8:])),
            (
                "processing lease",
                (
                    *probe_values[:2],
                    "PROCESSING",
                    0,
                    probe_timestamp,
                    "worker",
                    None,
                    None,
                    None,
                    probe_timestamp,
                    probe_timestamp,
                ),
            ),
        )
        for label, values in probes:
            try:
                connection.execute(probe_sql, values)
            except sqlite3.IntegrityError:
                continue
            raise DiscoveryUnavailable(f"incompatible discovery schema: {label} constraint missing")
        valid_processing = (
            *probe_values[:2],
            "PROCESSING",
            0,
            probe_timestamp,
            "worker",
            probe_timestamp,
            "token",
            None,
            probe_timestamp,
            probe_timestamp,
        )
        connection.execute(probe_sql, valid_processing)
        duplicate_processing = (*valid_processing[:7], "token", *valid_processing[8:])
        try:
            connection.execute(probe_sql, duplicate_processing)
        except sqlite3.IntegrityError:
            pass
        else:
            raise DiscoveryUnavailable(
                "incompatible discovery schema: lease token uniqueness missing"
            )
    finally:
        connection.execute("ROLLBACK TO discovery_schema_probe")
        connection.execute("RELEASE discovery_schema_probe")


def _canonical_timestamp(value: object, field_name: str) -> datetime:
    if type(value) is not str:
        raise ValueError(f"invalid {field_name}")
    parsed = require_utc(datetime.fromisoformat(value), field_name)
    if parsed.isoformat() != value:
        raise ValueError(f"invalid canonical {field_name}")
    return parsed


def _validate_pending_row(row: sqlite3.Row) -> DiscoveryCandidate:
    job_id = row["job_id"]
    if type(job_id) is not str or re.fullmatch(r"[0-9a-f]{64}", job_id) is None:
        raise ValueError("invalid discovery job_id")
    candidate_json = row["candidate_json"]
    if type(candidate_json) is not str:
        raise ValueError("invalid candidate_json")
    data = json.loads(candidate_json)
    if type(data) is not dict or set(data) != {
        "stage",
        "project",
        "filename",
        "sha256",
        "link_href",
    }:
        raise ValueError("invalid candidate fields")
    if any(type(value) is not str for value in data.values()):
        raise ValueError("invalid candidate scalar types")
    candidate = DiscoveryCandidate(**data)
    if _candidate_payload(candidate) != candidate_json or _job_id(candidate) != job_id:
        raise ValueError("candidate identity does not match job_id")
    if row["state"] != "PENDING":
        raise ValueError("invalid pending state")
    if type(row["attempt_count"]) is not int or row["attempt_count"] < 0:
        raise ValueError("invalid attempt_count")
    _canonical_timestamp(row["available_at"], "available_at")
    _canonical_timestamp(row["created_at"], "created_at")
    _canonical_timestamp(row["updated_at"], "updated_at")
    if (
        row["lease_owner"] is not None
        or row["lease_expires_at"] is not None
        or row["lease_token"] is not None
    ):
        raise ValueError("invalid pending lease state")
    last_error = row["last_error"]
    if last_error is not None and (type(last_error) is not str or len(last_error) > 4096):
        raise ValueError("invalid last_error")
    return candidate


def _validate_processing_row(row: sqlite3.Row) -> datetime:
    job_id = row["job_id"]
    if type(job_id) is not str or re.fullmatch(r"[0-9a-f]{64}", job_id) is None:
        raise ValueError("invalid discovery job_id")
    candidate_json = row["candidate_json"]
    if type(candidate_json) is not str:
        raise ValueError("invalid candidate_json")
    data = json.loads(candidate_json)
    if (
        type(data) is not dict
        or set(data)
        != {
            "stage",
            "project",
            "filename",
            "sha256",
            "link_href",
        }
        or any(type(value) is not str for value in data.values())
    ):
        raise ValueError("invalid candidate fields")
    candidate = DiscoveryCandidate(**data)
    if _candidate_payload(candidate) != candidate_json or _job_id(candidate) != job_id:
        raise ValueError("candidate identity does not match job_id")
    if row["state"] != "PROCESSING":
        raise ValueError("invalid processing state")
    if type(row["attempt_count"]) is not int or row["attempt_count"] < 1:
        raise ValueError("invalid attempt_count")
    _canonical_timestamp(row["available_at"], "available_at")
    _canonical_timestamp(row["created_at"], "created_at")
    _canonical_timestamp(row["updated_at"], "updated_at")
    expiry = _canonical_timestamp(row["lease_expires_at"], "lease_expires_at")
    owner = row["lease_owner"]
    if type(owner) is not str or not owner.strip() or "\x00" in owner:
        raise ValueError("invalid lease_owner")
    token = row["lease_token"]
    if (
        type(token) is not str
        or len(token) != 64
        or any(character not in "0123456789abcdef" for character in token)
    ):
        raise ValueError("invalid lease_token")
    last_error = row["last_error"]
    if last_error is not None and (type(last_error) is not str or len(last_error) > 4096):
        raise ValueError("invalid last_error")
    return expiry


class FileDiscoverySink:
    """SQLite-backed discovery queue kept under the supplied directory.

    The historical class name remains stable for the F1/F2 integration point.
    SQLite replaces the original loose JSON files so producer deduplication,
    worker leases, retries, and crash recovery share one atomic state machine.
    """

    def __init__(
        self,
        root: Path,
        *,
        max_active_jobs: int = 10_000,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if type(max_active_jobs) is not int or max_active_jobs <= 0:
            raise ValueError("max_active_jobs must be a positive integer")
        self.root = Path(root)
        self.path = self.root / "discovery.db"
        self._max_active_jobs = max_active_jobs
        self._now = now if now is not None else lambda: datetime.now(UTC)
        self._scrub_cursor: tuple[str | None, int] | None = None
        self._initialize()

    def _initialize(self) -> None:
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            with closing(self._connect()) as connection:
                existing = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'discovery_jobs'"
                ).fetchone()
                if existing is not None:
                    columns = {
                        row[1] for row in connection.execute("PRAGMA table_info(discovery_jobs)")
                    }
                    missing = sorted(_REQUIRED_DISCOVERY_COLUMNS - columns)
                    if missing:
                        raise DiscoveryUnavailable(
                            "incompatible discovery schema; missing columns: " + ", ".join(missing)
                        )
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS discovery_jobs (
                        job_id TEXT PRIMARY KEY,
                        candidate_json TEXT NOT NULL,
                        state TEXT NOT NULL CHECK(
                            state IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')
                        ),
                        attempt_count INTEGER NOT NULL DEFAULT 0
                            CHECK(attempt_count >= 0),
                        available_at TEXT NOT NULL,
                        lease_owner TEXT,
                        lease_expires_at TEXT,
                        lease_token TEXT,
                        last_error TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        CHECK(
                            (state = 'PROCESSING' AND lease_owner IS NOT NULL
                             AND lease_expires_at IS NOT NULL AND lease_token IS NOT NULL)
                            OR
                            (state != 'PROCESSING' AND lease_owner IS NULL
                             AND lease_expires_at IS NULL AND lease_token IS NULL)
                        )
                    );
                    CREATE INDEX IF NOT EXISTS discovery_jobs_ready_idx
                    ON discovery_jobs(state, available_at, created_at, job_id);
                    CREATE UNIQUE INDEX IF NOT EXISTS discovery_jobs_processing_lease_idx
                    ON discovery_jobs(lease_token) WHERE lease_token IS NOT NULL;
                    CREATE INDEX IF NOT EXISTS discovery_jobs_integrity_idx
                    ON discovery_jobs(state, job_id);
                    """
                )
                columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(discovery_jobs)")
                }
                missing = sorted(_REQUIRED_DISCOVERY_COLUMNS - columns)
                if missing:
                    raise DiscoveryUnavailable(
                        "incompatible discovery schema; missing columns: " + ", ".join(missing)
                    )
                _validate_catalog(connection)
        except (OSError, sqlite3.Error) as exc:
            raise DiscoveryUnavailable(str(self.path)) from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @contextmanager
    def _write(self):
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    yield connection
                except BaseException:
                    connection.rollback()
                    raise
                else:
                    connection.commit()
        except DiscoveryUnavailable:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise DiscoveryUnavailable(str(self.path)) from exc

    def discover(self, candidate: DiscoveryCandidate) -> None:
        self.discover_many((candidate,))

    def discover_many(self, candidates: Iterable[DiscoveryCandidate]) -> None:
        items = tuple(candidates)
        if any(type(item) is not DiscoveryCandidate for item in items):
            raise ValueError("candidates must contain only DiscoveryCandidate values")
        if not items:
            return
        now = require_utc(self._now(), "now").isoformat()
        with self._write() as connection:
            active = connection.execute(
                "SELECT COUNT(*) FROM discovery_jobs WHERE state IN ('PENDING', 'PROCESSING')"
            ).fetchone()[0]
            for item in items:
                identifier = _job_id(item)
                exists = connection.execute(
                    "SELECT 1 FROM discovery_jobs WHERE job_id = ?",
                    (identifier,),
                ).fetchone()
                if exists is not None:
                    continue
                if active >= self._max_active_jobs:
                    raise DiscoveryQueueFull("discovery queue capacity reached")
                connection.execute(
                    """
                    INSERT INTO discovery_jobs(
                        job_id, candidate_json, state, available_at, created_at, updated_at
                    ) VALUES (?, ?, 'PENDING', ?, ?, ?)
                    """,
                    (identifier, _candidate_payload(item), now, now, now),
                )
                active += 1

    def _scrub_pending_rows(self, connection: sqlite3.Connection, now: str) -> None:
        cursor = self._scrub_cursor
        if cursor is None:
            rows = connection.execute(
                """
                SELECT rowid AS _rowid, * FROM discovery_jobs
                WHERE state = 'PENDING'
                ORDER BY job_id, rowid
                LIMIT ?
                """,
                (_SCRUB_BATCH_SIZE,),
            ).fetchall()
        else:
            last_job_id, last_rowid = cursor
            rows = connection.execute(
                """
                SELECT rowid AS _rowid, * FROM discovery_jobs
                WHERE state = 'PENDING'
                  AND (
                      job_id > ?
                      OR (job_id = ? AND rowid > ?)
                      OR (job_id IS NULL AND ? IS NULL AND rowid > ?)
                  )
                ORDER BY job_id, rowid
                LIMIT ?
                """,
                (last_job_id, last_job_id, last_rowid, last_job_id, last_rowid, _SCRUB_BATCH_SIZE),
            ).fetchall()
        for row in rows:
            try:
                _validate_pending_row(row)
            except (TypeError, ValueError, KeyError, json.JSONDecodeError) as error:
                diagnostic = f"discovery row invalid: {type(error).__name__}: {error}"[:4096]
                connection.execute(
                    """
                    UPDATE discovery_jobs
                    SET state = 'FAILED', lease_owner = NULL,
                        lease_expires_at = NULL, lease_token = NULL,
                        last_error = ?, updated_at = ?
                    WHERE rowid = ? AND state = 'PENDING'
                    """,
                    (diagnostic, now, row["_rowid"]),
                )
        if len(rows) < _SCRUB_BATCH_SIZE:
            self._scrub_cursor = None
        else:
            self._scrub_cursor = (rows[-1]["job_id"], rows[-1]["_rowid"])

    def recover_expired_claims(self) -> int:
        with self._write() as connection:
            now_value = require_utc(self._now(), "now")
            now = now_value.isoformat()
            rows = connection.execute(
                """
                SELECT rowid AS _rowid, * FROM discovery_jobs
                WHERE state = 'PROCESSING'
                ORDER BY lease_expires_at, created_at, job_id
                """
            ).fetchall()
            changed = 0
            for row in rows:
                try:
                    expires_at = _validate_processing_row(row)
                except (TypeError, ValueError, KeyError, json.JSONDecodeError) as error:
                    diagnostic = f"processing row invalid: {type(error).__name__}: {error}"[:4096]
                    connection.execute(
                        """
                        UPDATE discovery_jobs
                        SET state = 'FAILED', lease_owner = NULL,
                            lease_expires_at = NULL, lease_token = NULL,
                            last_error = ?, updated_at = ?
                        WHERE rowid = ? AND state = 'PROCESSING'
                        """,
                        (diagnostic, now, row["_rowid"]),
                    )
                    changed += 1
                    continue
                if expires_at > now_value:
                    continue
                connection.execute(
                    """
                    UPDATE discovery_jobs
                    SET state = 'PENDING', available_at = ?, lease_owner = NULL,
                        lease_expires_at = NULL, lease_token = NULL, updated_at = ?,
                        last_error = 'discovery worker lease expired'
                    WHERE rowid = ? AND state = 'PROCESSING'
                    """,
                    (now, now, row["_rowid"]),
                )
                changed += 1
            return changed

    def claim_next(self, worker_id: str, lease_until: datetime) -> DiscoveryClaim | None:
        if not isinstance(worker_id, str) or not worker_id.strip() or "\x00" in worker_id:
            raise ValueError("worker_id must be a nonblank safe string")
        worker_id = str(worker_id)
        with self._write() as connection:
            now_value = require_utc(self._now(), "now")
            lease_value = require_utc(lease_until, "lease_until")
            if lease_value <= now_value:
                raise ValueError("lease_until must be in the future")
            now = now_value.isoformat()
            lease = lease_value.isoformat()
            lease_token = secrets.token_hex(32)
            self._scrub_pending_rows(connection, now)
            rows = connection.execute(
                """
                SELECT rowid AS _rowid, *
                FROM discovery_jobs
                WHERE state = 'PENDING' AND available_at <= ?
                ORDER BY available_at, created_at, job_id
                LIMIT ?
                """,
                (now, _CLAIM_BATCH_SIZE),
            ).fetchall()
            corrupt_rows = 0
            claimed: DiscoveryClaim | None = None
            for row in rows:
                try:
                    candidate = _validate_pending_row(row)
                    if _canonical_timestamp(row["available_at"], "available_at") > now_value:
                        continue
                except (TypeError, ValueError, KeyError, json.JSONDecodeError) as error:
                    diagnostic = f"discovery row invalid: {type(error).__name__}: {error}"[:4096]
                    connection.execute(
                        """
                        UPDATE discovery_jobs
                        SET state = 'FAILED', lease_owner = NULL,
                            lease_expires_at = NULL, lease_token = NULL,
                            last_error = ?, updated_at = ?
                        WHERE rowid = ? AND state = 'PENDING'
                        """,
                        (diagnostic, now, row["_rowid"]),
                    )
                    corrupt_rows += 1
                    if corrupt_rows >= _MAX_CLAIM_CORRUPT_ROWS:
                        return claimed
                    continue
                if claimed is not None:
                    continue
                attempt_count = row["attempt_count"] + 1
                cursor = connection.execute(
                    """
                    UPDATE discovery_jobs
                    SET state = 'PROCESSING', attempt_count = ?, lease_owner = ?,
                        lease_expires_at = ?, lease_token = ?, last_error = NULL, updated_at = ?
                    WHERE job_id = ? AND state = 'PENDING'
                    """,
                    (attempt_count, worker_id, lease, lease_token, now, row["job_id"]),
                )
                if cursor.rowcount != 1:
                    raise DiscoveryUnavailable("discovery job could not be claimed")
                claimed = DiscoveryClaim(
                    job_id=row["job_id"],
                    candidate=candidate,
                    worker_id=worker_id,
                    attempt_count=attempt_count,
                    lease_expires_at=lease_value,
                    lease_token=lease_token,
                )
            return claimed

    def complete(self, claim: DiscoveryClaim) -> None:
        self._finish(claim, state="COMPLETED", error=None)

    def fail(self, claim: DiscoveryClaim, error: str) -> None:
        self._finish(claim, state="FAILED", error=error)

    def _finish(self, claim: DiscoveryClaim, *, state: str, error: str | None) -> None:
        if state not in ("COMPLETED", "FAILED"):
            raise ValueError("invalid terminal discovery state")
        with self._write() as connection:
            now_value = require_utc(self._now(), "now")
            now = now_value.isoformat()
            _validate_claim(claim)
            if now_value >= claim.lease_expires_at:
                raise DiscoveryUnavailable("discovery claim has expired")
            cursor = connection.execute(
                """
                UPDATE discovery_jobs
                SET state = ?, lease_owner = NULL, lease_expires_at = NULL,
                    lease_token = NULL,
                    last_error = ?, updated_at = ?
                WHERE job_id = ? AND state = 'PROCESSING' AND lease_owner = ?
                  AND lease_token = ? AND lease_expires_at = ?
                  AND lease_expires_at > ?
                """,
                (
                    state,
                    error,
                    now,
                    claim.job_id,
                    claim.worker_id,
                    claim.lease_token,
                    claim.lease_expires_at.isoformat(),
                    now,
                ),
            )
            if cursor.rowcount != 1:
                raise DiscoveryUnavailable("discovery claim is no longer owned")

    def retry(
        self,
        claim: DiscoveryClaim,
        error: str,
        *,
        delay: timedelta = timedelta(0),
        max_attempts: int = 5,
    ) -> None:
        if delay < timedelta(0):
            raise ValueError("retry delay must not be negative")
        if type(max_attempts) is not int or max_attempts <= 0:
            raise ValueError("max_attempts must be a positive integer")
        with self._write() as connection:
            now_value = require_utc(self._now(), "now")
            _validate_claim(claim)
            if now_value >= claim.lease_expires_at:
                raise DiscoveryUnavailable("discovery claim has expired")
            terminal = claim.attempt_count >= max_attempts
            state = "FAILED" if terminal else "PENDING"
            available_at = (now_value + delay).isoformat()
            cursor = connection.execute(
                """
                UPDATE discovery_jobs
                SET state = ?, available_at = ?, lease_owner = NULL,
                    lease_expires_at = NULL, lease_token = NULL,
                    last_error = ?, updated_at = ?
                WHERE job_id = ? AND state = 'PROCESSING' AND lease_owner = ?
                  AND lease_token = ? AND lease_expires_at = ?
                  AND lease_expires_at > ?
                """,
                (
                    state,
                    available_at,
                    error,
                    now_value.isoformat(),
                    claim.job_id,
                    claim.worker_id,
                    claim.lease_token,
                    claim.lease_expires_at.isoformat(),
                    now_value.isoformat(),
                ),
            )
            if cursor.rowcount != 1:
                raise DiscoveryUnavailable("discovery claim is no longer owned")

    def count(self, state: str) -> int:
        if state not in _ALL_STATES:
            raise ValueError("invalid discovery state")
        try:
            with closing(self._connect()) as connection:
                return connection.execute(
                    "SELECT COUNT(*) FROM discovery_jobs WHERE state = ?",
                    (state,),
                ).fetchone()[0]
        except (OSError, sqlite3.Error) as exc:
            raise DiscoveryUnavailable(str(self.path)) from exc


def set_discovery_sink(xom, sink: DiscoverySink) -> None:
    if not callable(getattr(sink, "discover", None)):
        raise TypeError("sink must provide discover(candidate)")
    if not callable(getattr(sink, "discover_many", None)):
        raise TypeError("sink must provide discover_many(candidates)")
    setattr(xom, _DISCOVERY_SINK_XOM_ATTRIBUTE, sink)


def get_discovery_sink(xom) -> DiscoverySink:
    try:
        return getattr(xom, _DISCOVERY_SINK_XOM_ATTRIBUTE)
    except AttributeError as exc:
        raise DiscoveryUnavailable("discovery sink is not initialized") from exc
