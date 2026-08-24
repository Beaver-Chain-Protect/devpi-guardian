"""Durable request-to-worker handoff for newly observed Simple links."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from collections.abc import Callable, Iterable
from contextlib import contextmanager
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


def _validate_claim(claim: DiscoveryClaim) -> None:
    if type(claim) is not DiscoveryClaim:
        raise ValueError("claim must be a DiscoveryClaim")
    if not isinstance(claim.worker_id, str) or not claim.worker_id.strip():
        raise ValueError("claim worker_id must be a nonblank string")
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
        self._initialize()

    def _initialize(self) -> None:
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            with self._connect() as connection:
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
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
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

    def recover_expired_claims(self) -> int:
        now = require_utc(self._now(), "now").isoformat()
        with self._write() as connection:
            cursor = connection.execute(
                """
                UPDATE discovery_jobs
                SET state = 'PENDING', available_at = ?, lease_owner = NULL,
                    lease_expires_at = NULL, lease_token = NULL, updated_at = ?,
                    last_error = 'discovery worker lease expired'
                WHERE state = 'PROCESSING' AND lease_expires_at <= ?
                """,
                (now, now, now),
            )
            return cursor.rowcount

    def claim_next(self, worker_id: str, lease_until: datetime) -> DiscoveryClaim | None:
        if not isinstance(worker_id, str) or not worker_id.strip() or "\x00" in worker_id:
            raise ValueError("worker_id must be a nonblank safe string")
        worker_id = str(worker_id)
        now_value = require_utc(self._now(), "now")
        lease_value = require_utc(lease_until, "lease_until")
        if lease_value <= now_value:
            raise ValueError("lease_until must be in the future")
        now = now_value.isoformat()
        lease = lease_value.isoformat()
        lease_token = secrets.token_hex(32)
        with self._write() as connection:
            row = connection.execute(
                """
                SELECT job_id, candidate_json, attempt_count
                FROM discovery_jobs
                WHERE state = 'PENDING' AND available_at <= ?
                ORDER BY available_at, created_at, job_id
                LIMIT 1
                """,
                (now,),
            ).fetchone()
            if row is None:
                return None
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
            data = json.loads(row["candidate_json"])
            return DiscoveryClaim(
                job_id=row["job_id"],
                candidate=DiscoveryCandidate(**data),
                worker_id=worker_id,
                attempt_count=attempt_count,
                lease_expires_at=lease_value,
                lease_token=lease_token,
            )

    def complete(self, claim: DiscoveryClaim) -> None:
        self._finish(claim, state="COMPLETED", error=None)

    def fail(self, claim: DiscoveryClaim, error: str) -> None:
        self._finish(claim, state="FAILED", error=error)

    def _finish(self, claim: DiscoveryClaim, *, state: str, error: str | None) -> None:
        if state not in ("COMPLETED", "FAILED"):
            raise ValueError("invalid terminal discovery state")
        now = require_utc(self._now(), "now").isoformat()
        _validate_claim(claim)
        with self._write() as connection:
            cursor = connection.execute(
                """
                UPDATE discovery_jobs
                SET state = ?, lease_owner = NULL, lease_expires_at = NULL,
                    lease_token = NULL,
                    last_error = ?, updated_at = ?
                WHERE job_id = ? AND state = 'PROCESSING' AND lease_owner = ?
                  AND lease_token = ?
                """,
                (state, error, now, claim.job_id, claim.worker_id, claim.lease_token),
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
        now_value = require_utc(self._now(), "now")
        _validate_claim(claim)
        terminal = claim.attempt_count >= max_attempts
        state = "FAILED" if terminal else "PENDING"
        available_at = (now_value + delay).isoformat()
        with self._write() as connection:
            cursor = connection.execute(
                """
                UPDATE discovery_jobs
                SET state = ?, available_at = ?, lease_owner = NULL,
                    lease_expires_at = NULL, lease_token = NULL,
                    last_error = ?, updated_at = ?
                WHERE job_id = ? AND state = 'PROCESSING' AND lease_owner = ?
                  AND lease_token = ?
                """,
                (
                    state,
                    available_at,
                    error,
                    now_value.isoformat(),
                    claim.job_id,
                    claim.worker_id,
                    claim.lease_token,
                ),
            )
            if cursor.rowcount != 1:
                raise DiscoveryUnavailable("discovery claim is no longer owned")

    def count(self, state: str) -> int:
        if state not in _ALL_STATES:
            raise ValueError("invalid discovery state")
        try:
            with self._connect() as connection:
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
