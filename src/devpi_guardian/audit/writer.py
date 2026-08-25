from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from devpi_guardian.verdicts.errors import StoreUnavailable
from devpi_guardian.verdicts.models import AuditEventInput, Decision, validate_sha256

EVENT_VERSION = 1
CANONICALIZATION_VERSION = 1
ZERO_HASH = "0" * 64
_SHA256_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_MAX_ACTOR = 4096
_MAX_ACTION = 256
_MAX_REASON = 4096
_MAX_VERSION = 4096
_MAX_CANONICAL_PAYLOAD_BYTES = 64 * 1024
_AUDIT_COLUMNS = """
    id, event_version, canonicalization_version, occurred_at,
    actor, action, sha256, previous_decision, new_decision,
    reason, policy_version, analyzer_version, previous_hash,
    event_hash
"""
_REQUIRED_SCHEMA_OBJECTS = frozenset(
    {
        ("index", "audit_events_sha256_occurred_at_idx"),
        ("index", "audit_events_action_occurred_at_idx"),
        ("index", "audit_events_event_hash_unique_idx"),
        ("trigger", "audit_events_history_insert_guard"),
        ("trigger", "audit_events_chain_insert_guard"),
        ("trigger", "audit_events_update_guard"),
        ("trigger", "audit_events_delete_guard"),
    }
)


@dataclass(frozen=True, slots=True)
class _VerifiedPrefix:
    connection: sqlite3.Connection
    schema: tuple[tuple[str, str, str], ...]
    schema_version: int
    data_version: int
    count: int
    head: str


def _text(value: object, field: str, maximum: int) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{field} must be a nonblank string")
    if any(
        ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        or 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    ):
        raise ValueError(f"{field} contains a control character")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field} is not valid UTF-8") from exc
    if len(encoded) > maximum:
        raise ValueError(f"{field} is too long")
    return value


def _optional_text(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _text(value, field, _MAX_VERSION)


def _utc_timestamp(value: object, field: str = "occurred_at") -> str:
    if type(value) is not datetime:
        raise ValueError(f"{field} must be a datetime")
    try:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{field} must be timezone-aware")
        return value.astimezone(UTC).isoformat()
    except (OverflowError, TypeError, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc) == f"{field} must be timezone-aware":
            raise
        raise ValueError(f"{field} must be timezone-aware") from exc


def _validated_event(event: object) -> dict[str, Any]:
    if type(event) is not AuditEventInput:
        raise ValueError("event must be an AuditEventInput")
    previous = event.previous_decision
    new = event.new_decision
    if type(previous) is not Decision or type(new) is not Decision:
        raise ValueError("decisions must be Decision values")
    return {
        "occurred_at": _utc_timestamp(event.occurred_at),
        "actor": _text(event.actor, "actor", _MAX_ACTOR),
        "action": _text(event.action, "action", _MAX_ACTION),
        "sha256": validate_sha256(event.sha256),
        "previous_decision": previous.value,
        "new_decision": new.value,
        "reason": _text(event.reason, "reason", _MAX_REASON),
        "policy_version": _optional_text(event.policy_version, "policy_version"),
        "analyzer_version": _optional_text(event.analyzer_version, "analyzer_version"),
    }


def _canonical_payload(
    event_id: int,
    previous_hash: str,
    values: dict[str, Any],
) -> bytes:
    payload = {
        "action": values["action"],
        "actor": values["actor"],
        "analyzer_version": values["analyzer_version"],
        "canonicalization_version": CANONICALIZATION_VERSION,
        "event_version": EVENT_VERSION,
        "id": event_id,
        "new_decision": values["new_decision"],
        "occurred_at": values["occurred_at"],
        "policy_version": values["policy_version"],
        "previous_decision": values["previous_decision"],
        "previous_hash": previous_hash,
        "reason": values["reason"],
        "sha256": values["sha256"],
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _event_hash(previous_hash: str, event_id: int, values: dict[str, Any]) -> str:
    payload = _canonical_payload(event_id, previous_hash, values)
    if len(payload) > _MAX_CANONICAL_PAYLOAD_BYTES:
        raise ValueError("canonical audit payload is too large")
    return hashlib.sha256(
        bytes.fromhex(previous_hash) + b"\0" + payload,
    ).hexdigest()


def _validate_persisted_row(row: sqlite3.Row | tuple[object, ...]) -> dict[str, Any]:
    """Validate one stored row and return its canonical semantic fields."""
    if len(row) != 14:
        raise ValueError("invalid audit column count")
    event_id, event_version, canonicalization_version = row[:3]
    if type(event_id) is not int or event_id <= 0:
        raise ValueError("invalid audit event id")
    if type(event_version) is not int or event_version != EVENT_VERSION:
        raise ValueError("invalid event version")
    if (
        type(canonicalization_version) is not int
        or canonicalization_version != CANONICALIZATION_VERSION
    ):
        raise ValueError("invalid canonicalization version")
    occurred_at, actor, action, sha256 = row[3:7]
    if type(occurred_at) is not str:
        raise ValueError("invalid occurred_at")
    try:
        parsed = datetime.fromisoformat(occurred_at)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("invalid occurred_at")
        if parsed.astimezone(UTC).isoformat() != occurred_at:
            raise ValueError("invalid occurred_at")
    except (TypeError, OverflowError, ValueError) as exc:
        if str(exc) == "invalid occurred_at":
            raise
        raise ValueError("invalid occurred_at") from exc
    actor = _text(actor, "actor", _MAX_ACTOR)
    action = _text(action, "action", _MAX_ACTION)
    sha256 = validate_sha256(sha256)
    previous_decision, new_decision = row[7:9]
    if previous_decision not in {decision.value for decision in Decision}:
        raise ValueError("invalid previous decision")
    if new_decision not in {decision.value for decision in Decision}:
        raise ValueError("invalid new decision")
    reason = _text(row[9], "reason", _MAX_REASON)
    policy_version = _optional_text(row[10], "policy_version")
    analyzer_version = _optional_text(row[11], "analyzer_version")
    previous_hash, event_hash = row[12:14]
    if type(previous_hash) is not str or _SHA256_RE.fullmatch(previous_hash) is None:
        raise ValueError("invalid previous hash")
    if type(event_hash) is not str or _SHA256_RE.fullmatch(event_hash) is None:
        raise ValueError("invalid event hash")
    return {
        "id": event_id,
        "occurred_at": occurred_at,
        "actor": actor,
        "action": action,
        "sha256": sha256,
        "previous_decision": previous_decision,
        "new_decision": new_decision,
        "reason": reason,
        "policy_version": policy_version,
        "analyzer_version": analyzer_version,
        "previous_hash": previous_hash,
        "event_hash": event_hash,
    }


def _store_unavailable(connection_or_path: object, exc: BaseException) -> StoreUnavailable:
    path = getattr(connection_or_path, "path", None)
    if path is None:
        path = "audit database"
    return StoreUnavailable(str(path))


def _schema_contract(
    connection: sqlite3.Connection,
) -> tuple[tuple[tuple[str, str, str], ...], int, int]:
    raw_columns = connection.execute("PRAGMA table_info(audit_events)").fetchall()
    if any(type(row[1]) is not str or type(row[2]) is not str for row in raw_columns):
        raise StoreUnavailable("audit database")
    columns = tuple((row[1], row[2].upper(), row[3], row[5]) for row in raw_columns)
    expected_columns = (
        ("id", "INTEGER", 0, 1),
        ("event_version", "INTEGER", 1, 0),
        ("canonicalization_version", "INTEGER", 1, 0),
        ("occurred_at", "TEXT", 1, 0),
        ("actor", "TEXT", 1, 0),
        ("action", "TEXT", 1, 0),
        ("sha256", "TEXT", 1, 0),
        ("previous_decision", "TEXT", 1, 0),
        ("new_decision", "TEXT", 1, 0),
        ("reason", "TEXT", 1, 0),
        ("policy_version", "TEXT", 0, 0),
        ("analyzer_version", "TEXT", 0, 0),
        ("previous_hash", "TEXT", 1, 0),
        ("event_hash", "TEXT", 1, 0),
    )
    if columns != expected_columns:
        raise StoreUnavailable("audit database")
    objects = tuple(
        (row[0], row[1], row[2])
        for row in connection.execute(
            """
            SELECT type, name, sql FROM sqlite_master
            WHERE type IN ('index', 'trigger') AND name NOT GLOB 'sqlite_*'
            ORDER BY type, name
            """
        ).fetchall()
    )
    present = {(kind, name) for kind, name, _sql in objects}
    if not present >= _REQUIRED_SCHEMA_OBJECTS:
        raise StoreUnavailable("audit database")
    if any(type(sql) is not str or not sql for _kind, _name, sql in objects):
        raise StoreUnavailable("audit database")
    expected_definitions = {
        "audit_events_action_occurred_at_idx": (
            "create index audit_events_action_occurred_at_idx on audit_events(action, occurred_at)"
        ),
        "audit_events_event_hash_unique_idx": (
            "create unique index audit_events_event_hash_unique_idx on audit_events(event_hash)"
        ),
        "audit_events_sha256_occurred_at_idx": (
            "create index audit_events_sha256_occurred_at_idx on audit_events(sha256, occurred_at)"
        ),
        "audit_events_chain_insert_guard": (
            "create trigger audit_events_chain_insert_guard before insert on audit_events "
            "when new.id is not coalesce( (select max(id) + 1 from audit_events), 1 ) "
            "or new.previous_hash is not coalesce( (select event_hash from audit_events "
            "order by id desc limit 1), lower(hex(zeroblob(32))) ) begin select raise(abort, "
            "'invalid audit chain head'); end"
        ),
        "audit_events_delete_guard": (
            "create trigger audit_events_delete_guard before delete on audit_events "
            "begin select raise(abort, 'audit events are append-only'); end"
        ),
        "audit_events_history_insert_guard": (
            "create trigger audit_events_history_insert_guard before insert on audit_events "
            "when exists(select 1 from audit_events where id = new.id) or "
            "exists(select 1 from audit_events where event_hash = new.event_hash) "
            "begin select raise(abort, 'immutable audit event history'); end"
        ),
        "audit_events_update_guard": (
            "create trigger audit_events_update_guard before update on audit_events "
            "begin select raise(abort, 'audit events are append-only'); end"
        ),
    }
    definitions = {
        name: re.sub(r"\s+", " ", sql).strip().lower()
        for _kind, name, sql in objects
        if name in expected_definitions
    }
    if definitions != expected_definitions:
        raise StoreUnavailable("audit database")
    schema_version = connection.execute("PRAGMA schema_version").fetchone()
    data_version = connection.execute("PRAGMA data_version").fetchone()
    if (
        schema_version is None
        or type(schema_version[0]) is not int
        or data_version is None
        or type(data_version[0]) is not int
    ):
        raise StoreUnavailable("audit database")
    return objects, schema_version[0], data_version[0]


def _verify_rows(
    rows: Any,
    *,
    start: int,
    head: str,
    expected_count: int,
) -> tuple[int, str]:
    position = start
    for row in rows:
        position += 1
        if type(row[0]) is not int or row[0] != position:
            raise StoreUnavailable("audit database")
        existing = _validate_persisted_row(row)
        previous_hash = existing["previous_hash"]
        stored_hash = existing["event_hash"]
        if previous_hash != head:
            raise StoreUnavailable("audit database")
        try:
            expected_hash = _event_hash(previous_hash, existing["id"], existing)
        except (TypeError, ValueError, UnicodeError, OverflowError):
            raise StoreUnavailable("audit database") from None
        if stored_hash != expected_hash:
            raise StoreUnavailable("audit database")
        head = stored_hash
        if position > expected_count:
            raise StoreUnavailable("audit database")
    if position != expected_count:
        raise StoreUnavailable("audit database")
    return position, head


class SQLiteAuditWriter:
    """Append validated, chained audit events using an existing transaction."""

    def __init__(self) -> None:
        self._cache: _VerifiedPrefix | None = None
        self._cache_lock = RLock()

    def _verified_prefix(self, connection: sqlite3.Connection) -> tuple[int, str]:
        """Verify the visible prefix, caching only rows present before insertion.

        The cache is instance-local and bound to the live connection plus its
        immutable audit schema catalog. It is never advanced after this method
        returns, so an outer transaction may roll back safely; a later count
        regression or schema change forces a cold full scan.
        """
        with self._cache_lock:
            schema, schema_version, data_version = _schema_contract(connection)
            count_row = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()
            if (
                count_row is None
                or len(count_row) != 1
                or type(count_row[0]) is not int
                or count_row[0] < 0
            ):
                raise StoreUnavailable("audit database")
            count = count_row[0]
            cache = self._cache
            usable = (
                cache is not None
                and cache.connection is connection
                and cache.schema == schema
                and cache.schema_version == schema_version
                and cache.data_version == data_version
                and count >= cache.count
            )
            if usable and cache.count:
                tail = connection.execute(
                    f"SELECT {_AUDIT_COLUMNS} FROM audit_events WHERE id = ?",
                    (cache.count,),
                ).fetchone()
                if tail is None:
                    usable = False
                else:
                    persisted = _validate_persisted_row(tail)
                    usable = (
                        persisted["id"] == cache.count and persisted["event_hash"] == cache.head
                    )
            if usable:
                if count > cache.count:
                    rows = connection.execute(
                        f"SELECT {_AUDIT_COLUMNS} FROM audit_events WHERE id > ? ORDER BY id",
                        (cache.count,),
                    )
                    verified_count, head = _verify_rows(
                        rows,
                        start=cache.count,
                        head=cache.head,
                        expected_count=count,
                    )
                else:
                    verified_count, head = cache.count, cache.head
            else:
                rows = connection.execute(f"SELECT {_AUDIT_COLUMNS} FROM audit_events ORDER BY id")
                verified_count, head = _verify_rows(
                    rows,
                    start=0,
                    head=ZERO_HASH,
                    expected_count=count,
                )
            self._cache = _VerifiedPrefix(
                connection, schema, schema_version, data_version, verified_count, head
            )
            return verified_count, head

    def append_in_transaction(
        self,
        connection: sqlite3.Connection,
        event: AuditEventInput,
    ) -> None:
        values = _validated_event(event)
        try:
            active_transaction = connection.in_transaction
        except sqlite3.Error as exc:
            raise _store_unavailable(connection, exc) from exc
        if not active_transaction:
            raise ValueError("an active transaction is required")
        try:
            existing_count, head = self._verified_prefix(connection)
            event_id = existing_count + 1
            previous_hash = head
            event_hash = _event_hash(previous_hash, event_id, values)
            connection.execute(
                """
                INSERT INTO audit_events(
                    id, event_version, canonicalization_version, occurred_at,
                    actor, action, sha256, previous_decision, new_decision,
                    reason, policy_version, analyzer_version, previous_hash,
                    event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    EVENT_VERSION,
                    CANONICALIZATION_VERSION,
                    values["occurred_at"],
                    values["actor"],
                    values["action"],
                    values["sha256"],
                    values["previous_decision"],
                    values["new_decision"],
                    values["reason"],
                    values["policy_version"],
                    values["analyzer_version"],
                    previous_hash,
                    event_hash,
                ),
            )
            stored = connection.execute(
                """
                SELECT id, event_version, canonicalization_version, occurred_at,
                       actor, action, sha256, previous_decision, new_decision,
                       reason, policy_version, analyzer_version, previous_hash,
                       event_hash
                FROM audit_events WHERE id = ?
                """,
                (event_id,),
            ).fetchone()
            expected = (
                event_id,
                EVENT_VERSION,
                CANONICALIZATION_VERSION,
                values["occurred_at"],
                values["actor"],
                values["action"],
                values["sha256"],
                values["previous_decision"],
                values["new_decision"],
                values["reason"],
                values["policy_version"],
                values["analyzer_version"],
                previous_hash,
                event_hash,
            )
            if stored is None or tuple(stored) != expected:
                raise StoreUnavailable("audit database")
            persisted = _validate_persisted_row(stored)
            if persisted["event_hash"] != event_hash:
                raise StoreUnavailable("audit database")
        except StoreUnavailable:
            raise
        except (sqlite3.Error, TypeError, ValueError, UnicodeError, OverflowError) as exc:
            raise _store_unavailable(connection, exc) from exc
