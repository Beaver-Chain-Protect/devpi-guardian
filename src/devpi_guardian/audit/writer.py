from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import UTC, datetime
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


def _text(value: object, field: str, maximum: int) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{field} must be a nonblank string")
    if len(value) > maximum:
        raise ValueError(f"{field} is too long")
    if any(
        ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        or 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    ):
        raise ValueError(f"{field} contains a control character")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field} is not valid UTF-8") from exc
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
    return hashlib.sha256(
        bytes.fromhex(previous_hash) + b"\0" + _canonical_payload(event_id, previous_hash, values),
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


class SQLiteAuditWriter:
    """Append validated, chained audit events using an existing transaction."""

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
            row = connection.execute(
                """
                SELECT id, event_version, canonicalization_version, occurred_at,
                       actor, action, sha256, previous_decision, new_decision,
                       reason, policy_version, analyzer_version, previous_hash,
                       event_hash
                FROM audit_events ORDER BY id DESC LIMIT 1
                """
            ).fetchone()
            head = ZERO_HASH
            event_id = 1
            if row is not None:
                existing = _validate_persisted_row(row)
                previous_hash = existing["previous_hash"]
                stored_hash = existing["event_hash"]
                try:
                    expected_hash = _event_hash(previous_hash, existing["id"], existing)
                except (TypeError, ValueError, UnicodeError, OverflowError):
                    raise StoreUnavailable("audit database") from None
                if stored_hash != expected_hash:
                    raise StoreUnavailable("audit database")
                head = stored_hash
                event_id = existing["id"] + 1
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
