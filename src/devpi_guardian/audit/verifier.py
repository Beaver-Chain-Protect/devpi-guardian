from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from devpi_guardian.verdicts.db import ConnectionFactory
from devpi_guardian.verdicts.errors import StoreUnavailable
from devpi_guardian.verdicts.models import validate_sha256

from .writer import (
    ZERO_HASH,
    _event_hash,
    _validate_persisted_row,
)


@dataclass(frozen=True, slots=True)
class AuditVerificationResult:
    valid: bool
    count: int
    head: str | None
    first_invalid_id: int | None
    reason: str | None


# A descriptive alias keeps the result discoverable for callers that use the
# chain terminology from the design.
AuditChainVerification = AuditVerificationResult


def _invalid(
    count: int,
    head: str | None,
    event_id: int | None,
    reason: str,
) -> AuditVerificationResult:
    return AuditVerificationResult(False, count, head, event_id, reason)


def verify_audit_chain(
    factory: ConnectionFactory,
    expected_head: str | None = None,
) -> AuditVerificationResult:
    if expected_head is not None:
        validate_sha256(expected_head)
    connection: sqlite3.Connection | None = None
    try:
        connection = factory.connect()
        connection.execute("BEGIN")
        count_row = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()
        if (
            count_row is None
            or len(count_row) != 1
            or type(count_row[0]) is not int
            or count_row[0] < 0
        ):
            raise ValueError("invalid audit event count")
        count = count_row[0]
        rows = connection.execute(
            """
            SELECT id, event_version, canonicalization_version, occurred_at,
                   actor, action, sha256, previous_decision, new_decision,
                   reason, policy_version, analyzer_version, previous_hash,
                   event_hash
            FROM audit_events ORDER BY id
            """
        )
        head: str | None = None
        for position, row in enumerate(rows, 1):
            event_id = row[0] if row and type(row[0]) is int else position
            if type(row[0]) is not int or row[0] != position:
                return _invalid(count, head, position, "id gap or reorder")
            try:
                values = _validate_persisted_row(row)
            except (TypeError, ValueError, UnicodeError, OverflowError) as exc:
                return _invalid(count, head, event_id, str(exc))
            previous_hash = values["previous_hash"]
            if previous_hash != (head or ZERO_HASH):
                return _invalid(count, head, event_id, "previous hash mismatch")
            try:
                computed = _event_hash(previous_hash, position, values)
            except (TypeError, ValueError, UnicodeError, OverflowError):
                return _invalid(count, head, event_id, "event hash computation failed")
            if values["event_hash"] != computed:
                return _invalid(count, head, event_id, "event hash mismatch")
            head = values["event_hash"]
        if expected_head is not None and expected_head != head:
            return _invalid(count, head, count + 1, "expected head mismatch")
        return AuditVerificationResult(True, count, head, None, None)
    except StoreUnavailable:
        raise
    except (sqlite3.Error, OSError, TypeError, ValueError, UnicodeError, OverflowError) as exc:
        path = getattr(factory, "path", "audit database")
        raise StoreUnavailable(str(path)) from exc
    finally:
        if connection is not None:
            try:
                if connection.in_transaction:
                    connection.rollback()
                connection.close()
            except (sqlite3.Error, OSError):
                pass
