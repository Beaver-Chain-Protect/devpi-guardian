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
        try:
            validate_sha256(expected_head)
        except (TypeError, ValueError):
            return _invalid(0, None, None, "invalid expected head")
    connection: sqlite3.Connection | None = None
    result: AuditVerificationResult | None = None
    primary: BaseException | None = None
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
        seen = 0
        for position, row in enumerate(rows, 1):
            seen = position
            if seen > count:
                result = _invalid(count, head, position, "row count mismatch")
                break
            event_id = row[0] if row and type(row[0]) is int else position
            if type(row[0]) is not int or row[0] != position:
                result = _invalid(count, head, position, "id gap or reorder")
                break
            try:
                values = _validate_persisted_row(row)
            except (TypeError, ValueError, UnicodeError, OverflowError) as exc:
                result = _invalid(count, head, event_id, str(exc))
                break
            previous_hash = values["previous_hash"]
            if previous_hash != (head or ZERO_HASH):
                result = _invalid(count, head, event_id, "previous hash mismatch")
                break
            try:
                computed = _event_hash(previous_hash, position, values)
            except (TypeError, ValueError, UnicodeError, OverflowError):
                result = _invalid(count, head, event_id, "event hash computation failed")
                break
            if values["event_hash"] != computed:
                result = _invalid(count, head, event_id, "event hash mismatch")
                break
            head = values["event_hash"]
        if result is None and seen != count:
            result = _invalid(count, head, seen + 1, "row count mismatch")
        if result is None and expected_head is not None and expected_head != head:
            result = _invalid(count, head, count + 1, "expected head mismatch")
        if result is None:
            result = AuditVerificationResult(True, count, head, None, None)
    except BaseException as exc:
        primary = exc
    finally:
        cleanup_errors: list[BaseException] = []
        if connection is not None:
            try:
                if connection.in_transaction:
                    connection.rollback()
            except BaseException as exc:
                cleanup_errors.append(exc)
            try:
                connection.close()
            except BaseException as exc:
                cleanup_errors.append(exc)
        if cleanup_errors:
            process_control = next(
                (
                    error
                    for error in cleanup_errors
                    if isinstance(error, (KeyboardInterrupt, SystemExit, GeneratorExit))
                ),
                None,
            )
            note_target = process_control or cleanup_errors[0]
            for cleanup_error in cleanup_errors:
                if cleanup_error is not note_target:
                    note_target.add_note(
                        "additional audit cleanup failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
            if primary is not None:
                primary.add_note(
                    f"audit cleanup failed: {type(note_target).__name__}: {note_target}"
                )
            elif process_control is not None:
                primary = process_control
            else:
                primary = StoreUnavailable(str(getattr(factory, "path", "audit database")))
                primary.__cause__ = cleanup_errors[0]
    if primary is not None:
        if isinstance(primary, StoreUnavailable):
            raise primary
        if isinstance(
            primary, (sqlite3.Error, OSError, TypeError, ValueError, UnicodeError, OverflowError)
        ):
            path = getattr(factory, "path", "audit database")
            raise StoreUnavailable(str(path)) from primary
        raise primary
    assert result is not None
    return result
