from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from datetime import datetime, timedelta
from enum import StrEnum

from devpi_guardian.verdicts.db import ConnectionFactory

ACTIVATION_VERSION = 1
_MAX_BOUNDARY_STRING = 4096


class _InvalidActivationClock(ValueError):
    pass


class ActivationFailureCategory(StrEnum):
    EXISTING_ARTIFACTS = "existing_artifacts"
    INVENTORY_UNAVAILABLE = "inventory_unavailable"
    MARKER_CORRUPT = "marker_corrupt"
    STORE_UNAVAILABLE = "store_unavailable"
    UUID_MISMATCH = "uuid_mismatch"


class GuardianActivationError(RuntimeError):
    def __init__(self, category: ActivationFailureCategory) -> None:
        self.category = category
        super().__init__(f"guardian activation failed: {category.value}")


CandidateFinder = Callable[[], str | None]


def _valid_boundary_string(value: object) -> bool:
    if type(value) is not str:
        return False
    if not value or not value.strip() or len(value) > _MAX_BOUNDARY_STRING:
        return False
    if "\x00" in value:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _serialize_clock(now: Callable[[], datetime]) -> str:
    try:
        value = now()
    except Exception:
        raise _InvalidActivationClock("invalid activation clock") from None
    if type(value) is not datetime:
        raise _InvalidActivationClock("invalid activation clock")
    try:
        offset = value.utcoffset()
    except Exception:
        raise _InvalidActivationClock("invalid activation clock") from None
    try:
        if value.tzinfo is None or offset != timedelta(0):
            raise _InvalidActivationClock("invalid activation clock")
        serialized = value.isoformat()
        if not _valid_canonical_timestamp(serialized):
            raise _InvalidActivationClock("invalid activation clock")
        return serialized
    except _InvalidActivationClock:
        raise
    except Exception:
        raise _InvalidActivationClock("invalid activation clock") from None


def _valid_canonical_timestamp(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = datetime.fromisoformat(value)
        offset = parsed.utcoffset()
    except (TypeError, ValueError, OverflowError):
        return False
    if parsed.tzinfo is None or offset != timedelta(0):
        return False
    return parsed.isoformat() == value


def _marker_is_valid(row: object) -> bool:
    try:
        if len(row) != 4:
            return False
        singleton, marker_uuid, activated_at, version = row
    except (TypeError, ValueError):
        return False
    return (
        type(singleton) is int
        and singleton == 1
        and _valid_boundary_string(marker_uuid)
        and _valid_canonical_timestamp(activated_at)
        and type(version) is int
        and version == ACTIVATION_VERSION
    )


def _store_failure() -> GuardianActivationError:
    return GuardianActivationError(ActivationFailureCategory.STORE_UNAVAILABLE)


def ensure_guardian_activation(
    factory: ConnectionFactory,
    devpi_uuid: str,
    find_candidate: CandidateFinder,
    *,
    now: Callable[[], datetime],
) -> bool:
    """Create or validate the immutable activation marker."""
    if not _valid_boundary_string(devpi_uuid):
        raise ValueError("invalid devpi UUID")

    connection = None
    transaction_started = False
    committed = False
    result = False
    activated_at = ""
    primary: BaseException | None = None

    try:
        try:
            connection = factory.connect()
            connection.execute("BEGIN IMMEDIATE")
            transaction_started = True
            cursor = connection.execute(
                "SELECT singleton, devpi_uuid, activated_at, "
                "activation_version "
                "FROM guardian_activation LIMIT 2"
            )
            rows = cursor.fetchmany(2)
            if len(rows) > 1:
                raise GuardianActivationError(
                    ActivationFailureCategory.MARKER_CORRUPT,
                )
            if rows:
                row = rows[0]
                if not _marker_is_valid(row):
                    raise GuardianActivationError(
                        ActivationFailureCategory.MARKER_CORRUPT,
                    )
                if row[1] != devpi_uuid:
                    raise GuardianActivationError(
                        ActivationFailureCategory.UUID_MISMATCH,
                    )
                result = False
            else:
                try:
                    activated_at = _serialize_clock(now)
                except _InvalidActivationClock as exc:
                    primary = ValueError(str(exc))
                    raise
                try:
                    candidate = find_candidate()
                except Exception:
                    raise GuardianActivationError(
                        ActivationFailureCategory.INVENTORY_UNAVAILABLE
                    ) from None
                if candidate is not None:
                    if not _valid_boundary_string(candidate):
                        raise GuardianActivationError(
                            ActivationFailureCategory.INVENTORY_UNAVAILABLE
                        )
                    raise GuardianActivationError(
                        ActivationFailureCategory.EXISTING_ARTIFACTS,
                    )
                connection.execute(
                    "INSERT INTO guardian_activation "
                    "(singleton, devpi_uuid, activated_at, "
                    "activation_version) "
                    "VALUES (?, ?, ?, ?)",
                    (1, devpi_uuid, activated_at, ACTIVATION_VERSION),
                )
                result = True
            connection.commit()
            committed = True
        except _InvalidActivationClock:
            pass
        except GuardianActivationError as exc:
            primary = exc
        except Exception:
            primary = _store_failure()
    finally:
        if connection is not None and transaction_started and not committed:
            with suppress(Exception):
                connection.rollback()
        if connection is not None:
            try:
                connection.close()
            except Exception:
                if primary is None and not committed:
                    primary = _store_failure()

    if primary is not None:
        raise primary
    return result
