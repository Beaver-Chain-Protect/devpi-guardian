from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest

from devpi_guardian.activation import (
    ACTIVATION_VERSION,
    ActivationFailureCategory,
    GuardianActivationError,
    ensure_guardian_activation,
)
from devpi_guardian.verdicts.db import ConnectionFactory, migrate

NOW = datetime(2026, 8, 24, tzinfo=UTC)
DEVPI_UUID = "devpi-test-uuid"


def _factory(tmp_path):
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    return factory


def _count(factory):
    query = "SELECT COUNT(*) FROM guardian_activation"
    with closing(factory.connect()) as connection:
        row = connection.execute(query).fetchone()
        return row[0]


def test_first_empty_activation_persists_marker_once(tmp_path) -> None:
    factory = _factory(tmp_path)
    calls = 0

    def find_candidate() -> None:
        nonlocal calls
        calls += 1

    created = ensure_guardian_activation(
        factory,
        DEVPI_UUID,
        find_candidate,
        now=lambda: NOW,
    )

    with closing(factory.connect()) as connection:
        row = connection.execute(
            "SELECT singleton, devpi_uuid, activated_at, activation_version "
            "FROM guardian_activation"
        ).fetchone()
    assert created is True
    assert calls == 1
    assert tuple(row) == (1, DEVPI_UUID, NOW.isoformat(), ACTIVATION_VERSION)


def test_existing_marker_skips_inventory(tmp_path) -> None:
    factory = _factory(tmp_path)
    first = ensure_guardian_activation(
        factory,
        DEVPI_UUID,
        lambda: None,
        now=lambda: NOW,
    )

    def unexpected_inventory() -> None:
        raise AssertionError("inventory must not run on restart")

    second = ensure_guardian_activation(
        factory,
        DEVPI_UUID,
        unexpected_inventory,
        now=lambda: NOW + timedelta(days=1),
    )
    assert first is True
    assert second is False


def test_candidate_refuses_without_persisting_marker(tmp_path) -> None:
    factory = _factory(tmp_path)

    with pytest.raises(GuardianActivationError) as error:
        ensure_guardian_activation(
            factory,
            DEVPI_UUID,
            lambda: "release_link",
            now=lambda: NOW,
        )

    assert error.value.category is ActivationFailureCategory.EXISTING_ARTIFACTS
    assert str(error.value) == "guardian activation failed: existing_artifacts"
    assert _count(factory) == 0


def test_marker_uuid_mismatch_fails_closed(tmp_path) -> None:
    factory = _factory(tmp_path)
    ensure_guardian_activation(
        factory,
        DEVPI_UUID,
        lambda: None,
        now=lambda: NOW,
    )

    calls = 0

    def inventory() -> None:
        nonlocal calls
        calls += 1

    with pytest.raises(GuardianActivationError) as error:
        ensure_guardian_activation(
            factory,
            "other-devpi",
            inventory,
            now=lambda: NOW,
        )
    assert error.value.category is ActivationFailureCategory.UUID_MISMATCH
    assert calls == 0
    assert _count(factory) == 1


def test_malformed_persisted_timestamp_fails_closed(tmp_path) -> None:
    factory = _factory(tmp_path)
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            "INSERT INTO guardian_activation "
            "(singleton, devpi_uuid, activated_at, activation_version) "
            "VALUES (1, ?, ?, 1)",
            (DEVPI_UUID, "not-a-timestamp"),
        )

    with pytest.raises(GuardianActivationError) as error:
        ensure_guardian_activation(
            factory,
            DEVPI_UUID,
            lambda: None,
            now=lambda: NOW,
        )
    assert error.value.category is ActivationFailureCategory.MARKER_CORRUPT


def test_unknown_activation_version_fails_closed(tmp_path) -> None:
    factory = _factory(tmp_path)
    with closing(factory.connect()) as connection, connection:
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            "UPDATE sqlite_master SET sql = replace(sql, "
            "'activation_version INTEGER NOT NULL', "
            "'activation_version INTEGER NOT NULL') "
            "WHERE name = 'guardian_activation'"
        )
        connection.execute("PRAGMA writable_schema = OFF")
        # Temporarily loosen the table check to insert a malformed row.
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            "UPDATE sqlite_master SET sql = replace(sql, "
            "'activation_version = 1', 'activation_version >= 1') "
            "WHERE name = 'guardian_activation'"
        )
        connection.execute("PRAGMA writable_schema = OFF")
        connection.execute("VACUUM")
        connection.execute(
            "INSERT INTO guardian_activation "
            "(singleton, devpi_uuid, activated_at, activation_version) "
            "VALUES (1, ?, ?, 2)",
            (DEVPI_UUID, NOW.isoformat()),
        )

    with pytest.raises(GuardianActivationError) as error:
        ensure_guardian_activation(
            factory,
            DEVPI_UUID,
            lambda: None,
            now=lambda: NOW,
        )
    assert error.value.category is ActivationFailureCategory.MARKER_CORRUPT


def test_inventory_exception_is_sanitized(tmp_path) -> None:
    factory = _factory(tmp_path)
    secret = "inventory secret / candidate"

    def inventory() -> None:
        raise RuntimeError(secret)

    with pytest.raises(GuardianActivationError) as error:
        ensure_guardian_activation(
            factory,
            DEVPI_UUID,
            inventory,
            now=lambda: NOW,
        )
    category = error.value.category
    assert category is ActivationFailureCategory.INVENTORY_UNAVAILABLE
    assert secret not in str(error.value)
    assert DEVPI_UUID not in str(error.value)
    assert _count(factory) == 0


def test_sqlite_error_is_sanitized(tmp_path) -> None:
    factory = _factory(tmp_path)
    with closing(factory.connect()) as connection, connection:
        connection.execute("DROP TABLE guardian_activation")
    with pytest.raises(GuardianActivationError) as error:
        ensure_guardian_activation(
            factory,
            DEVPI_UUID,
            lambda: None,
            now=lambda: NOW,
        )
    assert error.value.category is ActivationFailureCategory.STORE_UNAVAILABLE
    assert str(factory.path) not in str(error.value)
    assert "guardian_activation" not in str(error.value)


@pytest.mark.parametrize(
    ("uuid", "clock"),
    [
        ("", lambda: NOW),
        ("   ", lambda: NOW),
        ("bad\x00uuid", lambda: NOW),
        ("ok", lambda: datetime(2026, 8, 24)),
        ("ok", lambda: datetime(2026, 8, 24, tzinfo=timedelta(hours=1))),
    ],
)
def test_invalid_uuid_and_non_utc_clock_are_rejected_before_write(
    tmp_path,
    uuid,
    clock,
) -> None:
    factory = _factory(tmp_path)
    calls = 0

    def inventory() -> None:
        nonlocal calls
        calls += 1

    with pytest.raises(ValueError):
        ensure_guardian_activation(factory, uuid, inventory, now=clock)
    assert calls == 0
    assert _count(factory) == 0


@pytest.mark.parametrize("uuid", [True, 1, "\ud800", "x\x00y"])
def test_uuid_requires_exact_safe_string(tmp_path, uuid) -> None:
    factory = _factory(tmp_path)
    with pytest.raises(ValueError):
        ensure_guardian_activation(
            factory,
            uuid,
            lambda: None,
            now=lambda: NOW,
        )
    assert _count(factory) == 0


@pytest.mark.parametrize("candidate", [True, 1, "", "   ", "x\x00y", "\ud800"])
def test_invalid_candidate_is_inventory_unavailable(
    tmp_path,
    candidate,
) -> None:
    factory = _factory(tmp_path)
    with pytest.raises(GuardianActivationError) as error:
        ensure_guardian_activation(
            factory,
            DEVPI_UUID,
            lambda: candidate,
            now=lambda: NOW,
        )
    category = error.value.category
    assert category is ActivationFailureCategory.INVENTORY_UNAVAILABLE
    if candidate:
        assert str(candidate) not in str(error.value)
    assert _count(factory) == 0


def test_matching_row_accepts_only_canonical_utc_timestamp(tmp_path) -> None:
    factory = _factory(tmp_path)
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            "INSERT INTO guardian_activation "
            "(singleton, devpi_uuid, activated_at, activation_version) "
            "VALUES (1, ?, ?, 1)",
            (DEVPI_UUID, "2026-08-24T00:00:00Z"),
        )
    with pytest.raises(GuardianActivationError) as error:
        ensure_guardian_activation(
            factory,
            DEVPI_UUID,
            lambda: None,
            now=lambda: NOW,
        )
    assert error.value.category is ActivationFailureCategory.MARKER_CORRUPT


class _CloseFailConnection:
    def __init__(self, connection, *, fail_close=False, fail_rollback=False):
        self._connection = connection
        self.fail_close = fail_close
        self.fail_rollback = fail_rollback
        self.rollback_calls = 0

    def execute(self, *args, **kwargs):
        return self._connection.execute(*args, **kwargs)

    def rollback(self):
        self.rollback_calls += 1
        if self.fail_rollback:
            raise sqlite3.OperationalError("rollback secret")
        return self._connection.rollback()

    def commit(self):
        return self._connection.commit()

    @property
    def in_transaction(self):
        return self._connection.in_transaction

    def close(self):
        self._connection.close()
        if self.fail_close:
            raise sqlite3.OperationalError("close secret")


class _Factory:
    def __init__(self, connection):
        self.connection = connection

    def connect(self):
        return self.connection


def test_primary_inventory_failure_survives_rollback_and_close_failure(
    tmp_path,
) -> None:
    factory = _factory(tmp_path)
    wrapper = _CloseFailConnection(
        factory.connect(),
        fail_close=True,
        fail_rollback=True,
    )
    with pytest.raises(GuardianActivationError) as error:
        ensure_guardian_activation(
            _Factory(wrapper),
            DEVPI_UUID,
            lambda: (_ for _ in ()).throw(RuntimeError("primary secret")),
            now=lambda: NOW,
        )
    category = error.value.category
    assert category is ActivationFailureCategory.INVENTORY_UNAVAILABLE
    assert "primary secret" not in str(error.value)
    assert wrapper is not None and wrapper.rollback_calls == 1


def test_close_failure_after_commit_does_not_report_rollback(tmp_path) -> None:
    factory = _factory(tmp_path)
    wrapper = _CloseFailConnection(factory.connect(), fail_close=True)
    assert (
        ensure_guardian_activation(
            _Factory(wrapper),
            DEVPI_UUID,
            lambda: None,
            now=lambda: NOW,
        )
        is True
    )

    query = "SELECT COUNT(*) FROM guardian_activation"
    with closing(factory.connect()) as connection:
        row = connection.execute(query).fetchone()
        assert row[0] == 1
