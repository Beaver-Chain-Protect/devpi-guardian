from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from types import SimpleNamespace

import pytest

from devpi_guardian.activation import (
    ACTIVATION_VERSION,
    ActivationFailureCategory,
    GuardianActivationError,
    ensure_guardian_activation,
)
from devpi_guardian.verdicts.db import ConnectionFactory, migrate


def _plugin_config(tmp_path, *, quarantine_root=None):
    args = SimpleNamespace(
        guardian_db=str(tmp_path / "guardian.db"),
        guardian_quarantine_root=None if quarantine_root is None else str(quarantine_root),
        guardian_base_url="http://127.0.0.1:3141",
        guardian_cooldown_hours=24.0,
        guardian_worker_poll_interval=0.25,
    )
    return SimpleNamespace(
        args=args,
        server_path=str(tmp_path / "server"),
        nodeinfo={"uuid": "plugin-test"},
    )


def test_primary_rejects_missing_quarantine_before_migration_or_publication(tmp_path, monkeypatch):
    import devpi_guardian.plugin as plugin

    xom = SimpleNamespace(is_replica=lambda: False, thread_pool=SimpleNamespace(registered=[]))
    pyramid = SimpleNamespace(registry={"xom": xom}, tweens=[])
    config = _plugin_config(tmp_path)
    monkeypatch.setattr(plugin, "migrate", lambda _factory: pytest.fail("migration must not run"))

    with pytest.raises(plugin.Fatal, match="quarantine root"):
        plugin.devpiserver_pyramid_configure(config, pyramid)

    assert xom.thread_pool.registered == []
    assert plugin.VERDICT_READER_REGISTRY_KEY not in pyramid.registry
    assert pyramid.tweens == []


@pytest.mark.parametrize("kind", ["relative", "contained", "symlink", "mode", "owner"])
def test_primary_rejects_unsafe_quarantine_roots_before_migration(tmp_path, monkeypatch, kind):
    import os

    import devpi_guardian.plugin as plugin

    server = tmp_path / "server"
    server.mkdir()
    target = tmp_path / "quarantine-target"
    target.mkdir()
    target.chmod(0o700)
    if kind == "relative":
        root = Path("relative-quarantine")
    elif kind == "contained":
        root = server / "quarantine"
        root.mkdir()
        root.chmod(0o700)
    elif kind == "symlink":
        root = tmp_path / "quarantine-link"
        root.symlink_to(target, target_is_directory=True)
    else:
        root = target
        if kind == "mode":
            root.chmod(0o755)
        elif kind == "owner":
            owner_uid = os.geteuid()
            monkeypatch.setattr(plugin.os, "geteuid", lambda: owner_uid + 1)

    xom = SimpleNamespace(is_replica=lambda: False, thread_pool=SimpleNamespace(registered=[]))
    pyramid = SimpleNamespace(registry={"xom": xom}, tweens=[])
    config = _plugin_config(tmp_path, quarantine_root=root)
    config.server_path = str(server)
    monkeypatch.setattr(plugin, "migrate", lambda _factory: pytest.fail("migration must not run"))

    with pytest.raises(plugin.Fatal):
        plugin.devpiserver_pyramid_configure(config, pyramid)

    assert xom.thread_pool.registered == []
    assert pyramid.registry == {"xom": xom}
    assert pyramid.tweens == []


def test_primary_rejects_unsafe_quarantine_parent_before_migration(tmp_path, monkeypatch):
    import devpi_guardian.plugin as plugin

    server = tmp_path / "server"
    server.mkdir()
    parent = tmp_path / "unsafe-parent"
    parent.mkdir(mode=0o700)
    parent.chmod(0o777)
    root = parent / "quarantine"
    root.mkdir(mode=0o700)
    xom = SimpleNamespace(is_replica=lambda: False, thread_pool=SimpleNamespace(registered=[]))
    pyramid = SimpleNamespace(registry={"xom": xom}, tweens=[])
    config = _plugin_config(tmp_path, quarantine_root=root)
    config.server_path = str(server)
    monkeypatch.setattr(plugin, "migrate", lambda _factory: pytest.fail("migration must not run"))

    with pytest.raises(plugin.Fatal, match=r"parent|unsafe|mode"):
        plugin.devpiserver_pyramid_configure(config, pyramid)


def test_upload_hook_replica_is_noop_but_primary_requires_connector():
    import devpi_guardian.plugin as plugin

    replica = SimpleNamespace(is_replica=lambda: True)
    plugin.devpiserver_on_upload(SimpleNamespace(xom=replica), "demo", "1.0", object())

    primary = SimpleNamespace(is_replica=lambda: False)
    with pytest.raises(RuntimeError, match="connector"):
        plugin.devpiserver_on_upload(SimpleNamespace(xom=primary), "demo", "1.0", object())


def test_upload_hook_forwards_exact_arguments():
    import devpi_guardian.plugin as plugin

    calls = []

    class Connector:
        def capture(self, **kwargs):
            calls.append(kwargs)

    xom = SimpleNamespace(is_replica=lambda: False)
    xom._devpi_guardian_upload_connector = Connector()
    stage = SimpleNamespace(xom=xom)
    link = object()
    plugin.devpiserver_on_upload(stage, "demo", "1.0", link)

    assert calls == [{"stage": stage, "project": "demo", "version": "1.0", "link": link}]


def test_publish_failure_rolls_back_registry_xom_and_thread_registration(monkeypatch):
    import devpi_guardian.plugin as plugin

    class Pool:
        def __init__(self):
            self.registered = []

        def register(self, worker):
            self.registered.append(worker)

    pool = Pool()
    xom = SimpleNamespace(thread_pool=pool)
    registry = {}
    pyramid = SimpleNamespace(registry=registry, routes=[], views=[], tweens=[])
    worker = object()

    class Queue:
        def discover(self, _candidate):
            return None

        def discover_many(self, _candidates):
            return None

    components = SimpleNamespace(
        queue=Queue(),
        reader=object(),
        block_metrics=object(),
        admin_service=object(),
        upload_connector=object(),
        worker=worker,
    )
    monkeypatch.setattr(
        plugin,
        "configure_admin_routes",
        lambda _config: (_ for _ in ()).throw(RuntimeError("route failure")),
    )

    with pytest.raises(RuntimeError, match="route failure"):
        plugin._publish_components(components, pyramid, xom)

    assert pool.registered == []
    assert registry == {}
    assert not hasattr(xom, "_devpi_guardian_verdict_reader")
    assert not hasattr(xom, "_devpi_guardian_discovery_sink")
    assert not hasattr(xom, "_devpi_guardian_upload_connector")
    assert pyramid.routes == []
    assert pyramid.views == []
    assert pyramid.tweens == []


def test_publish_add_tween_failure_precedes_real_thread_registration(monkeypatch):
    import devpi_guardian.plugin as plugin

    class Pool:
        def __init__(self):
            self.registered = []

        def register(self, worker):
            self.registered.append(worker)

    pool = Pool()
    xom = SimpleNamespace(thread_pool=pool)
    pyramid = SimpleNamespace(registry={}, routes=[], views=[], tweens=[])
    components = SimpleNamespace(
        queue=SimpleNamespace(discover=lambda _candidate: None, discover_many=lambda _items: None),
        reader=object(),
        block_metrics=object(),
        admin_service=object(),
        upload_connector=object(),
        worker=object(),
    )
    monkeypatch.setattr(plugin, "configure_admin_routes", lambda _config: None)
    monkeypatch.setattr(
        pyramid,
        "add_tween",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("tween conflict")),
        raising=False,
    )

    with pytest.raises(RuntimeError, match="tween conflict"):
        plugin._publish_components(components, pyramid, xom)

    assert pool.registered == []


def test_real_configurator_conflict_does_not_publish_or_build(monkeypatch, tmp_path):
    from pyramid.config import Configurator
    from pyramid.exceptions import ConfigurationConflictError

    import devpi_guardian.plugin as plugin

    root = (tmp_path / "quarantine").resolve()
    root.mkdir()
    root.chmod(0o700)
    xom = SimpleNamespace(is_replica=lambda: False, thread_pool=SimpleNamespace(_objects=[]))
    config = _plugin_config(tmp_path, quarantine_root=root)
    pyramid = Configurator(autocommit=False)
    pyramid.registry["xom"] = xom
    monkeypatch.setattr(plugin, "migrate", lambda _factory: None)
    monkeypatch.setattr(plugin, "verify_audit_chain", lambda _factory: SimpleNamespace(valid=True))
    monkeypatch.setattr(plugin, "ensure_guardian_activation", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        plugin,
        "_build_components",
        lambda *_args: pytest.fail("components must not build before commit conflict resolution"),
    )

    plugin.devpiserver_pyramid_configure(config, pyramid)
    pyramid.add_route("guardian_health", "/different-conflicting-route")

    with pytest.raises(ConfigurationConflictError):
        pyramid.commit()

    assert xom.thread_pool._objects == []
    assert not hasattr(xom, "_devpi_guardian_verdict_reader")
    assert plugin.ADMIN_SERVICE_REGISTRY_KEY not in pyramid.registry


def test_real_configurator_activation_failure_rolls_back_routes_tween_and_introspection(
    monkeypatch, tmp_path
):
    from pyramid.config import Configurator
    from pyramid.interfaces import IRoutesMapper, ITweens

    import devpi_guardian.plugin as plugin
    from devpi_guardian.activation import ActivationFailureCategory

    root = (tmp_path / "quarantine").resolve()
    root.mkdir()
    root.chmod(0o700)
    xom = SimpleNamespace(is_replica=lambda: False, thread_pool=SimpleNamespace(_objects=[]))
    config = _plugin_config(tmp_path, quarantine_root=root)
    pyramid = Configurator(autocommit=False)
    pyramid.registry["xom"] = xom
    before_mapper = pyramid.registry.queryUtility(IRoutesMapper)
    before_tweens = pyramid.registry.queryUtility(ITweens)
    before_introspection = {
        category: dict(entries) for category, entries in pyramid.introspector._categories.items()
    }
    monkeypatch.setattr(plugin, "migrate", lambda _factory: None)
    monkeypatch.setattr(plugin, "verify_audit_chain", lambda _factory: SimpleNamespace(valid=True))
    monkeypatch.setattr(
        plugin,
        "ensure_guardian_activation",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            plugin.GuardianActivationError(ActivationFailureCategory.STORE_UNAVAILABLE)
        ),
    )

    plugin.devpiserver_pyramid_configure(config, pyramid)

    with pytest.raises(Exception, match="guardian activation failed"):
        pyramid.commit()

    assert xom.thread_pool._objects == []
    assert pyramid.registry == {"xom": xom}
    assert pyramid.registry.queryUtility(IRoutesMapper) is before_mapper
    assert pyramid.registry.queryUtility(ITweens) is before_tweens
    assert pyramid.registry.queryUtility(ITweens).sorter.names == before_tweens.sorter.names
    assert {
        category: dict(entries) for category, entries in pyramid.introspector._categories.items()
    } == before_introspection
    events = []
    pyramid.action("post-rollback", callable=lambda: events.append("ran"))
    pyramid.commit()
    assert events == ["ran"]


def test_final_publication_runs_after_later_finite_actions(monkeypatch, tmp_path):
    from pyramid.config import Configurator

    import devpi_guardian.plugin as plugin

    root = (tmp_path / "quarantine").resolve()
    root.mkdir()
    root.chmod(0o700)
    xom = SimpleNamespace(is_replica=lambda: False, thread_pool=SimpleNamespace(_objects=[]))
    config = _plugin_config(tmp_path, quarantine_root=root)
    pyramid = Configurator(autocommit=False)
    pyramid.registry["xom"] = xom
    events = []
    monkeypatch.setattr(plugin, "migrate", lambda _factory: None)
    monkeypatch.setattr(plugin, "verify_audit_chain", lambda _factory: SimpleNamespace(valid=True))
    monkeypatch.setattr(plugin, "ensure_guardian_activation", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        plugin,
        "_build_components",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("build probe")),
    )
    plugin.devpiserver_pyramid_configure(config, pyramid)
    pyramid.action("later-finite", callable=lambda: events.append("later"), order=9999)

    with pytest.raises(Exception, match="build probe"):
        pyramid.commit()

    assert events == ["later"]


def test_activation_failure_after_quarantine_open_has_no_component_side_effects(tmp_path):
    import devpi_guardian.plugin as plugin

    root = tmp_path / "quarantine"
    root.mkdir()
    root.chmod(0o700)
    settings = plugin._GuardianSettings(
        db_path=tmp_path / "guardian.db",
        quarantine_root=root,
        base_url="http://127.0.0.1:3141",
        cooldown_duration=timedelta(hours=24),
        poll_interval=0.1,
    )
    xom = SimpleNamespace(is_replica=lambda: False)

    with pytest.raises(RuntimeError, match="activation failed"):
        plugin._build_components(
            settings,
            ConnectionFactory(tmp_path / "unused.db"),
            xom,
            activation=lambda: (_ for _ in ()).throw(RuntimeError("activation failed")),
        )

    assert not (tmp_path / "discovery").exists()
    assert list(root.iterdir()) == []


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


def test_matching_restart_skips_clock_and_inventory(tmp_path) -> None:
    factory = _factory(tmp_path)
    ensure_guardian_activation(
        factory,
        DEVPI_UUID,
        lambda: None,
        now=lambda: NOW,
    )
    calls = {"clock": 0, "inventory": 0}

    def invalid_clock() -> datetime:
        calls["clock"] += 1
        raise AssertionError("clock must not run")

    def unexpected_inventory() -> None:
        calls["inventory"] += 1
        raise AssertionError("inventory must not run")

    assert (
        ensure_guardian_activation(
            factory,
            DEVPI_UUID,
            unexpected_inventory,
            now=invalid_clock,
        )
        is False
    )
    assert calls == {"clock": 0, "inventory": 0}


def test_uuid_mismatch_wins_before_clock_or_inventory(tmp_path) -> None:
    factory = _factory(tmp_path)
    ensure_guardian_activation(
        factory,
        DEVPI_UUID,
        lambda: None,
        now=lambda: NOW,
    )
    calls = {"clock": 0, "inventory": 0}

    def invalid_clock() -> datetime:
        calls["clock"] += 1
        raise AssertionError("clock must not run")

    def unexpected_inventory() -> None:
        calls["inventory"] += 1
        raise AssertionError("inventory must not run")

    with pytest.raises(GuardianActivationError) as error:
        ensure_guardian_activation(
            factory,
            "other-devpi",
            unexpected_inventory,
            now=invalid_clock,
        )
    assert error.value.category is ActivationFailureCategory.UUID_MISMATCH
    assert calls == {"clock": 0, "inventory": 0}
    assert _count(factory) == 1


@pytest.mark.parametrize("corrupt", ["timestamp", "version"])
def test_marker_corruption_wins_before_clock_or_inventory(
    tmp_path,
    corrupt,
) -> None:
    factory = _factory(tmp_path)
    with closing(factory.connect()) as connection, connection:
        activated_at = NOW.isoformat()
        if corrupt == "timestamp":
            activated_at = "not-a-timestamp"
        version = 2 if corrupt == "version" else 1
        if corrupt == "timestamp":
            connection.execute(
                "INSERT INTO guardian_activation "
                "(singleton, devpi_uuid, activated_at, activation_version) "
                "VALUES (1, ?, ?, ?)",
                (DEVPI_UUID, activated_at, version),
            )
        if corrupt == "version":
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
                "VALUES (1, ?, ?, ?)",
                (DEVPI_UUID, NOW.isoformat(), version),
            )
    calls = {"clock": 0, "inventory": 0}

    def invalid_clock() -> datetime:
        calls["clock"] += 1
        raise AssertionError("clock must not run")

    def unexpected_inventory() -> None:
        calls["inventory"] += 1
        raise AssertionError("inventory must not run")

    with pytest.raises(GuardianActivationError) as error:
        ensure_guardian_activation(
            factory,
            DEVPI_UUID,
            unexpected_inventory,
            now=invalid_clock,
        )
    assert error.value.category is ActivationFailureCategory.MARKER_CORRUPT
    assert calls == {"clock": 0, "inventory": 0}
    assert _count(factory) == 1


def test_invalid_missing_row_clock_preserves_value_error(tmp_path) -> None:
    factory = _factory(tmp_path)
    calls = {"clock": 0, "inventory": 0}

    def invalid_clock() -> datetime:
        calls["clock"] += 1
        raise ValueError("clock secret")

    def inventory() -> None:
        calls["inventory"] += 1

    with pytest.raises(ValueError, match="invalid activation clock") as error:
        ensure_guardian_activation(
            factory,
            DEVPI_UUID,
            inventory,
            now=invalid_clock,
        )
    assert "clock secret" not in str(error.value)
    assert calls == {"clock": 1, "inventory": 0}
    assert _count(factory) == 0


class _StatefulZone(tzinfo):
    def __init__(self) -> None:
        self.calls = 0

    def utcoffset(self, value):
        self.calls += 1
        if self.calls == 1:
            return timedelta(0)
        return timedelta(hours=1)


def test_stateful_clock_timezone_is_rejected_after_serialization(
    tmp_path,
) -> None:
    factory = _factory(tmp_path)
    zone = _StatefulZone()
    calls = 0

    def inventory() -> None:
        nonlocal calls
        calls += 1

    with pytest.raises(ValueError, match="invalid activation clock") as error:
        ensure_guardian_activation(
            factory,
            DEVPI_UUID,
            inventory,
            now=lambda: datetime(2026, 8, 24, tzinfo=zone),
        )
    assert "01:00" not in str(error.value)
    assert calls == 0
    assert zone.calls >= 2
    assert _count(factory) == 0


class _StringSubclass(str):
    pass


class _FakeCursor:
    def __init__(self, rows):
        self.rows = rows

    def fetchmany(self, size):
        assert size == 2
        return self.rows


class _FakeConnection:
    def __init__(self, rows):
        self.cursor = _FakeCursor(rows)
        self.statements = []
        self.commit_calls = 0
        self.rollback_calls = 0
        self.close_calls = 0

    def execute(self, statement, *parameters):
        self.statements.append(statement)
        if statement.startswith("SELECT"):
            return self.cursor
        return self

    def commit(self):
        self.commit_calls += 1

    def rollback(self):
        self.rollback_calls += 1

    def close(self):
        self.close_calls += 1


class _FakeFactory:
    def __init__(self, connection):
        self.connection = connection
        self.connect_calls = 0

    def connect(self):
        self.connect_calls += 1
        return self.connection


@pytest.mark.parametrize(
    "rows",
    [
        [
            (1, DEVPI_UUID, NOW.isoformat(), 1),
            (1, DEVPI_UUID, NOW.isoformat(), 1),
        ],
        [(True, DEVPI_UUID, NOW.isoformat(), 1)],
        [(1, DEVPI_UUID, NOW.isoformat(), "1")],
        [(1, _StringSubclass(DEVPI_UUID), NOW.isoformat(), 1)],
    ],
    ids=["duplicate", "bool-singleton", "string-version", "string-subclass"],
)
def test_marker_row_shape_and_types_fail_closed_without_clock(
    rows,
) -> None:
    connection = _FakeConnection(rows)
    factory = _FakeFactory(connection)
    calls = {"clock": 0, "inventory": 0}

    def invalid_clock() -> datetime:
        calls["clock"] += 1
        raise AssertionError("clock must not run")

    def unexpected_inventory() -> None:
        calls["inventory"] += 1
        raise AssertionError("inventory must not run")

    with pytest.raises(GuardianActivationError) as error:
        ensure_guardian_activation(
            factory,
            DEVPI_UUID,
            unexpected_inventory,
            now=invalid_clock,
        )
    assert error.value.category is ActivationFailureCategory.MARKER_CORRUPT
    assert calls == {"clock": 0, "inventory": 0}
    assert factory.connect_calls == 1
    assert connection.commit_calls == 0
    assert connection.rollback_calls == 1
    assert connection.close_calls == 1


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
    calls = 0

    def inventory() -> None:
        nonlocal calls
        calls += 1
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
    assert calls == 1
    assert _count(factory) == 0


def test_sqlite_error_is_sanitized(tmp_path) -> None:
    factory = _factory(tmp_path)
    with closing(factory.connect()) as connection, connection:
        connection.execute("DROP TABLE guardian_activation")
    calls = 0

    def inventory() -> None:
        nonlocal calls
        calls += 1

    with pytest.raises(GuardianActivationError) as error:
        ensure_guardian_activation(
            factory,
            DEVPI_UUID,
            inventory,
            now=lambda: NOW,
        )
    assert error.value.category is ActivationFailureCategory.STORE_UNAVAILABLE
    assert str(factory.path) not in str(error.value)
    assert "guardian_activation" not in str(error.value)
    assert calls == 0


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


def test_precommit_close_failure_overrides_inventory_and_rollback_failure(
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
    assert category is ActivationFailureCategory.STORE_UNAVAILABLE
    message = str(error.value)
    assert "primary secret" not in message
    assert "rollback secret" not in message
    assert "close secret" not in message
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
