import sqlite3
from importlib import metadata
from pathlib import Path
from types import SimpleNamespace

import pytest

from devpi_guardian.enforcement.metrics import (
    BLOCK_METRIC_REGISTRY_KEY,
    InMemoryBlockMetricRecorder,
)
from devpi_guardian.enforcement.tween import VERDICT_READER_REGISTRY_KEY
from devpi_guardian.plugin import (
    devpiserver_add_parser_options,
    devpiserver_pyramid_configure,
)


class FakeParser:
    def __init__(self):
        self.calls = []

    def addoption(self, *args, **kwargs):
        self.calls.append((args, kwargs))


class FakePyramidConfig:
    def __init__(self):
        self.registry = {}
        self.tweens = []

    def add_tween(self, name, **kwargs):
        self.tweens.append((name, kwargs))


def test_package_exposes_devpi_server_entry_point() -> None:
    matches = [
        entry_point
        for entry_point in metadata.entry_points(group="devpi_server")
        if entry_point.name == "guardian"
    ]

    assert len(matches) == 1
    assert matches[0].value == "devpi_guardian.plugin"


def test_plugin_hooks_are_marked_for_devpiserver() -> None:
    from devpi_guardian import plugin

    assert "devpiserver_impl" in plugin.devpiserver_add_parser_options.__dict__
    assert "devpiserver_impl" in plugin.devpiserver_pyramid_configure.__dict__


def test_parser_exposes_guardian_db_option() -> None:
    parser = FakeParser()
    help_text = "path to the persistent devpi-guardian SQLite database"

    devpiserver_add_parser_options(parser)

    assert parser.calls == [
        (
            ("--guardian-db",),
            {
                "action": "store",
                "dest": "guardian_db",
                "default": None,
                "help": help_text,
            },
        )
    ]


def test_pyramid_hook_migrates_and_registers_reader_and_tween(
    tmp_path,
) -> None:
    pyramid = FakePyramidConfig()
    config = SimpleNamespace(
        args=SimpleNamespace(guardian_db=str(tmp_path / "guardian.db")),
        server_path=Path(tmp_path / "server"),
    )

    devpiserver_pyramid_configure(config, pyramid)

    assert VERDICT_READER_REGISTRY_KEY in pyramid.registry
    metrics = pyramid.registry[BLOCK_METRIC_REGISTRY_KEY]
    assert isinstance(metrics, InMemoryBlockMetricRecorder)
    assert metrics.snapshot() == {}
    tween_prefix = "devpi_guardian.enforcement.tween."
    tween_suffix = "guardian_enforcement_tween_factory"
    tween_name = tween_prefix + tween_suffix
    assert pyramid.tweens == [
        (
            tween_name,
            {"under": "devpi_server.views.tween_keyfs_transaction"},
        )
    ]
    assert (tmp_path / "guardian.db").exists()
    with sqlite3.connect(tmp_path / "guardian.db") as connection:
        migration_query = "SELECT version FROM schema_migrations"
        assert connection.execute(migration_query).fetchone() == (1,)
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'artifacts'"
        ).fetchone() == (1,)


def test_pyramid_hook_uses_deterministic_default_path(tmp_path) -> None:
    pyramid = FakePyramidConfig()
    config = SimpleNamespace(
        args=SimpleNamespace(guardian_db=None),
        server_path=tmp_path / "server",
    )

    devpiserver_pyramid_configure(config, pyramid)

    assert (tmp_path / "server" / "guardian" / "guardian.db").exists()


def test_migration_failure_has_no_registry_or_tween_side_effects(
    tmp_path,
    monkeypatch,
) -> None:
    pyramid = FakePyramidConfig()
    config = SimpleNamespace(
        args=SimpleNamespace(guardian_db=str(tmp_path / "guardian.db")),
        server_path=tmp_path / "server",
    )

    def fail_migration(factory):
        raise RuntimeError("migration failed")

    monkeypatch.setattr("devpi_guardian.plugin.migrate", fail_migration)

    with pytest.raises(RuntimeError, match="migration failed"):
        devpiserver_pyramid_configure(config, pyramid)

    assert pyramid.registry == {}
    assert pyramid.tweens == []


def test_real_devpi_plugin_manager_recognizes_guardian_hooks() -> None:
    from devpi_server.config import get_pluginmanager

    plugin_manager = get_pluginmanager()
    guardian_plugins = []
    for entry in plugin_manager.list_name_plugin():
        if entry[0] == "guardian":
            guardian_plugins.append(entry)

    assert len(guardian_plugins) == 1
    assert plugin_manager.hook.devpiserver_add_parser_options.get_hookimpls()
    assert plugin_manager.hook.devpiserver_pyramid_configure.get_hookimpls()
