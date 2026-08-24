# Project Ruff and upstream devpi intentionally use conflicting import layouts.
# Keep devpi's no-section, from-first style in this integration-facing test.
# ruff: noqa: I001
from devpi_guardian import plugin
from devpi_guardian.admin.views import ADMIN_SERVICE_REGISTRY_KEY
from devpi_guardian.enforcement.metrics import BLOCK_METRIC_REGISTRY_KEY
from devpi_guardian.enforcement.metrics import InMemoryBlockMetricRecorder
from devpi_guardian.enforcement.tween import VERDICT_READER_REGISTRY_KEY
from devpi_guardian.plugin import devpiserver_add_parser_options
from devpi_guardian.plugin import devpiserver_pyramid_configure
from devpi_guardian.verdicts.errors import StoreUnavailable
from devpi_server.model import BaseStageCustomizer
from devpi_server.model import InvalidIndexconfig
from importlib import metadata
from pathlib import Path
from types import SimpleNamespace
import pytest
import sqlite3


_STAGE_HOOK_NAME = "devpiserver_get_stage_customizer_classes"


class FakeParser:
    def __init__(self):
        self.calls = []

    def addoption(self, *args, **kwargs):
        self.calls.append((args, kwargs))


class FakePyramidConfig:
    def __init__(self):
        self.xom = SimpleNamespace()
        self.registry = {"xom": self.xom}
        self.tweens = []
        self.routes = []
        self.views = []

    def add_tween(self, name, **kwargs):
        self.tweens.append((name, kwargs))

    def add_route(self, name, path):
        self.routes.append((name, path))

    def add_view(self, view, **kwargs):
        self.views.append((view, kwargs))


def test_package_exposes_devpi_server_entry_point() -> None:
    matches = [
        entry_point
        for entry_point in metadata.entry_points(group="devpi_server")
        if entry_point.name == "guardian"
    ]

    assert len(matches) == 1
    assert matches[0].value == "devpi_guardian.plugin"


def test_plugin_hooks_are_marked_for_devpiserver() -> None:
    assert "devpiserver_impl" in plugin.devpiserver_add_parser_options.__dict__
    assert "devpiserver_impl" in plugin.devpiserver_pyramid_configure.__dict__
    stage_hook = getattr(plugin, _STAGE_HOOK_NAME, None)
    assert callable(stage_hook)
    assert "devpiserver_impl" in stage_hook.__dict__


def test_stage_customizer_hook_registers_guardian_exactly_once() -> None:
    stage_hook = getattr(plugin, _STAGE_HOOK_NAME, None)

    assert callable(stage_hook)
    registrations = stage_hook()
    assert len(registrations) == 1
    index_type, guardian_stage = registrations[0]
    assert index_type == "guardian"
    assert isinstance(guardian_stage, type)


@pytest.mark.parametrize("index_config", [{}, {"bases": []}])
def test_guardian_stage_requires_at_least_one_base(index_config) -> None:
    from devpi_server.config import get_pluginmanager
    from devpi_server.model import get_stage_customizer_class

    plugin_manager = get_pluginmanager()
    xom = SimpleNamespace(config=SimpleNamespace(hook=plugin_manager.hook))
    stage_hook = getattr(plugin, _STAGE_HOOK_NAME, None)

    assert callable(stage_hook)
    [(index_type, guardian_stage)] = stage_hook()
    assert index_type == "guardian"
    assert not issubclass(guardian_stage, BaseStageCustomizer)
    resolved_class = get_stage_customizer_class(xom, "guardian")
    assert resolved_class is not guardian_stage
    assert issubclass(resolved_class, BaseStageCustomizer)

    customizer = resolved_class(SimpleNamespace(xom=xom))
    assert customizer.readonly is True
    with pytest.raises(InvalidIndexconfig):
        customizer.validate_config({}, index_config)


def test_guardian_stage_accepts_a_valid_base() -> None:
    from devpi_server.config import get_pluginmanager
    from devpi_server.model import get_stage_customizer_class

    plugin_manager = get_pluginmanager()
    xom = SimpleNamespace(config=SimpleNamespace(hook=plugin_manager.hook))
    stage_hook = getattr(plugin, _STAGE_HOOK_NAME, None)

    assert callable(stage_hook)
    [(index_type, _guardian_stage)] = stage_hook()
    assert index_type == "guardian"
    resolved_class = get_stage_customizer_class(xom, "guardian")
    customizer = resolved_class(SimpleNamespace(xom=xom))

    assert customizer.validate_config({}, {"bases": ["root/pypi"]}) is None


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
    monkeypatch,
) -> None:
    pyramid = FakePyramidConfig()
    config = SimpleNamespace(
        args=SimpleNamespace(guardian_db=str(tmp_path / "guardian.db")),
        server_path=Path(tmp_path / "server"),
    )
    real_reader_class = plugin.SQLiteVerdictReader
    created_readers = []

    def create_reader(factory):
        reader = real_reader_class(factory)
        created_readers.append(reader)
        return reader

    monkeypatch.setattr(plugin, "SQLiteVerdictReader", create_reader)

    devpiserver_pyramid_configure(config, pyramid)

    assert len(created_readers) == 1
    assert VERDICT_READER_REGISTRY_KEY in pyramid.registry
    reader = pyramid.registry[VERDICT_READER_REGISTRY_KEY]
    xom_reader = getattr(
        pyramid.xom,
        "_devpi_guardian_verdict_reader",
        None,
    )
    assert xom_reader is reader
    reader_accessor = getattr(plugin, "get_verdict_reader", None)
    assert callable(reader_accessor)
    assert reader_accessor(pyramid.xom) is reader
    metrics = pyramid.registry[BLOCK_METRIC_REGISTRY_KEY]
    assert isinstance(metrics, InMemoryBlockMetricRecorder)
    assert metrics.snapshot() == {}
    assert pyramid.registry[ADMIN_SERVICE_REGISTRY_KEY].health() == {
        "database": "ok",
        "schema_version": 3,
        "mutations_ready": False,
    }
    assert len(pyramid.routes) == 7
    assert len(pyramid.views) == 7
    assert all(options["permission"] == "user_modify" for _, options in pyramid.views)
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
        migration_query = "SELECT MAX(version) FROM schema_migrations"
        assert connection.execute(migration_query).fetchone() == (3,)
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

    def fail_migration(_factory):
        raise RuntimeError("migration failed")

    monkeypatch.setattr("devpi_guardian.plugin.migrate", fail_migration)

    with pytest.raises(RuntimeError, match="migration failed"):
        devpiserver_pyramid_configure(config, pyramid)

    assert pyramid.registry == {"xom": pyramid.xom}
    assert not hasattr(pyramid.xom, "_devpi_guardian_verdict_reader")
    assert pyramid.tweens == []


def test_reader_accessor_fails_without_lazy_initialization(
    monkeypatch,
) -> None:
    reader_accessor = getattr(plugin, "get_verdict_reader", None)
    assert callable(reader_accessor)
    xom = SimpleNamespace()

    def unexpected_call(*_args, **_kwargs):
        message = "reader access must not create or migrate the verdict store"
        pytest.fail(message)

    monkeypatch.setattr(plugin, "ConnectionFactory", unexpected_call)
    monkeypatch.setattr(plugin, "SQLiteVerdictReader", unexpected_call)
    monkeypatch.setattr(plugin, "migrate", unexpected_call)

    with pytest.raises(StoreUnavailable):
        reader_accessor(xom)
    assert not hasattr(xom, "_devpi_guardian_verdict_reader")


def test_real_devpi_plugin_manager_recognizes_guardian_hooks() -> None:
    from devpi_server.config import get_pluginmanager

    plugin_manager = get_pluginmanager()
    entries = plugin_manager.list_name_plugin()
    guardian_plugins = [entry for entry in entries if entry[0] == "guardian"]

    assert len(guardian_plugins) == 1
    assert plugin_manager.hook.devpiserver_add_parser_options.get_hookimpls()
    assert plugin_manager.hook.devpiserver_pyramid_configure.get_hookimpls()
    hooks = plugin_manager.hook
    customizer_lists = hooks.devpiserver_get_stage_customizer_classes()
    registered_guardians = [
        customizer
        for customizers in customizer_lists
        for index_type, customizer in customizers
        if index_type == "guardian"
    ]
    assert len(registered_guardians) == 1
    stage_hook = getattr(plugin, _STAGE_HOOK_NAME, None)
    assert callable(stage_hook)
    [(_, guardian_stage)] = stage_hook()
    assert registered_guardians[0] is guardian_stage


def test_readme_documents_f6_allowed_release_lookup_contract() -> None:
    readme = Path(__file__).parents[1].joinpath("README.md").read_text()
    f6_section = readme.split("F6 consumers can obtain", 1)[1]
    f6_section = f6_section.split("F5 does not receive", 1)[0]
    f6_section = " ".join(f6_section.split())

    required_contract = (
        "".join(
            (
                "from devpi_guardian.enforcement.tween import ",
                "VERDICT_READER_REGISTRY_KEY",
            )
        ),
        "list_allowed_releases(project: str) -> tuple[AllowedRelease, ...]",
        "release.project",
        "PEP 503-normalized",
        "every stage by canonical project",
        "stage/version/filename/sha256/origin_url",
        "no results is `()`",
        "unexpired current manual override wins",
        "manual DENY excludes",
        "manual ALLOW includes",
        "expires_at <= evaluation time is ignored",
        "only automated ALLOW includes",
        "origin_url` is an absolute URL, not a local filesystem path",
        "".join(
            (
                "removes userinfo, query, and fragment, but does not ",
                "constrain ",
                "the stored scheme",
            )
        ),
        "F5 MUST record the canonical devpi HTTP(S) `+f`/`+e` artifact URL",
        "".join(
            (
                "F6 MUST issue HTTP(S) through canonical devpi `+f`/`+e` and ",
                "Guardian enforcement",
            )
        ),
        "never use `origin_url` as a trust bypass or local open",
        "F4 does not fetch the URL or independently rehash its contents",
    )
    for phrase in required_contract:
        assert phrase in f6_section


def test_readme_documents_verdict_baseline_tier_contract() -> None:
    readme = Path(__file__).parents[1].joinpath("README.md").read_text()
    f10_marker = "F10 supplies the exact current DTO fields"
    _, opening, remainder = readme.partition(f10_marker)
    assert opening
    f10_section, closing, _ = remainder.partition("Manual transitions")
    assert closing
    f10_section = " ".join(f10_section.split())

    for phrase in (
        'Literal["same_tag", "universal_wheel", "sdist"]',
        "baseline_sha256 and baseline_tier must both be set or both be None",
        "baseline_tier=None",
        "sdist comparisons have lower confidence",
    ):
        assert phrase in f10_section
