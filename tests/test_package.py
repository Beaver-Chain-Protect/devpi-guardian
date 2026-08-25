# Project Ruff and upstream devpi intentionally use conflicting import layouts.
# Keep devpi's no-section, from-first style in this integration-facing test.
# ruff: noqa: I001
from devpi_guardian import plugin
from devpi_guardian.enforcement.metrics import BLOCK_METRIC_REGISTRY_KEY
from devpi_guardian.enforcement.metrics import InMemoryBlockMetricRecorder
from devpi_guardian.enforcement.tween import VERDICT_READER_REGISTRY_KEY
from devpi_guardian.plugin import devpiserver_add_parser_options
from devpi_guardian.plugin import devpiserver_pyramid_configure
from devpi_guardian.verdicts.errors import StoreUnavailable
from devpi_server.model import BaseStageCustomizer
from devpi_server.model import InvalidIndexconfig
from importlib import metadata
from importlib import resources
from pathlib import Path
from packaging.requirements import Requirement
from types import SimpleNamespace
import pytest
from devpi_server.main import Fatal
import sqlite3


_STAGE_HOOK_NAME = "devpiserver_get_stage_customizer_classes"


class FakeParser:
    def __init__(self):
        self.calls = []

    def addoption(self, *args, **kwargs):
        self.calls.append((args, kwargs))


class FakePyramidConfig:
    def __init__(self, xom=None):
        self.xom = SimpleNamespace() if xom is None else xom
        self.registry = {"xom": self.xom}
        self.tweens = []

    def add_tween(self, name, **kwargs):
        self.tweens.append((name, kwargs))


def _config(tmp_path, *, guardian_db=None):
    if guardian_db is None:
        guardian_db = tmp_path / "guardian.db"
    return SimpleNamespace(
        args=SimpleNamespace(
            guardian_db=str(guardian_db),
        ),
        nodeinfo={"uuid": "devpi-test-uuid"},
        server_path=Path(tmp_path / "server"),
    )


def test_package_exposes_devpi_server_entry_point() -> None:
    matches = [
        entry_point
        for entry_point in metadata.entry_points(group="devpi_server")
        if entry_point.name == "guardian"
    ]

    assert len(matches) == 1
    assert matches[0].value == "devpi_guardian.plugin"


def test_package_exposes_guardian_admin_console_script() -> None:
    matches = [
        entry_point
        for entry_point in metadata.entry_points(group="console_scripts")
        if entry_point.name == "guardian"
    ]

    assert len(matches) == 1
    assert matches[0].value == "devpi_guardian.admin.cli:main"


def test_package_declares_requests_as_direct_runtime_dependency() -> None:
    requirements = [Requirement(value) for value in metadata.requires("devpi-guardian") or []]

    assert any(
        requirement.name == "requests"
        and requirement.marker is None
        and str(requirement.specifier) == "<3,>=2.32"
        for requirement in requirements
    )


def test_package_contains_exact_guardian_sql_migrations() -> None:
    migration_names = sorted(
        resource.name
        for resource in resources.files("devpi_guardian.verdicts.sql").iterdir()
        if resource.name.endswith(".sql")
    )
    assert migration_names == [
        "001_initial.sql",
        "002_baseline_tier.sql",
        "003_guardian_activation.sql",
        "004_artifact_cooldown.sql",
        "005_audit_events.sql",
        "006_baseline_overrides.sql",
    ]


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
    config = _config(tmp_path)
    monkeypatch.setattr(
        "devpi_guardian.plugin.find_existing_artifact_candidate",
        lambda xom: None,
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
        assert connection.execute(migration_query).fetchone() == (6,)
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'artifacts'"
        ).fetchone() == (1,)


def test_pyramid_hook_uses_deterministic_default_path(
    tmp_path,
    monkeypatch,
) -> None:
    pyramid = FakePyramidConfig()
    config = SimpleNamespace(
        args=SimpleNamespace(guardian_db=None),
        nodeinfo={"uuid": "devpi-test-uuid"},
        server_path=tmp_path / "server",
    )

    # The default-path test only exercises path selection; no persisted XOM
    # data is present in this unit boundary.
    monkeypatch.setattr(
        "devpi_guardian.plugin.find_existing_artifact_candidate",
        lambda xom: None,
    )
    devpiserver_pyramid_configure(config, pyramid)

    assert (tmp_path / "server" / "guardian" / "guardian.db").exists()


def test_migration_failure_has_no_registry_or_tween_side_effects(
    tmp_path,
    monkeypatch,
) -> None:
    pyramid = FakePyramidConfig()
    config = _config(tmp_path)

    def fail_migration(_factory):
        raise RuntimeError("migration failed")

    monkeypatch.setattr("devpi_guardian.plugin.migrate", fail_migration)

    with pytest.raises(RuntimeError, match="migration failed"):
        devpiserver_pyramid_configure(config, pyramid)

    assert pyramid.registry == {"xom": pyramid.xom}
    assert not hasattr(pyramid.xom, "_devpi_guardian_verdict_reader")
    assert pyramid.tweens == []


def test_pyramid_hook_runs_activation_before_registry_side_effects(
    tmp_path,
    monkeypatch,
) -> None:
    events = []
    pyramid = FakePyramidConfig()
    config = _config(tmp_path)

    monkeypatch.setattr(
        "devpi_guardian.plugin.migrate",
        lambda factory: events.append("migrate"),
    )

    def activate(factory, devpi_uuid, find_candidate, *, now):
        assert devpi_uuid == "devpi-test-uuid"
        events.append("activation")
        assert find_candidate() is None
        return True

    monkeypatch.setattr(
        "devpi_guardian.plugin.ensure_guardian_activation",
        activate,
    )
    monkeypatch.setattr(
        "devpi_guardian.plugin.find_existing_artifact_candidate",
        lambda xom: events.append("inventory") or None,
    )

    class Reader:
        def __init__(self, factory):
            events.append("reader")

    class Metrics:
        def __init__(self):
            events.append("metrics")

    monkeypatch.setattr("devpi_guardian.plugin.SQLiteVerdictReader", Reader)
    monkeypatch.setattr(
        "devpi_guardian.plugin.InMemoryBlockMetricRecorder",
        Metrics,
    )

    original_add_tween = pyramid.add_tween

    def add_tween(name, **kwargs):
        events.append("tween")
        original_add_tween(name, **kwargs)

    pyramid.add_tween = add_tween

    class Registry(dict):
        def __setitem__(self, key, value):
            if key == VERDICT_READER_REGISTRY_KEY:
                registry_event = "registry-reader"
            else:
                registry_event = "registry-metrics"
            events.append(registry_event)
            super().__setitem__(key, value)

    pyramid.registry = Registry(pyramid.registry)

    devpiserver_pyramid_configure(config, pyramid)

    assert events == [
        "migrate",
        "activation",
        "inventory",
        "reader",
        "metrics",
        "registry-reader",
        "registry-metrics",
        "tween",
    ]


@pytest.mark.parametrize(
    "category",
    [
        "existing_artifacts",
        "uuid_mismatch",
        "store_unavailable",
    ],
)
def test_activation_failures_are_fatal_before_registry_mutation(
    tmp_path,
    monkeypatch,
    category,
) -> None:
    from devpi_guardian.activation import (
        ActivationFailureCategory,
        GuardianActivationError,
    )

    pyramid = FakePyramidConfig()
    config = _config(tmp_path)
    monkeypatch.setattr("devpi_guardian.plugin.migrate", lambda factory: None)

    def activate(factory, devpi_uuid, find_candidate, *, now):
        raise GuardianActivationError(ActivationFailureCategory(category))

    monkeypatch.setattr(
        "devpi_guardian.plugin.ensure_guardian_activation",
        activate,
    )

    with pytest.raises(Fatal) as error:
        devpiserver_pyramid_configure(config, pyramid)

    assert str(error.value) == f"guardian activation failed: {category}"
    assert pyramid.registry == {"xom": pyramid.xom}
    assert pyramid.tweens == []


def test_non_guardian_startup_exception_is_not_downgraded(
    tmp_path,
    monkeypatch,
) -> None:
    pyramid = FakePyramidConfig()
    config = _config(tmp_path)
    failure = f"{tmp_path / 'guardian.db'} devpi-test-uuid activation-secret"
    expected = RuntimeError(failure)
    monkeypatch.setattr("devpi_guardian.plugin.migrate", lambda factory: None)

    def activate(factory, devpi_uuid, find_candidate, *, now):
        raise expected

    monkeypatch.setattr(
        "devpi_guardian.plugin.ensure_guardian_activation",
        activate,
    )

    with pytest.raises(RuntimeError) as error:
        devpiserver_pyramid_configure(config, pyramid)

    assert error.value is expected
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


def _assert_exact_ci_workflow(workflow: str) -> None:
    expected_workflow = (
        "\n".join(
            (
                "name: CI",
                "",
                "on:",
                "  pull_request:",
                "  push:",
                "    branches: [main]",
                "",
                "permissions:",
                "  contents: read",
                "",
                "concurrency:",
                "  group: ci-${{ github.workflow }}-${{ github.ref }}",
                "  cancel-in-progress: true",
                "",
                "jobs:",
                "  tests:",
                "    name: tests (Python ${{ matrix.python-version }})",
                "    runs-on: ubuntu-latest",
                "    strategy:",
                "      fail-fast: false",
                "      matrix:",
                '        python-version: ["3.11", "3.12", "3.13", "3.14"]',
                "    steps:",
                "".join(
                    (
                        "      - uses: actions/checkout@",
                        "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
                    )
                ),
                "".join(
                    (
                        "      - uses: astral-sh/setup-uv@",
                        "20cfd1bf945f4377ade1205e4dbc17946fc9a30d # v10.0.1",
                    )
                ),
                "        with:",
                "          python-version: ${{ matrix.python-version }}",
                "          enable-cache: true",
                "      - run: uv sync --locked --extra test",
                "      - run: uv run pytest -v",
                "",
                "  quality:",
                "    name: quality (Python 3.11)",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "".join(
                    (
                        "      - uses: actions/checkout@",
                        "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
                    )
                ),
                "".join(
                    (
                        "      - uses: astral-sh/setup-uv@",
                        "20cfd1bf945f4377ade1205e4dbc17946fc9a30d # v10.0.1",
                    )
                ),
                "        with:",
                '          python-version: "3.11"',
                "          enable-cache: true",
                "      - run: uv sync --locked --extra test",
                "      - run: uv run ruff format --check .",
                "      - run: uv run ruff check .",
                "      - run: uv run flake8 src tests",
                "      - run: uv run python -m build",
            )
        )
        + "\n"
    )
    assert workflow == expected_workflow
    for forbidden in (
        "pull-requests:",
        "contents: write",
        "continue-on-error",
        "pytest -m",
        "pytest -k",
        "pytest -m=",
        "pytest -k=",
        "--ignore",
        "pytest tests/",
    ):
        assert forbidden not in workflow


def test_ci_covers_supported_python_and_quality_gates() -> None:
    repo_root = Path(__file__).parents[1]
    workflow_path = repo_root.joinpath(".github/workflows/ci.yml")
    workflow = workflow_path.read_text(encoding="utf-8")
    _assert_exact_ci_workflow(workflow)


def test_ci_contract_rejects_narrowed_or_mutated_workflow() -> None:
    repo_root = Path(__file__).parents[1]
    workflow_path = repo_root.joinpath(".github/workflows/ci.yml")
    workflow = workflow_path.read_text(encoding="utf-8")
    narrowed_command = "uv run pytest tests/test_package.py -v"
    narrowed = workflow.replace("uv run pytest -v", narrowed_command)

    with pytest.raises(AssertionError):
        _assert_exact_ci_workflow(narrowed)


def test_readme_documents_new_install_activation_boundary() -> None:
    repo_root = Path(__file__).parents[1]
    readme_path = repo_root.joinpath("README.md")
    readme = readme_path.read_text(encoding="utf-8")
    activation_marker = "## New-install activation boundary"
    _, opening, remainder = readme.partition(activation_marker)
    assert opening
    activation_section, closing, _ = remainder.partition("## F5 quarantine")
    assert closing
    activation_section = " ".join(activation_section.split())

    for phrase in (
        "new Guardian deployments only",
        "guardian_activation",
        "devpi_uuid",
        "first activation marker",
        "existing_artifacts",
        "any existing private or root-pypi Artifact candidate",
        "DB loss",
        "restored devpi",
        "no online/public network inventory",
        "Migration/backfill is deferred and not supported in PR1",
        "no compatibility bypass",
        "Operational preflight",
        "backup",
        "rollback",
        "fail-closed",
    ):
        assert phrase in activation_section


def test_readme_documents_f5_quarantine_contract() -> None:
    repo_root = Path(__file__).parents[1]
    readme_path = repo_root.joinpath("README.md")
    readme = readme_path.read_text(encoding="utf-8")
    _, opening, remainder = readme.partition("## F5 quarantine")
    assert opening
    error_mapping_marker = "## Error mapping for API callers"
    quarantine_section, closing, _ = remainder.partition(error_mapping_marker)
    assert closing
    quarantine_section = " ".join(quarantine_section.split())

    for phrase in (
        "GUARDIAN_QUARANTINE_DIR",
        "".join(
            (
                "absolute dedicated permission-restricted path outside ",
                "public devpi ",
                "storage/routes",
            )
        ),
        "objects/sha256/<first-2>/<next-2>/<sha256>",
        "Unapproved bytes never live in SQLite or",
        "public `+f`/`+e` for unapproved worker input",
        "same filesystem",
        "Publish-before-discover ordering",
        "atomic no-overwrite publish",
        "duplicate digest byte identity",
        "no-symlink/no traversal",
        "same-open-file digest verification",
        "only then parses",
        "Mismatch/missing/I/O/symlink failures are fail-closed",
        "F5 alone reads unapproved bytes from this path",
        "F6 still uses HTTP(S) canonical +f/+e after ALLOW",
        "no worker/public route bypass token",
        "cleanup/retention contract",
        "verified FileEntry read stream",
        "mirror discovery connector",
        "upstream hash",
        "origin_url",
        "never fetch",
        "local path",
        "ClaimedArtifact",
        "sha256",
        "size_bytes",
        "exclusive",
        "expected owner/mode",
        "openat",
        "O_NOFOLLOW",
        "fstat",
        "rewind the descriptor",
        "kept open for analysis",
        "fenced claim",
        "mark_analysis_error()",
        "no verdict",
    ):
        assert phrase in quarantine_section
