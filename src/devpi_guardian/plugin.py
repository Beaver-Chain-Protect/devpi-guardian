"""devpi-server hooks with activation-first Guardian composition."""

from __future__ import annotations

import math
import os
import socket
import stat
from contextlib import suppress
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests
from devpi_server.main import Fatal
from pluggy import HookimplMarker
from pyramid.httpexceptions import HTTPServiceUnavailable
from pyramid.interfaces import IRoutesMapper, ITweens

from . import __version__
from .activation import GuardianActivationError, ensure_guardian_activation
from .admin.providers import ProductionAdminProviders
from .admin.service import GuardianAdminService
from .admin.views import ADMIN_SERVICE_REGISTRY_KEY, configure_admin_routes
from .audit import SQLiteAuditWriter, verify_audit_chain
from .enforcement.metrics import BLOCK_METRIC_REGISTRY_KEY, InMemoryBlockMetricRecorder
from .enforcement.tween import VERDICT_READER_REGISTRY_KEY
from .legacy_inventory import find_existing_artifact_candidate
from .policy import PolicyEngine
from .verdicts.db import ConnectionFactory, migrate
from .verdicts.errors import InvalidSha256, StoreUnavailable
from .verdicts.models import DecisionSource, validate_sha256
from .verdicts.reader import SQLiteVerdictReader
from .verdicts.store import SQLiteArtifactStore
from .worker.devpi_paths import DevpiBase, DevpiRouteError
from .worker.discovery import (
    DiscoveryCandidate,
    DiscoveryUnavailable,
    FileDiscoverySink,
    get_discovery_sink,
    set_discovery_sink,
)
from .worker.quarantine import QuarantineStore
from .worker.runtime import GuardianWorkerThread, build_worker_thread
from .worker.upload import PrivateUploadConnector

server_hookimpl = HookimplMarker("devpiserver")
_VERDICT_READER_XOM_ATTRIBUTE = "_devpi_guardian_verdict_reader"
_UPLOAD_CONNECTOR_XOM_ATTRIBUTE = "_devpi_guardian_upload_connector"


class GuardianStage:
    readonly = True

    def validate_config(self, _oldconfig, newconfig) -> None:
        if not newconfig.get("bases"):
            raise self.InvalidIndexconfig("guardian index requires a base")

    def get_simple_links_filter_iter(self, project, links):
        link_snapshot = []
        link_sha256s = []
        for link in links:
            link_snapshot.append(link)
            try:
                sha256 = validate_sha256(link.hashes.get("sha256"))
            except InvalidSha256:
                sha256 = None
            link_sha256s.append(sha256)
        requested = [sha256 for sha256 in link_sha256s if sha256 is not None]
        if not requested:
            return iter(False for _ in link_sha256s)
        try:
            reader = get_verdict_reader(self.stage.xom)
            decisions = reader.get_effective_decisions(requested)
        except StoreUnavailable as exc:
            unavailable = HTTPServiceUnavailable(headers={"Retry-After": "5"})
            raise unavailable from exc
        missing = []
        project_name = project if type(project) is str else None
        for link, sha256 in zip(link_snapshot, link_sha256s, strict=True):
            decision = decisions.get(sha256) if sha256 is not None else None
            if (
                project_name is None
                or getattr(decision, "source", None) is not DecisionSource.MISSING
            ):
                continue
            missing.append(
                DiscoveryCandidate(
                    stage=str(getattr(self.stage, "name", "guardian")),
                    project=project_name,
                    filename=str(link.basename),
                    sha256=sha256,
                    link_href=str(link.href),
                )
            )
        if missing:
            try:
                get_discovery_sink(self.stage.xom).discover_many(missing)
            except DiscoveryUnavailable as exc:
                unavailable = HTTPServiceUnavailable(headers={"Retry-After": "5"})
                raise unavailable from exc
        return (
            getattr(decisions.get(sha256), "allowed", False) is True
            if sha256 is not None
            else False
            for sha256 in link_sha256s
        )


def get_verdict_reader(xom) -> SQLiteVerdictReader:
    try:
        return getattr(xom, _VERDICT_READER_XOM_ATTRIBUTE)
    except AttributeError as exc:
        raise StoreUnavailable("verdict reader is not initialized") from exc


def get_upload_connector(xom) -> PrivateUploadConnector:
    try:
        return getattr(xom, _UPLOAD_CONNECTOR_XOM_ATTRIBUTE)
    except AttributeError as exc:
        raise RuntimeError("Guardian upload connector is not initialized") from exc


@server_hookimpl
def devpiserver_get_stage_customizer_classes():
    return [("guardian", GuardianStage)]


@server_hookimpl
def devpiserver_add_parser_options(parser) -> None:
    parser.addoption(
        "--guardian-db",
        action="store",
        dest="guardian_db",
        default=None,
        help="path to the persistent devpi-guardian SQLite database",
    )
    parser.addoption(
        "--guardian-quarantine-root",
        action="store",
        dest="guardian_quarantine_root",
        default=None,
        help="absolute path to the private SHA-256 quarantine directory",
    )
    parser.addoption(
        "--guardian-base-url",
        action="store",
        dest="guardian_base_url",
        default=None,
        help="canonical devpi URL used to resolve artifact links",
    )
    parser.addoption(
        "--guardian-cooldown-hours",
        action="store",
        type=float,
        dest="guardian_cooldown_hours",
        default=24.0,
        help="hours an automated ALLOW remains quarantined",
    )
    parser.addoption(
        "--guardian-worker-poll-interval",
        action="store",
        type=float,
        dest="guardian_worker_poll_interval",
        default=0.25,
        help="seconds between idle Guardian worker polls",
    )


@dataclass(frozen=True, slots=True)
class _GuardianSettings:
    db_path: Path
    quarantine_root: Path | None
    base_url: str
    cooldown_duration: timedelta
    poll_interval: float


def _worker_base_url(config) -> str:
    configured = getattr(config.args, "guardian_base_url", None)
    if configured is not None:
        return configured
    outside = getattr(config.args, "outside_url", None)
    if outside is not None:
        return outside
    host = getattr(config.args, "host", "localhost") or "localhost"
    if host in ("0.0.0.0", "::", "*"):
        host = "localhost"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = getattr(config.args, "port", 3141) or 3141
    return f"http://{host}:{port}"


def _is_replica(xom) -> bool:
    check = getattr(xom, "is_replica", None)
    return bool(check()) if callable(check) else False


def _safe_path(path: Path, *, label: str, server_path: Path) -> Path:
    if not path.is_absolute():
        raise Fatal(f"{label} must be an absolute path")
    if any(part in (".", "..") for part in path.parts):
        raise Fatal(f"{label} must use canonical path components")
    canonical_server = server_path.resolve(strict=False)
    canonical_path = path.resolve(strict=False)
    if canonical_path == canonical_server or canonical_path.is_relative_to(canonical_server):
        raise Fatal(f"{label} must be outside the devpi server directory")
    if path.is_symlink():
        raise Fatal(f"{label} must not be a symlink")
    for parent in (path, *path.parents):
        if parent == Path("/"):
            break
        if parent.is_symlink():
            raise Fatal(f"{label} must not contain symlinked components")
    if not path.exists() or not path.is_dir():
        raise Fatal(f"{label} must already exist as a directory")
    try:
        stat_result = path.stat()
    except OSError as exc:
        raise Fatal(f"{label} cannot be inspected") from exc
    if stat_result.st_uid != os.geteuid():
        raise Fatal(f"{label} owner is unsafe")
    mode = stat_result.st_mode & 0o777
    if mode != 0o700:
        raise Fatal(f"{label} mode must be 0700")
    for parent in path.parents:
        if parent == Path("/"):
            break
        try:
            parent_stat = parent.stat()
        except OSError as exc:
            raise Fatal(f"{label} parent cannot be inspected") from exc
        owner = parent_stat.st_uid
        if owner not in (0, os.geteuid()):
            raise Fatal(f"{label} parent owner is unsafe")
        mode = stat.S_IMODE(parent_stat.st_mode)
        # Root-owned sticky system directories (for example /tmp) are the
        # only shared writable ancestors accepted by the boundary.
        if mode & 0o022 and not (owner == 0 and mode & stat.S_ISVTX):
            raise Fatal(f"{label} parent mode is unsafe")
    return path


def _validate_settings(config, xom) -> _GuardianSettings:
    configured_db = getattr(config.args, "guardian_db", None)
    db_path = (
        Path(configured_db)
        if configured_db is not None
        else Path(config.server_path) / "guardian" / "guardian.db"
    )
    if not db_path.is_absolute():
        raise Fatal("guardian database path must be absolute")
    server_path = Path(config.server_path).absolute()
    primary = not _is_replica(xom)
    configured_root = getattr(config.args, "guardian_quarantine_root", None)
    quarantine_root = None
    if primary:
        if configured_root is None:
            raise Fatal("guardian quarantine root is required for a primary")
        quarantine_root = _safe_path(
            Path(configured_root), label="guardian quarantine root", server_path=server_path
        )
    base_url = _worker_base_url(config)
    try:
        DevpiBase.parse(base_url)
    except DevpiRouteError as exc:
        raise Fatal("guardian base URL must be a canonical HTTP(S) URL") from exc
    cooldown_hours = getattr(config.args, "guardian_cooldown_hours", 24.0)
    poll_interval = getattr(config.args, "guardian_worker_poll_interval", 0.25)
    if (
        not isinstance(cooldown_hours, (int, float))
        or not math.isfinite(cooldown_hours)
        or cooldown_hours <= 0
    ):
        raise Fatal("guardian cooldown hours must be positive")
    if (
        not isinstance(poll_interval, (int, float))
        or not math.isfinite(poll_interval)
        or poll_interval <= 0
    ):
        raise Fatal("guardian worker poll interval must be positive")
    try:
        cooldown = timedelta(hours=float(cooldown_hours))
    except (OverflowError, ValueError) as exc:
        raise Fatal("guardian cooldown hours are invalid") from exc
    return _GuardianSettings(db_path, quarantine_root, base_url, cooldown, float(poll_interval))


@dataclass(slots=True)
class _Components:
    reader: SQLiteVerdictReader
    store: SQLiteArtifactStore
    queue: FileDiscoverySink
    block_metrics: InMemoryBlockMetricRecorder
    admin_service: GuardianAdminService
    providers: ProductionAdminProviders
    worker: GuardianWorkerThread | None
    upload_connector: PrivateUploadConnector | None
    session: requests.Session | None
    quarantine: QuarantineStore | None


@dataclass(slots=True)
class _PyramidState:
    registry_values: dict
    utility_registrations: dict
    adapter_registrations: dict
    mutable_utilities: tuple
    introspector_categories: dict
    introspector_refs: dict
    introspector_counter: int


def _snapshot_pyramid_state(pyramid_config) -> _PyramidState:
    registry = pyramid_config.registry
    mutable_utilities = []
    for interface in (IRoutesMapper, ITweens):
        utility = registry.queryUtility(interface)
        if utility is not None:
            mutable_utilities.append((utility, deepcopy(vars(utility))))
    introspector = pyramid_config.introspector
    return _PyramidState(
        registry_values=dict(registry),
        utility_registrations=dict(registry._utility_registrations),
        adapter_registrations=dict(registry._adapter_registrations),
        mutable_utilities=tuple(mutable_utilities),
        introspector_categories={
            category: dict(entries) for category, entries in introspector._categories.items()
        },
        introspector_refs=dict(introspector._refs),
        introspector_counter=introspector._counter,
    )


def _restore_pyramid_state(pyramid_config, snapshot: _PyramidState) -> None:
    registry = pyramid_config.registry
    registry.clear()
    registry.update(snapshot.registry_values)

    for key, _registration in list(registry._utility_registrations.items()):
        if key not in snapshot.utility_registrations:
            provided, name = key
            registry.unregisterUtility(provided=provided, name=name)
    for key, registration in snapshot.utility_registrations.items():
        if registry._utility_registrations.get(key) != registration:
            provided, name = key
            if key in registry._utility_registrations:
                registry.unregisterUtility(provided=provided, name=name)
            component, info, factory = registration
            registry.registerUtility(
                component, provided=provided, name=name, info=info, factory=factory
            )

    for key in list(registry._adapter_registrations):
        if key not in snapshot.adapter_registrations:
            required, provided, name = key
            registry.unregisterAdapter(required=required, provided=provided, name=name)
    for key, registration in snapshot.adapter_registrations.items():
        if registry._adapter_registrations.get(key) != registration:
            required, provided, name = key
            if key in registry._adapter_registrations:
                registry.unregisterAdapter(required=required, provided=provided, name=name)
            factory, info = registration
            registry.registerAdapter(
                factory, required=required, provided=provided, name=name, info=info
            )

    for utility, state in snapshot.mutable_utilities:
        utility.__dict__.clear()
        utility.__dict__.update(deepcopy(state))
    registry._clear_view_lookup_cache()

    introspector = pyramid_config.introspector
    introspector._categories = {
        category: dict(entries) for category, entries in snapshot.introspector_categories.items()
    }
    introspector._refs = dict(snapshot.introspector_refs)
    introspector._counter = snapshot.introspector_counter


def _close_components_resources(components: _Components, primary: BaseException) -> None:
    for resource in (components.session, components.quarantine):
        close = getattr(resource, "close", None)
        if callable(close):
            try:
                close()
            except BaseException as cleanup:
                primary.add_note(
                    f"Guardian resource cleanup failed: {type(cleanup).__name__}: {cleanup}"
                )


def _build_components(
    settings: _GuardianSettings,
    factory: ConnectionFactory,
    xom,
    *,
    activation=None,
) -> _Components:
    primary = not _is_replica(xom)
    session = None
    quarantine = None
    worker = None
    upload_connector = None
    worker_build_started = False
    worker_build_complete = False
    try:
        if primary:
            assert settings.quarantine_root is not None
            quarantine = QuarantineStore(
                settings.quarantine_root,
                max_size_bytes=1_000_000_000,
                initialize=activation is None,
            )
            if activation is not None:
                activation()
                quarantine.initialize()
        elif activation is not None:
            activation()
        # Activation is the publication boundary: component construction
        # below may create SQLite files and other durable state.
        audit_writer = SQLiteAuditWriter()
        store = SQLiteArtifactStore(factory, audit_writer)
        reader = SQLiteVerdictReader(factory)
        queue = FileDiscoverySink(settings.db_path.parent / "discovery")
        policy = PolicyEngine()
        metrics = InMemoryBlockMetricRecorder()
        if primary:
            session = requests.Session()
            session.headers["User-Agent"] = f"devpi-guardian/{__version__}"
            worker_build_started = True
            worker = build_worker_thread(
                xom=xom,
                store=store,
                reader=reader,
                policy_engine=policy,
                baseline_http_session=session,
                base_url=settings.base_url,
                quarantine=quarantine,
                discovery_queue=queue,
                analyzer_version=__version__,
                worker_id=f"{socket.gethostname()}-{os.getpid()}",
                cooldown_duration=settings.cooldown_duration,
                poll_interval=settings.poll_interval,
            )
            worker_build_complete = True
            upload_connector = PrivateUploadConnector(
                quarantine=quarantine, store=store, base_url=settings.base_url
            )
        providers = ProductionAdminProviders(
            factory=factory,
            reader=reader,
            store=store,
            discovery=queue,
            policy_engine=policy,
            worker=worker,
        )
        admin_service = GuardianAdminService(
            reader=reader,
            store=store,
            worker_health_reader=providers,
            audit_reader=providers,
            diff_reader=providers,
            baseline_manager=providers,
            policy_manager=providers,
        )
        return _Components(
            reader,
            store,
            queue,
            metrics,
            admin_service,
            providers,
            worker,
            upload_connector,
            session,
            quarantine,
        )
    except BaseException as primary_error:
        resources = (
            (session, quarantine) if (not worker_build_started or worker_build_complete) else ()
        )
        for resource in resources:
            close = getattr(resource, "close", None)
            if callable(close):
                try:
                    close()
                except BaseException as cleanup:
                    primary_error.add_note(
                        f"Guardian resource cleanup failed: {type(cleanup).__name__}: {cleanup}"
                    )
        raise


def _publish_components(components: _Components, pyramid_config, xom, *, configure=True) -> None:
    thread_pool = getattr(xom, "thread_pool", None)
    if components.worker is not None and thread_pool is None:
        raise Fatal("Guardian primary requires a devpi thread pool")
    registry = pyramid_config.registry
    sentinel = object()
    registry_before = {
        key: registry.get(key, sentinel)
        for key in (
            VERDICT_READER_REGISTRY_KEY,
            BLOCK_METRIC_REGISTRY_KEY,
            ADMIN_SERVICE_REGISTRY_KEY,
        )
    }
    xom_before = {
        name: getattr(xom, name, sentinel)
        for name in (
            _VERDICT_READER_XOM_ATTRIBUTE,
            "_devpi_guardian_discovery_sink",
            _UPLOAD_CONNECTOR_XOM_ATTRIBUTE,
        )
    }
    list_before = {
        name: list(value) for name, value in vars(pyramid_config).items() if isinstance(value, list)
    }
    try:
        set_discovery_sink(xom, components.queue)
        setattr(xom, _VERDICT_READER_XOM_ATTRIBUTE, components.reader)
        if components.upload_connector is not None:
            setattr(xom, _UPLOAD_CONNECTOR_XOM_ATTRIBUTE, components.upload_connector)
        registry[VERDICT_READER_REGISTRY_KEY] = components.reader
        registry[BLOCK_METRIC_REGISTRY_KEY] = components.block_metrics
        registry[ADMIN_SERVICE_REGISTRY_KEY] = components.admin_service
        if configure:
            configure_admin_routes(pyramid_config)
            pyramid_config.add_tween(
                "devpi_guardian.enforcement.tween.guardian_enforcement_tween_factory",
                under="devpi_server.views.tween_keyfs_transaction",
            )
        if components.worker is not None:
            thread_pool.register(components.worker)
    except BaseException:
        for key, value in registry_before.items():
            if value is sentinel:
                registry.pop(key, None)
            else:
                registry[key] = value
        for name, value in xom_before.items():
            if value is sentinel:
                with suppress(AttributeError):
                    delattr(xom, name)
            else:
                setattr(xom, name, value)
        for name, values in list_before.items():
            current = getattr(pyramid_config, name, None)
            if isinstance(current, list):
                current[:] = values
        raise


@server_hookimpl
def devpiserver_pyramid_configure(config, pyramid_config) -> None:
    xom = pyramid_config.registry["xom"]
    settings = _validate_settings(config, xom)
    factory = ConnectionFactory(settings.db_path)
    try:
        migrate(factory)
    except Exception as exc:
        raise Fatal("guardian migration failed") from exc
    try:
        verification = verify_audit_chain(factory)
    except Exception as exc:
        raise Fatal("guardian audit chain verification failed") from exc
    if not verification.valid:
        raise Fatal("guardian audit chain verification failed")

    def activate() -> None:
        try:
            ensure_guardian_activation(
                factory,
                config.nodeinfo["uuid"],
                lambda: find_existing_artifact_candidate(xom),
                now=lambda: datetime.now(UTC),
            )
        except GuardianActivationError as exc:
            raise Fatal(str(exc)) from None

    action = getattr(pyramid_config, "action", None)
    if callable(action):
        # Register all route/tween actions first.  Pyramid resolves their
        # conflicts before this final action runs, so a conflict cannot leave
        # a worker registered or Guardian state published.
        pyramid_state = _snapshot_pyramid_state(pyramid_config)
        configure_admin_routes(pyramid_config)
        pyramid_config.add_tween(
            "devpi_guardian.enforcement.tween.guardian_enforcement_tween_factory",
            under="devpi_server.views.tween_keyfs_transaction",
        )

        def publish() -> None:
            components = None
            try:
                components = _build_components(settings, factory, xom, activation=activate)
                _publish_components(components, pyramid_config, xom, configure=False)
            except BaseException as primary:
                if components is not None:
                    _close_components_resources(components, primary)
                try:
                    _restore_pyramid_state(pyramid_config, pyramid_state)
                except BaseException as rollback_error:
                    primary.add_note(
                        "Guardian Pyramid rollback failed: "
                        f"{type(rollback_error).__name__}: {rollback_error}"
                    )
                raise

        action("devpi-guardian-final-publication", callable=publish, order=math.inf)
        return

    # Small fake configurators used by unit tests do not implement Pyramid's
    # deferred action API; preserve their direct, deterministic behavior.
    activate()
    components = _build_components(settings, factory, xom)
    try:
        _publish_components(components, pyramid_config, xom)
    except BaseException as primary:
        _close_components_resources(components, primary)
        raise


@server_hookimpl
def devpiserver_on_upload(stage, project, version, link) -> None:
    xom = stage.xom
    try:
        connector = get_upload_connector(xom)
    except RuntimeError:
        if _is_replica(xom):
            return
        raise
    connector.capture(stage=stage, project=project, version=version, link=link)
