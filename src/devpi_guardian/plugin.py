"""devpi-server hooks with activation-first Guardian composition."""

from __future__ import annotations

import math
import os
import socket
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import requests
from devpi_common.metadata import normalize_name, splitbasename
from devpi_server.main import Fatal
from pluggy import HookimplMarker
from pyramid.httpexceptions import HTTPServiceUnavailable
from pyramid.interfaces import IRouteRequest, IRoutesMapper, ITweens

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
from .worker.devpi_paths import DevpiBase, DevpiRouteError, validate_artifact_relpath
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
        link_hrefs = []
        project_name = str(project) if isinstance(project, str) else None
        for link in links:
            link_snapshot.append(link)
            try:
                sha256 = validate_sha256(link.hashes.get("sha256"))
            except InvalidSha256:
                sha256 = None
            hydrated_href = None
            if sha256 is None:
                hydrated = _hydrate_cached_plus_e_link(self.stage.xom, link, project=project_name)
                if hydrated is not None:
                    sha256, hydrated_href = hydrated
            link_sha256s.append(sha256)
            link_hrefs.append(hydrated_href)
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
        for link, sha256, hydrated_href in zip(
            link_snapshot, link_sha256s, link_hrefs, strict=True
        ):
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
                    link_href=hydrated_href or str(link.href),
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


def _hydrate_cached_plus_e_link(xom, link, *, project: str | None) -> tuple[str, str] | None:
    """Return authoritative identity for a cached devpi ``+e`` link.

    A hashless ``+e`` link is useful only when the corresponding devpi
    FileEntry is already materialized.  The URL is used to select a key, but
    every identity field is cross-checked against that entry before a
    discovery candidate is created.  In particular, this helper never reads
    an upstream URL or the public Guardian route.
    """
    try:
        href = link.href
        if not isinstance(href, str):
            return None
        filename = link.basename
        if type(filename) is not str or project is None:
            return None
        try:
            parsed_project, parsed_version, _ = splitbasename(filename)
            parsed_project = normalize_name(parsed_project)
            requested_project = normalize_name(project)
        except (TypeError, ValueError):
            return None
        if parsed_project != requested_project:
            return None
        raw = urlsplit(href)
        if raw.query or raw.fragment:
            return None
        base = DevpiBase.parse(_worker_base_url(xom.config))
        relpath, _ = base.resolve_link(href)
        parts = validate_artifact_relpath(relpath, filename=filename)
        if parts[2] != "+e":
            return None

        filestore = xom.filestore
        key = filestore.get_key_from_relpath(relpath)
        if key is None or key.exists() is not True:
            return None
        entry = filestore.get_file_entry_from_key(key)
        if entry is None:
            return None
        if (
            type(entry.relpath) is not str
            or entry.relpath != relpath
            or type(entry.user) is not str
            or entry.user != parts[0]
            or type(entry.index) is not str
            or entry.index != parts[1]
            or type(entry.basename) is not str
            or entry.basename != filename
            or not isinstance(entry.project, str)
            or normalize_name(entry.project) != parsed_project
            or type(entry.version) is not str
            or entry.version != parsed_version
            or entry.file_exists() is not True
        ):
            return None
        hashes = entry.hashes
        if not isinstance(hashes, Mapping):
            return None
        advertised = hashes.get("sha256")
        if type(advertised) is not str:
            return None
        sha256 = validate_sha256(advertised)
        return sha256, f"{base.origin_for(entry.relpath)}#sha256={sha256}"
    except (AttributeError, InvalidSha256, KeyError, TypeError, ValueError, OSError):
        return None


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
    routes_mapper: object | None
    baseline_routes: dict
    baseline_routelist: tuple
    baseline_static_routes: tuple
    baseline_utility_keys: frozenset
    baseline_introspection_categories: frozenset
    tweens: object | None
    baseline_tween_names: frozenset
    baseline_action_ids: frozenset
    guardian_route_names: frozenset = frozenset()
    guardian_introspectables: tuple = ()
    guardian_tween_names: frozenset = frozenset()


def _snapshot_pyramid_state(pyramid_config) -> _PyramidState:
    registry = pyramid_config.registry
    routes_mapper = registry.queryUtility(IRoutesMapper)
    tweens = registry.queryUtility(ITweens)
    action_state = getattr(pyramid_config, "action_state", None)
    actions = getattr(action_state, "actions", ()) if action_state is not None else ()
    return _PyramidState(
        routes_mapper=routes_mapper,
        baseline_routes=dict(getattr(routes_mapper, "routes", {})),
        baseline_routelist=tuple(getattr(routes_mapper, "routelist", ())),
        baseline_static_routes=tuple(getattr(routes_mapper, "static_routes", ())),
        baseline_utility_keys=frozenset(registry._utility_registrations),
        baseline_introspection_categories=frozenset(
            getattr(getattr(pyramid_config, "introspector", None), "_categories", {})
        ),
        tweens=tweens,
        baseline_tween_names=frozenset(getattr(getattr(tweens, "sorter", None), "names", ())),
        baseline_action_ids=frozenset(id(action) for action in actions),
    )


def _capture_guardian_actions(pyramid_config, snapshot: _PyramidState) -> None:
    action_state = getattr(pyramid_config, "action_state", None)
    actions = getattr(action_state, "actions", ()) if action_state is not None else ()
    guardian_actions = [
        action for action in actions if id(action) not in snapshot.baseline_action_ids
    ]
    introspectables = tuple(
        introspectable
        for action in guardian_actions
        for introspectable in action.get("introspectables", ())
    )
    snapshot.guardian_introspectables = introspectables
    snapshot.guardian_route_names = frozenset(
        introspectable["name"]
        for introspectable in introspectables
        if introspectable.category_name == "routes" and "name" in introspectable
    )
    snapshot.guardian_tween_names = frozenset(
        introspectable["name"]
        for introspectable in introspectables
        if introspectable.category_name == "tweens" and "name" in introspectable
    )


def _remove_guardian_view_adapters(pyramid_config, snapshot: _PyramidState) -> None:
    """Remove only view adapters created by Guardian's deferred actions.

    Pyramid 2.1 does not expose an iterator over view registrations.  The
    adapter registry is therefore inspected narrowly here, using the
    ``derived_callable`` identity Pyramid records on each Guardian view
    introspectable.  A MultiView is edited in place so a later plugin view in
    the same adapter slot remains registered.
    """
    targets = {
        introspectable.get("derived_callable")
        for introspectable in snapshot.guardian_introspectables
        if introspectable.category_name == "views"
        and introspectable.get("derived_callable") is not None
    }
    if not targets:
        return

    registry = pyramid_config.registry
    for key, registration in list(registry._adapter_registrations.items()):
        required, provided, name = key
        factory = registration[0]
        if factory in targets:
            registry.unregisterAdapter(required=required, provided=provided, name=name)
            continue
        views = getattr(factory, "views", None)
        media_views = getattr(factory, "media_views", None)
        if views is None and media_views is None:
            continue
        changed = False
        if views is not None:
            retained = [entry for entry in views if entry[1] not in targets]
            changed = len(retained) != len(views)
            views[:] = retained
        if media_views is not None:
            for offer, offer_views in list(media_views.items()):
                retained = [entry for entry in offer_views if entry[1] not in targets]
                changed = changed or len(retained) != len(offer_views)
                if retained:
                    media_views[offer] = retained
                else:
                    media_views.pop(offer)
            if hasattr(factory, "accepts"):
                factory.accepts[:] = [offer for offer in factory.accepts if offer in media_views]
        if (
            changed
            and not getattr(factory, "views", ())
            and not getattr(factory, "media_views", {})
        ):
            registry.unregisterAdapter(required=required, provided=provided, name=name)


def _remove_route(mapper, route) -> None:
    mapper.routelist[:] = [candidate for candidate in mapper.routelist if candidate is not route]
    mapper.static_routes[:] = [
        candidate for candidate in mapper.static_routes if candidate is not route
    ]


def _restore_guardian_routes(pyramid_config, snapshot: _PyramidState) -> None:
    registry = pyramid_config.registry
    mapper = registry.queryUtility(IRoutesMapper)
    if mapper is not None and (snapshot.routes_mapper is None or mapper is snapshot.routes_mapper):
        for name in snapshot.guardian_route_names:
            current = mapper.routes.get(name)
            baseline = snapshot.baseline_routes.get(name)
            if baseline is None:
                if current is not None:
                    _remove_route(mapper, current)
                    mapper.routes.pop(name, None)
                continue
            if current is not baseline:
                if current is not None:
                    _remove_route(mapper, current)
                mapper.routes[name] = baseline
                if baseline in snapshot.baseline_routelist and baseline not in mapper.routelist:
                    index = snapshot.baseline_routelist.index(baseline)
                    mapper.routelist.insert(min(index, len(mapper.routelist)), baseline)
                if (
                    baseline in snapshot.baseline_static_routes
                    and baseline not in mapper.static_routes
                ):
                    index = snapshot.baseline_static_routes.index(baseline)
                    mapper.static_routes.insert(min(index, len(mapper.static_routes)), baseline)

    for name in snapshot.guardian_route_names:
        key = (IRouteRequest, name)
        if key in snapshot.baseline_utility_keys:
            continue
        if registry.queryUtility(IRouteRequest, name=name) is not None:
            registry.unregisterUtility(provided=IRouteRequest, name=name)

    if (
        snapshot.routes_mapper is None
        and mapper is not None
        and not getattr(mapper, "routelist", ())
        and not getattr(mapper, "static_routes", ())
    ):
        registry.unregisterUtility(provided=IRoutesMapper, name="")


def _restore_guardian_tweens(pyramid_config, snapshot: _PyramidState) -> None:
    tweens = pyramid_config.registry.queryUtility(ITweens)
    if tweens is None or (snapshot.tweens is not None and tweens is not snapshot.tweens):
        return
    sorter = getattr(tweens, "sorter", None)
    if sorter is not None:
        for name in snapshot.guardian_tween_names:
            if name not in snapshot.baseline_tween_names and name in sorter.names:
                sorter.remove(name)
    explicit = getattr(tweens, "explicit", None)
    if explicit is not None:
        explicit[:] = [
            entry
            for entry in explicit
            if entry[0] not in snapshot.guardian_tween_names
            or entry[0] in snapshot.baseline_tween_names
        ]
    if (
        snapshot.tweens is None
        and not getattr(sorter, "names", ())
        and not getattr(tweens, "explicit", ())
    ):
        pyramid_config.registry.unregisterUtility(provided=ITweens, name="")


def _restore_guardian_introspection(pyramid_config, snapshot: _PyramidState) -> None:
    introspector = pyramid_config.introspector
    for introspectable in snapshot.guardian_introspectables:
        current = introspector.get(introspectable.category_name, introspectable.discriminator)
        if current is introspectable:
            introspector.remove(introspectable.category_name, introspectable.discriminator)
    for category in list(introspector._categories):
        if (
            category not in snapshot.baseline_introspection_categories
            and not introspector._categories[category]
        ):
            del introspector._categories[category]


def _restore_pyramid_state(pyramid_config, snapshot: _PyramidState) -> None:
    _remove_guardian_view_adapters(pyramid_config, snapshot)
    _restore_guardian_routes(pyramid_config, snapshot)
    _restore_guardian_tweens(pyramid_config, snapshot)
    _restore_guardian_introspection(pyramid_config, snapshot)


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
        _capture_guardian_actions(pyramid_config, pyramid_state)

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
