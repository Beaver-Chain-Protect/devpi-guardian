"""devpi-server hook implementations for Guardian enforcement."""

from __future__ import annotations  # noqa: I001 - use devpi order

from . import __version__
from .admin.providers import ProductionAdminProviders
from .admin.service import GuardianAdminService
from .admin.views import ADMIN_SERVICE_REGISTRY_KEY
from .admin.views import configure_admin_routes
from .audit import SQLiteAuditWriter
from .audit import verify_audit_chain
from .enforcement.metrics import BLOCK_METRIC_REGISTRY_KEY
from .enforcement.metrics import InMemoryBlockMetricRecorder
from .enforcement.tween import VERDICT_READER_REGISTRY_KEY
from .policy import PolicyEngine
from .verdicts.db import ConnectionFactory
from .verdicts.db import migrate
from .verdicts.errors import InvalidSha256
from .verdicts.errors import StoreUnavailable
from .verdicts.models import validate_sha256
from .verdicts.models import DecisionSource
from .verdicts.reader import SQLiteVerdictReader
from .verdicts.store import SQLiteArtifactStore
from .worker.discovery import DiscoveryCandidate
from .worker.discovery import DiscoveryUnavailable
from .worker.discovery import FileDiscoverySink
from .worker.discovery import get_discovery_sink
from .worker.discovery import set_discovery_sink
from .worker.runtime import build_worker_thread
from datetime import timedelta
from pathlib import Path
from pluggy import HookimplMarker
from pyramid.httpexceptions import HTTPServiceUnavailable
import os
import requests
import socket

server_hookimpl = HookimplMarker("devpiserver")
_VERDICT_READER_XOM_ATTRIBUTE = "_devpi_guardian_verdict_reader"


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
        for link, sha256 in zip(link_snapshot, link_sha256s, strict=True):
            decision = decisions.get(sha256) if sha256 is not None else None
            if getattr(decision, "source", None) is not DecisionSource.MISSING:
                continue
            missing.append(
                DiscoveryCandidate(
                    stage=str(self.stage.name),
                    project=str(project),
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
        "--guardian-base-url",
        action="store",
        dest="guardian_base_url",
        default=None,
        help="absolute devpi URL used to validate discovered artifact links",
    )
    parser.addoption(
        "--guardian-quarantine-root",
        action="store",
        dest="guardian_quarantine_root",
        default=None,
        help="path to the persistent SHA-256 quarantine directory",
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


@server_hookimpl
def devpiserver_pyramid_configure(config, pyramid_config) -> None:
    configured = config.args.guardian_db
    db_path = (
        Path(configured)
        if configured is not None
        else Path(config.server_path) / "guardian" / "guardian.db"
    )
    factory = ConnectionFactory(db_path)
    migrate(factory)
    verification = verify_audit_chain(factory)
    if not verification.valid:
        raise StoreUnavailable(f"{db_path}: audit chain verification failed")
    audit_writer = SQLiteAuditWriter()
    store = SQLiteArtifactStore(factory, audit_writer)
    reader = SQLiteVerdictReader(factory)
    discovery_sink = FileDiscoverySink(db_path.parent / "discovery")
    block_metrics = InMemoryBlockMetricRecorder()
    policy_engine = PolicyEngine()
    xom = pyramid_config.registry["xom"]
    set_discovery_sink(xom, discovery_sink)
    worker = None
    thread_pool = getattr(xom, "thread_pool", None)
    is_replica = getattr(xom, "is_replica", lambda: False)()
    if thread_pool is not None and not is_replica:
        quarantine_configured = getattr(config.args, "guardian_quarantine_root", None)
        quarantine_root = (
            Path(quarantine_configured)
            if quarantine_configured is not None
            else db_path.parent / "quarantine"
        )
        baseline_session = requests.Session()
        baseline_session.headers["User-Agent"] = f"devpi-guardian/{__version__}"
        worker = build_worker_thread(
            xom=xom,
            store=store,
            reader=reader,
            policy_engine=policy_engine,
            baseline_http_session=baseline_session,
            base_url=_worker_base_url(config),
            quarantine_root=quarantine_root,
            analyzer_version=__version__,
            worker_id=f"{socket.gethostname()}-{os.getpid()}",
            cooldown_duration=timedelta(
                hours=getattr(config.args, "guardian_cooldown_hours", 24.0),
            ),
            poll_interval=getattr(
                config.args,
                "guardian_worker_poll_interval",
                0.25,
            ),
        )
        thread_pool.register(worker)
    providers = ProductionAdminProviders(
        factory=factory,
        reader=reader,
        store=store,
        discovery=discovery_sink,
        policy_engine=policy_engine,
        worker=worker,
    )
    setattr(
        xom,
        _VERDICT_READER_XOM_ATTRIBUTE,
        reader,
    )
    pyramid_config.registry[VERDICT_READER_REGISTRY_KEY] = reader
    pyramid_config.registry[BLOCK_METRIC_REGISTRY_KEY] = block_metrics
    pyramid_config.registry[ADMIN_SERVICE_REGISTRY_KEY] = GuardianAdminService(
        reader=reader,
        store=store,
        worker_health_reader=providers,
        audit_reader=providers,
        diff_reader=providers,
        baseline_manager=providers,
        policy_manager=providers,
    )
    configure_admin_routes(pyramid_config)
    pyramid_config.add_tween(
        "devpi_guardian.enforcement.tween.guardian_enforcement_tween_factory",
        under="devpi_server.views.tween_keyfs_transaction",
    )
