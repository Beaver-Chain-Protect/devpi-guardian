"""devpi-server hook implementations for Guardian enforcement."""

from __future__ import annotations  # noqa: I001 - use devpi order

from .admin.service import GuardianAdminService
from .admin.views import ADMIN_SERVICE_REGISTRY_KEY
from .admin.views import configure_admin_routes
from .audit import SQLiteAuditWriter
from .audit import verify_audit_chain
from .enforcement.metrics import BLOCK_METRIC_REGISTRY_KEY
from .enforcement.metrics import InMemoryBlockMetricRecorder
from .enforcement.tween import VERDICT_READER_REGISTRY_KEY
from .verdicts.db import ConnectionFactory
from .verdicts.db import migrate
from .verdicts.errors import InvalidSha256
from .verdicts.errors import StoreUnavailable
from .verdicts.models import validate_sha256
from .verdicts.reader import SQLiteVerdictReader
from .verdicts.store import SQLiteArtifactStore
from pathlib import Path
from pluggy import HookimplMarker
from pyramid.httpexceptions import HTTPServiceUnavailable

server_hookimpl = HookimplMarker("devpiserver")
_VERDICT_READER_XOM_ATTRIBUTE = "_devpi_guardian_verdict_reader"


class GuardianStage:
    readonly = True

    def validate_config(self, _oldconfig, newconfig) -> None:
        if not newconfig.get("bases"):
            raise self.InvalidIndexconfig("guardian index requires a base")

    def get_simple_links_filter_iter(self, _project, links):
        link_sha256s = []
        for link in links:
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
    block_metrics = InMemoryBlockMetricRecorder()
    setattr(
        pyramid_config.registry["xom"],
        _VERDICT_READER_XOM_ATTRIBUTE,
        reader,
    )
    pyramid_config.registry[VERDICT_READER_REGISTRY_KEY] = reader
    pyramid_config.registry[BLOCK_METRIC_REGISTRY_KEY] = block_metrics
    pyramid_config.registry[ADMIN_SERVICE_REGISTRY_KEY] = GuardianAdminService(
        reader=reader,
        store=store,
    )
    configure_admin_routes(pyramid_config)
    pyramid_config.add_tween(
        "devpi_guardian.enforcement.tween.guardian_enforcement_tween_factory",
        under="devpi_server.views.tween_keyfs_transaction",
    )
