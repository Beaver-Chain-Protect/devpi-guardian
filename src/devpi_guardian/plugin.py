"""devpi-server hook implementations for Guardian enforcement."""

from __future__ import annotations

from pathlib import Path

from pluggy import HookimplMarker

from .enforcement.metrics import (
    BLOCK_METRIC_REGISTRY_KEY,
    InMemoryBlockMetricRecorder,
)
from .enforcement.tween import VERDICT_READER_REGISTRY_KEY
from .verdicts.db import ConnectionFactory, migrate
from .verdicts.reader import SQLiteVerdictReader

server_hookimpl = HookimplMarker("devpiserver")


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
    reader = SQLiteVerdictReader(factory)
    block_metrics = InMemoryBlockMetricRecorder()
    pyramid_config.registry[VERDICT_READER_REGISTRY_KEY] = reader
    pyramid_config.registry[BLOCK_METRIC_REGISTRY_KEY] = block_metrics
    pyramid_config.add_tween(
        "devpi_guardian.enforcement.tween.guardian_enforcement_tween_factory",
        under="devpi_server.views.tween_keyfs_transaction",
    )
