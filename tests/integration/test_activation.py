from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from tests.integration.test_direct_download import _build_wheel

pytestmark = pytest.mark.integration


def _activation_marker(path: Path) -> tuple[str, str, int]:
    with sqlite3.connect(path) as connection:
        select_columns = "SELECT devpi_uuid, activated_at, activation_version"
        query = f"{select_columns} FROM guardian_activation"
        row = connection.execute(
            query,
        ).fetchone()
    assert row is not None
    return row


def test_activation_marker_survives_restart_and_legacy_reset_fails_closed(
    running_devpi,
    tmp_path: Path,
) -> None:
    nodeinfo = json.loads(
        (running_devpi.server_dir / ".nodeinfo").read_text(encoding="utf-8"),
    )
    devpi_uuid = nodeinfo["uuid"]
    marker_before = _activation_marker(running_devpi.guardian_db)
    assert marker_before[0] == devpi_uuid
    assert marker_before[2] == 1

    running_devpi.restart()
    marker_after = _activation_marker(running_devpi.guardian_db)
    assert marker_after == marker_before

    wheel = _build_wheel(tmp_path, "1.0.0")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    running_devpi.api("upload", str(wheel))

    diagnostic = running_devpi.reset_guardian_db_and_expect_failure()
    assert "existing_artifacts" in diagnostic
    assert str(running_devpi.guardian_db) not in diagnostic
    assert wheel.name not in diagnostic
    assert digest not in diagnostic
    assert "https://user:password@example.invalid/secret" not in diagnostic
