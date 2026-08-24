from __future__ import annotations

import hashlib
import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration
_SECRET_PATH = "https://user:password@example.invalid/secret?"
_SECRET_URL = f"{_SECRET_PATH}token=activation-secret"


def _activation_marker(path: Path) -> tuple[str, str, int]:
    with sqlite3.connect(path) as connection:
        select_columns = "SELECT devpi_uuid, activated_at, activation_version"
        query = f"{select_columns} FROM guardian_activation"
        row = connection.execute(
            query,
        ).fetchone()
    assert row is not None
    return row


def _secret_wheel(tmp_path: Path) -> tuple[Path, bytes]:
    filename = "activation-secret-1.0.0-py3-none-any.whl"
    wheel = tmp_path / filename
    metadata = (
        "Metadata-Version: 2.1\n"
        "Name: activation-secret\n"
        "Version: 1.0.0\n"
        f"Project-URL: Source, {_SECRET_URL}\n"
    )
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "activation_secret/__init__.py",
            "__version__ = '1.0.0'\n",
        )
        archive.writestr(
            "activation_secret-1.0.0.dist-info/METADATA",
            metadata,
        )
        archive.writestr(
            "activation_secret-1.0.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: activation-test\n"
            "Root-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr("activation_secret-1.0.0.dist-info/RECORD", "")
    return wheel, wheel.read_bytes()


def _contains(path: Path, value: str) -> bool:
    return value.encode() in path.read_bytes()


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

    wheel, wheel_bytes = _secret_wheel(tmp_path)
    digest = hashlib.sha256(wheel_bytes).hexdigest()
    assert _SECRET_URL.encode() in wheel_bytes
    running_devpi.api("upload", str(wheel))

    failure = running_devpi.reset_guardian_db_and_expect_failure()
    assert "existing_artifacts" in failure.diagnostic
    raw_log = failure.raw_log_path
    assert not _contains(raw_log, str(running_devpi.guardian_db))
    assert not _contains(raw_log, wheel.name)
    assert not _contains(raw_log, digest)
    assert not _contains(raw_log, "user:password")
    assert not _contains(raw_log, "token=activation-secret")
    assert not _contains(raw_log, _SECRET_URL)
