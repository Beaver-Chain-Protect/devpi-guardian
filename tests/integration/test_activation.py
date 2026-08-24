from __future__ import annotations

import hashlib
import json
import sqlite3
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.integration import conftest as integration_conftest

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


def _fake_server(tmp_path: Path, port: int) -> object:
    return integration_conftest._ServerProcess(
        SimpleNamespace(),
        "http://127.0.0.1:12345",
        port,
        tmp_path / f"server-{port}.log",
    )


def test_expected_ready_server_is_terminated_before_assertion(
    tmp_path: Path,
    monkeypatch,
) -> None:
    original = _fake_server(tmp_path, 1001)
    unexpected = _fake_server(tmp_path, 1002)
    running = integration_conftest.RunningDevpi(
        "http://127.0.0.1:1001",
        tmp_path / "guardian" / "guardian.db",
        tmp_path / "client",
        tmp_path / "server",
        "uv",
        tmp_path,
        _server=original,
        _log_dir=tmp_path,
    )
    terminated: list[object] = []
    monkeypatch.setattr(
        integration_conftest,
        "_terminate",
        lambda server: terminated.append(server),
    )
    monkeypatch.setattr(
        integration_conftest,
        "_remove_temporary_guardian_db",
        lambda path, allowed_root: None,
    )
    monkeypatch.setattr(
        integration_conftest,
        "_start_server",
        lambda *args, **kwargs: unexpected,
    )

    with pytest.raises(AssertionError, match="unexpectedly became ready"):
        running.reset_guardian_db_and_expect_failure()

    assert terminated == [original, unexpected]


def test_guardian_cleanup_removes_owned_database_and_sidecars(
    tmp_path: Path,
) -> None:
    guardian = tmp_path / "guardian"
    guardian.mkdir()
    database = guardian / "guardian.db"
    sidecars = (
        guardian / "guardian.db-wal",
        guardian / "guardian.db-shm",
    )
    for path in (database, *sidecars):
        path.write_bytes(b"owned")

    integration_conftest._remove_temporary_guardian_db(database, tmp_path)

    assert all(not path.exists() for path in (database, *sidecars))


def test_guardian_cleanup_rejects_database_outside_owned_root(
    tmp_path: Path,
) -> None:
    outside = tmp_path.parent / "guardian" / "guardian.db"
    outside.parent.mkdir()
    outside.write_bytes(b"must survive")

    with pytest.raises(ValueError):
        integration_conftest._remove_temporary_guardian_db(outside, tmp_path)

    assert outside.read_bytes() == b"must survive"


def test_guardian_cleanup_rejects_symlinked_guardian_directory(
    tmp_path: Path,
) -> None:
    external = tmp_path.parent / "external-guardian"
    external.mkdir()
    outside = external / "guardian.db"
    outside.write_bytes(b"must survive")
    (tmp_path / "guardian").symlink_to(external, target_is_directory=True)

    with pytest.raises(ValueError):
        integration_conftest._remove_temporary_guardian_db(
            tmp_path / "guardian" / "guardian.db",
            tmp_path,
        )

    assert outside.read_bytes() == b"must survive"


def test_guardian_cleanup_rejects_symlinked_database_and_sidecar(
    tmp_path: Path,
) -> None:
    guardian = tmp_path / "guardian"
    guardian.mkdir()
    external = tmp_path.parent / "external-db"
    external.write_bytes(b"must survive")
    database = guardian / "guardian.db"
    database.symlink_to(external)
    sidecar = guardian / "guardian.db-wal"
    sidecar.write_bytes(b"must survive")
    (guardian / "guardian.db-shm").symlink_to(external)

    with pytest.raises(ValueError):
        integration_conftest._remove_temporary_guardian_db(database, tmp_path)

    assert external.read_bytes() == b"must survive"
    assert sidecar.read_bytes() == b"must survive"


def test_guardian_cleanup_rejects_symlinked_sidecar_without_deleting_database(
    tmp_path: Path,
) -> None:
    guardian = tmp_path / "guardian"
    guardian.mkdir()
    database = guardian / "guardian.db"
    database.write_bytes(b"must survive")
    external = tmp_path.parent / "external-sidecar"
    external.write_bytes(b"must survive")
    (guardian / "guardian.db-wal").symlink_to(external)
    (guardian / "guardian.db-shm").write_bytes(b"must survive")

    with pytest.raises(ValueError):
        integration_conftest._remove_temporary_guardian_db(database, tmp_path)

    assert database.read_bytes() == b"must survive"
    assert external.read_bytes() == b"must survive"


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
