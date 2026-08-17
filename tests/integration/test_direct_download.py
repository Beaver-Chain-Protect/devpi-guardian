from __future__ import annotations

import hashlib
import html.parser
import io
import os
import subprocess
import sys
import urllib.parse
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from devpi_guardian.verdicts.db import ConnectionFactory
from devpi_guardian.verdicts.models import (
    ArtifactInput,
    Decision,
    ManualOverrideInput,
    ReleaseInput,
    VerdictInput,
)
from devpi_guardian.verdicts.store import SQLiteArtifactStore
from tests.conftest import RecordingAuditWriter

pytestmark = pytest.mark.integration


class Links(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.anchors: list[dict[str, str | None]] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag == "a":
            self.anchors.append(dict(attrs))


def _build_wheel(tmp_path: Path, version: str) -> Path:
    project = tmp_path / f"demo-{version}"
    package = project / "src" / "demo_guardian"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        f'__version__ = "{version}"\n',
        encoding="utf-8",
    )
    (project / "pyproject.toml").write_text(
        f"""
[build-system]
requires = ["setuptools>=80"]
build-backend = "setuptools.build_meta"

[project]
name = "demo-guardian"
version = "{version}"
""".strip(),
        encoding="utf-8",
    )
    built = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--no-isolation"],
        cwd=project,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert built.returncode == 0, "offline wheel build failed"
    return next((project / "dist").glob("*.whl"))


def _wheel_metadata(content: bytes) -> bytes:
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        suffix = ".dist-info/METADATA"
        metadata_files = []
        for name in archive.namelist():
            if name.endswith(suffix):
                metadata_files.append(name)
        assert len(metadata_files) == 1
        return archive.read(metadata_files[0])


def _direct_url(
    running_devpi,
    version: str,
) -> tuple[str, dict[str, str | None]]:
    simple_path = "/root/dev/+simple/demo-guardian/"
    simple = running_devpi.request(simple_path)
    assert simple.status == 200
    parser = Links()
    parser.feed(simple.body.decode("utf-8"))
    matching = [
        anchor
        for anchor in parser.anchors
        if version in urllib.parse.unquote(anchor.get("href") or "")
    ]
    assert len(matching) == 1
    href = matching[0]["href"]
    assert href is not None
    simple_url = urllib.parse.urljoin(running_devpi.base_url, simple_path)
    return urllib.parse.urljoin(simple_url, href), matching[0]


def _metadata_url(direct_url: str) -> str:
    parsed = urllib.parse.urlsplit(direct_url)
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            f"{parsed.path}.metadata",
            parsed.query,
            parsed.fragment,
        )
    )


def _record_verdict(
    store: SQLiteArtifactStore,
    sha256: str,
    decision: Decision,
) -> None:
    now = datetime.now(UTC)
    claim = store.claim_next("integration-worker", now + timedelta(minutes=5))
    assert claim is not None
    assert claim.sha256 == sha256
    store.record_verdict(
        claim,
        VerdictInput(
            sha256,
            decision,
            0,
            "policy-integration-1",
            "analyzer-integration-1",
            None,
            now,
        ),
        [],
    )


def _discover(
    store: SQLiteArtifactStore,
    *,
    sha256: str,
    content: bytes,
    version: str,
    filename: str,
    direct_url: str,
    stage: str = "root/dev",
    project: str = "demo-guardian",
) -> None:
    now = datetime.now(UTC)
    store.discover_artifact(
        ArtifactInput(sha256, len(content), now),
        ReleaseInput(
            stage,
            project,
            version,
            filename,
            sha256,
            direct_url,
            now,
        ),
    )


def _assert_blocked(running_devpi, direct_url: str) -> None:
    for url in (direct_url, _metadata_url(direct_url)):
        for method in ("GET", "HEAD"):
            blocked = running_devpi.request(url, method=method)
            assert blocked.status == 404
            assert b"ALLOW" not in blocked.body
            assert b"DENY" not in blocked.body


def _uv_environment(tmp_path: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["UV_NO_CACHE"] = "1"
    environment["UV_NO_INDEX"] = "1"
    environment["UV_CACHE_DIR"] = str(tmp_path / "uv-cache")
    return environment


def _uv(
    running_devpi,
    args: list[str],
    *,
    environment: dict[str, str],
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [running_devpi.uv_executable, *args],
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_private_direct_url_follows_live_verdicts_without_a_decision_cache(
    running_devpi,
    tmp_path: Path,
) -> None:
    wheel = _build_wheel(tmp_path, "1.0.0")
    content = wheel.read_bytes()
    sha256 = hashlib.sha256(content).hexdigest()
    running_devpi.api("upload", str(wheel))
    direct_url, anchor = _direct_url(running_devpi, "1.0.0")

    assert "/root/dev/+f/" in direct_url
    assert anchor.get("data-dist-info-metadata") is not None
    _assert_blocked(running_devpi, direct_url)

    environment = _uv_environment(tmp_path)
    venv = tmp_path / "direct-venv"
    created = _uv(running_devpi, ["venv", str(venv)], environment=environment)
    create_error = "uv could not create the isolated direct-url venv"
    assert created.returncode == 0, create_error
    blocked_uv = _uv(
        running_devpi,
        [
            "pip",
            "install",
            "--no-index",
            "--python",
            str(venv / "bin" / "python"),
            direct_url,
        ],
        environment=environment,
    )
    assert blocked_uv.returncode != 0

    store = SQLiteArtifactStore(
        ConnectionFactory(running_devpi.guardian_db),
        RecordingAuditWriter(),
    )
    _discover(
        store,
        sha256=sha256,
        content=content,
        version="1.0.0",
        filename=wheel.name,
        direct_url=direct_url,
    )
    _assert_blocked(running_devpi, direct_url)

    claim = store.claim_next(
        "integration-scanning-worker",
        datetime.now(UTC) + timedelta(minutes=5),
    )
    assert claim is not None
    _assert_blocked(running_devpi, direct_url)
    store.record_verdict(
        claim,
        VerdictInput(
            sha256,
            Decision.REVIEW,
            1,
            "policy-integration-1",
            "analyzer-integration-1",
            None,
            datetime.now(UTC),
        ),
        [],
    )
    _assert_blocked(running_devpi, direct_url)

    store.request_rescan(sha256, "integration-admin", "approve after rescan")
    _record_verdict(store, sha256, Decision.ALLOW)

    allowed = running_devpi.request(direct_url)
    assert allowed.status == 200
    assert allowed.body == content
    allowed_head = running_devpi.request(direct_url, method="HEAD")
    assert allowed_head.status == 200
    assert allowed_head.body == b""
    assert int(allowed_head.headers["Content-Length"]) == len(content)
    metadata_url = _metadata_url(direct_url)
    metadata = running_devpi.request(metadata_url)
    assert metadata.status == 200
    assert metadata.body != content
    assert metadata.body == _wheel_metadata(content)
    metadata_head = running_devpi.request(metadata_url, method="HEAD")
    assert metadata_head.status == 200
    assert metadata_head.body == b""

    allowed_uv = _uv(
        running_devpi,
        [
            "pip",
            "install",
            "--no-index",
            "--python",
            str(venv / "bin" / "python"),
            direct_url,
        ],
        environment=environment,
    )
    install_error = "uv direct-url install did not receive the allowed wheel"
    assert allowed_uv.returncode == 0, install_error
    imported = subprocess.run(
        [
            str(venv / "bin" / "python"),
            "-c",
            "import demo_guardian; print(demo_guardian.__version__)",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert imported.returncode == 0
    assert imported.stdout.strip() == "1.0.0"

    lock_project = tmp_path / "lock-project"
    lock_project.mkdir()
    (lock_project / "pyproject.toml").write_text(
        f"""
[project]
name = "guardian-lock-proof"
version = "0.0.0"
requires-python = ">=3.11"
dependencies = ["demo-guardian @ {direct_url}"]
""".strip(),
        encoding="utf-8",
    )
    locked = _uv(
        running_devpi,
        ["lock", "--no-cache"],
        environment=environment,
        cwd=lock_project,
    )
    assert locked.returncode == 0, "uv could not lock the allowed direct URL"
    assert (lock_project / "uv.lock").is_file()
    synced = _uv(
        running_devpi,
        ["sync", "--locked", "--no-cache", "--no-install-project"],
        environment=environment,
        cwd=lock_project,
    )
    assert synced.returncode == 0, "uv could not sync the locked direct URL"

    wheel_v2 = _build_wheel(tmp_path, "2.0.0")
    content_v2 = wheel_v2.read_bytes()
    sha256_v2 = hashlib.sha256(content_v2).hexdigest()
    running_devpi.api("upload", str(wheel_v2))
    direct_url_v2, _ = _direct_url(running_devpi, "2.0.0")
    assert running_devpi.request(direct_url).body == content
    _assert_blocked(running_devpi, direct_url_v2)

    _discover(
        store,
        sha256=sha256_v2,
        content=content_v2,
        version="2.0.0",
        filename=wheel_v2.name,
        direct_url=direct_url_v2,
    )
    _record_verdict(store, sha256_v2, Decision.REVIEW)
    store.set_manual_override(
        ManualOverrideInput(
            sha256_v2,
            Decision.ALLOW,
            "integration-admin",
            "temporary review approval",
            datetime.now(UTC),
        )
    )
    assert running_devpi.request(direct_url_v2).body == content_v2
    store.revoke_manual_override(
        sha256_v2,
        "integration-admin",
        "temporary approval withdrawn",
    )
    _assert_blocked(running_devpi, direct_url_v2)
    assert running_devpi.request(direct_url).body == content

    store.set_manual_override(
        ManualOverrideInput(
            sha256,
            Decision.DENY,
            "integration-admin",
            "immediate deny",
            datetime.now(UTC),
        )
    )
    _assert_blocked(running_devpi, direct_url)
    store.set_manual_override(
        ManualOverrideInput(
            sha256,
            Decision.ALLOW,
            "integration-admin",
            "temporary reapproval",
            datetime.now(UTC),
        )
    )
    assert running_devpi.request(direct_url).body == content
    store.request_rescan(sha256, "integration-admin", "new policy version")
    _assert_blocked(running_devpi, direct_url)
    revoked_lock_environment = _uv_environment(tmp_path / "revoked-lock")
    revoked_venv = tmp_path / "revoked-lock-venv"
    revoked_lock_environment["UV_PROJECT_ENVIRONMENT"] = str(revoked_venv)
    revoked_sync = _uv(
        running_devpi,
        ["sync", "--locked", "--no-cache", "--no-install-project"],
        environment=revoked_lock_environment,
        cwd=lock_project,
    )
    assert revoked_sync.returncode != 0

    backup = running_devpi.guardian_db.with_suffix(".saved")
    running_devpi.guardian_db.rename(backup)
    running_devpi.guardian_db.mkdir()
    try:
        unavailable = running_devpi.request(direct_url)
        assert unavailable.status == 503
        assert unavailable.headers["Retry-After"] == "5"
        assert sha256.encode() not in unavailable.body
    finally:
        running_devpi.guardian_db.rmdir()
        backup.rename(running_devpi.guardian_db)

    assert running_devpi.status_code("/+status") == 200
    index_api = running_devpi.request(
        "/root/dev",
        headers={"Accept": "application/json"},
    )
    assert index_api.status == 200


def test_hashless_root_pypi_plus_e_fails_closed_before_upstream_body_fetch(
    running_mirror_devpi,
) -> None:
    artifact = running_mirror_devpi.mirror_artifact
    assert artifact is not None
    direct_url = urllib.parse.urljoin(
        running_mirror_devpi.base_url,
        artifact.direct_path,
    )
    assert "/root/pypi/+e/" in direct_url
    upstream_requests = running_mirror_devpi.mirror_upstream_requests
    assert upstream_requests is not None
    assert not any("/packages/" in path for path in upstream_requests)

    for url in (direct_url, _metadata_url(direct_url)):
        for method in ("GET", "HEAD"):
            unavailable = running_mirror_devpi.request(url, method=method)
            assert unavailable.status == 503
            assert artifact.sha256.encode() not in unavailable.body
    assert not any("/packages/" in path for path in upstream_requests)

    store = SQLiteArtifactStore(
        ConnectionFactory(running_mirror_devpi.guardian_db),
        RecordingAuditWriter(),
    )
    _discover(
        store,
        sha256=artifact.sha256,
        content=artifact.content,
        version=artifact.version,
        filename=artifact.filename,
        direct_url=direct_url,
        stage="root/pypi",
        project=artifact.project,
    )
    _record_verdict(store, artifact.sha256, Decision.ALLOW)
    still_unavailable = running_mirror_devpi.request(direct_url)
    assert still_unavailable.status == 503
    assert not any("/packages/" in path for path in upstream_requests)

    parsed = urllib.parse.urlsplit(direct_url)
    missing_path = parsed.path.rsplit("/", 1)[0] + "/missing-1.0.0.whl"
    missing_identity = running_mirror_devpi.request(missing_path)
    assert missing_identity.status == 503
    assert artifact.sha256.encode() not in missing_identity.body
    assert running_mirror_devpi.status_code("/+status") == 200
