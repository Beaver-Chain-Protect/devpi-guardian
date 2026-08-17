from __future__ import annotations

import hashlib
import html.parser
import http.client
import io
import json
import os
import subprocess
import sys
import threading
import urllib.parse
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from devpi_guardian.verdicts.db import ConnectionFactory
from devpi_guardian.verdicts.models import (
    ArtifactInput,
    ArtifactState,
    Decision,
    DecisionSource,
    ManualOverrideInput,
    ReleaseInput,
    VerdictInput,
)
from devpi_guardian.verdicts.reader import SQLiteVerdictReader
from devpi_guardian.verdicts.store import SQLiteArtifactStore
from tests.conftest import RecordingAuditWriter

pytestmark = pytest.mark.integration
_EXTERNAL_PIP_SOURCE_ENVIRONMENT = (
    "PIP_FIND_LINKS",
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


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


def _assert_blocked(
    running_devpi,
    direct_url: str,
    *,
    artifact_content: bytes,
    metadata_content: bytes,
    sha256: str,
) -> None:
    for url in (direct_url, _metadata_url(direct_url)):
        for method in ("GET", "HEAD"):
            blocked = running_devpi.request(url, method=method)
            assert blocked.status == 404
            if method == "HEAD":
                assert blocked.body == b""
                continue
            for payload in (artifact_content, metadata_content):
                assert blocked.body != payload
                assert payload not in blocked.body
            assert sha256.encode() not in blocked.body
            for state in (
                b"DISCOVERED",
                b"SCANNING",
                b"ALLOW",
                b"REVIEW",
                b"DENY",
                b"ERROR",
                b"MISSING",
            ):
                assert state not in blocked.body


def _independent_barrier_get(
    direct_url: str,
    barrier: threading.Barrier,
) -> tuple[int, bytes]:
    parsed = urllib.parse.urlsplit(direct_url)
    assert parsed.hostname is not None
    target = urllib.parse.urlunsplit(("", "", parsed.path, parsed.query, ""))
    connection = http.client.HTTPConnection(
        parsed.hostname,
        parsed.port,
        timeout=10,
    )
    try:
        barrier.wait(timeout=10)
        connection.request("GET", target)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _assert_concurrent_blocked(
    direct_url: str,
    *,
    artifact_content: bytes,
    metadata_content: bytes,
    sha256: str,
) -> None:
    worker_count = 8
    repetition_count = 8
    results: list[tuple[int, bytes]] = []
    for _ in range(repetition_count):
        barrier = threading.Barrier(worker_count)
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [
                executor.submit(
                    _independent_barrier_get,
                    direct_url,
                    barrier,
                )
                for _ in range(worker_count)
            ]
            results.extend(future.result() for future in futures)

    assert len(results) == worker_count * repetition_count
    assert [status for status, _ in results] == [404] * len(results)
    for _, body in results:
        assert artifact_content not in body
        assert metadata_content not in body
        assert sha256.encode() not in body


def _pip_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for variable in _EXTERNAL_PIP_SOURCE_ENVIRONMENT:
        environment.pop(variable, None)
    environment["NO_PROXY"] = "127.0.0.1,localhost,::1"
    environment["no_proxy"] = "127.0.0.1,localhost,::1"
    environment["PIP_CONFIG_FILE"] = os.devnull
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    environment["PIP_NO_CACHE_DIR"] = "1"
    environment["PIP_NO_INDEX"] = "1"
    environment["PIP_RETRIES"] = "0"
    return environment


def _pip_install_exact(
    running_devpi,
    *,
    venv: Path,
) -> subprocess.CompletedProcess[str]:
    environment = _pip_environment()
    created = subprocess.run(
        [sys.executable, "-m", "venv", str(venv)],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert created.returncode == 0, "stdlib venv creation failed"
    simple_url = urllib.parse.urljoin(
        running_devpi.base_url,
        "/root/dev/+simple/demo-guardian/",
    )
    return subprocess.run(
        [
            str(venv / "bin" / "python"),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--find-links",
            simple_url,
            "demo-guardian==1.0.0",
        ],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _uv_environment(tmp_path: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["NO_PROXY"] = "127.0.0.1,localhost,::1"
    environment["no_proxy"] = "127.0.0.1,localhost,::1"
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


def _assert_revoked_lock_blocked_by_guardian(
    result: subprocess.CompletedProcess[str],
    *,
    direct_url: str,
    wheel_filename: str,
) -> None:
    assert result.returncode != 0
    combined = f"{result.stdout}\n{result.stderr}"
    direct_path = urllib.parse.urlsplit(direct_url).path
    assert "HTTP" in combined
    assert "404" in combined
    assert wheel_filename in combined
    assert direct_path in combined


@pytest.mark.parametrize(
    "variable",
    [
        "PIP_FIND_LINKS",
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ],
)
def test_pip_environment_cannot_inherit_an_external_source(
    monkeypatch: pytest.MonkeyPatch,
    variable: str,
) -> None:
    monkeypatch.setenv(variable, "https://user:secret@external.invalid/simple")
    monkeypatch.setenv("GUARDIAN_UNRELATED", "preserved")

    environment = _pip_environment()

    assert variable not in environment
    assert environment["GUARDIAN_UNRELATED"] == "preserved"
    assert environment["PIP_NO_INDEX"] == "1"
    assert environment["NO_PROXY"] == "127.0.0.1,localhost,::1"
    assert environment["no_proxy"] == "127.0.0.1,localhost,::1"


def test_revoked_lock_assertion_rejects_an_unrelated_failure() -> None:
    unrelated = subprocess.CompletedProcess(
        ("uv", "sync"),
        1,
        "",
        "failed because the disk is full",
    )

    with pytest.raises(AssertionError):
        _assert_revoked_lock_blocked_by_guardian(
            unrelated,
            direct_url="http://127.0.0.1/root/dev/+f/abc/demo.whl",
            wheel_filename="demo.whl",
        )


def test_private_direct_url_follows_live_verdicts_without_a_decision_cache(
    running_devpi,
    tmp_path: Path,
) -> None:
    wheel = _build_wheel(tmp_path, "1.0.0")
    content = wheel.read_bytes()
    metadata_content = _wheel_metadata(content)
    sha256 = hashlib.sha256(content).hexdigest()
    running_devpi.api("upload", str(wheel))
    direct_url, anchor = _direct_url(running_devpi, "1.0.0")

    assert "/root/dev/+f/" in direct_url
    assert anchor.get("data-dist-info-metadata") is not None
    _assert_blocked(
        running_devpi,
        direct_url,
        artifact_content=content,
        metadata_content=metadata_content,
        sha256=sha256,
    )
    _assert_concurrent_blocked(
        direct_url,
        artifact_content=content,
        metadata_content=metadata_content,
        sha256=sha256,
    )

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
    _assert_blocked(
        running_devpi,
        direct_url,
        artifact_content=content,
        metadata_content=metadata_content,
        sha256=sha256,
    )

    claim = store.claim_next(
        "integration-scanning-worker",
        datetime.now(UTC) + timedelta(minutes=5),
    )
    assert claim is not None
    _assert_blocked(
        running_devpi,
        direct_url,
        artifact_content=content,
        metadata_content=metadata_content,
        sha256=sha256,
    )
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
    _assert_blocked(
        running_devpi,
        direct_url,
        artifact_content=content,
        metadata_content=metadata_content,
        sha256=sha256,
    )

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
    assert metadata.body == metadata_content
    metadata_head = running_devpi.request(metadata_url, method="HEAD")
    assert metadata_head.status == 200
    assert metadata_head.body == b""

    running_devpi.restart()
    persisted_allow = running_devpi.request(direct_url)
    assert persisted_allow.status == 200
    assert persisted_allow.body == content
    persisted_metadata = running_devpi.request(metadata_url)
    assert persisted_metadata.status == 200
    assert persisted_metadata.body == metadata_content
    repeated_persisted_metadata = running_devpi.request(metadata_url)
    assert repeated_persisted_metadata.status == 200
    assert repeated_persisted_metadata.body == metadata_content

    pip_venv = tmp_path / "pip-exact-allowed-venv"
    pip_allowed = _pip_install_exact(
        running_devpi,
        venv=pip_venv,
    )
    assert pip_allowed.returncode == 0, (
        "pip exact-version install did not receive the allowed wheel"
    )
    pip_imported = subprocess.run(
        [
            str(pip_venv / "bin" / "python"),
            "-c",
            (
                "from pathlib import Path; import demo_guardian; "
                "print(demo_guardian.__version__); "
                "print(Path(demo_guardian.__file__).resolve())"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert pip_imported.returncode == 0
    installed_version, installed_file = pip_imported.stdout.splitlines()
    assert installed_version == "1.0.0"
    assert Path(installed_file).is_relative_to(pip_venv.resolve())

    toxresult_content = b'{"testenvs":{"py312":{"retcode":0}}}'
    toxresult_post = running_devpi.request(
        direct_url,
        method="POST",
        headers={"Content-Type": "application/json"},
        body=toxresult_content,
    )
    assert toxresult_post.status == 200
    toxresult_response = json.loads(toxresult_post.body)
    toxresult_entrypath = toxresult_response["result"]
    assert isinstance(toxresult_entrypath, str)
    assert toxresult_entrypath.startswith("root/dev/+f/")
    toxresult_url = urllib.parse.urljoin(
        running_devpi.base_url,
        f"/{toxresult_entrypath}",
    )
    toxresult_sha256 = hashlib.sha256(toxresult_content).hexdigest()
    toxresult_decision = SQLiteVerdictReader(
        ConnectionFactory(running_devpi.guardian_db)
    ).get_effective_decision(toxresult_sha256)
    assert toxresult_decision.allowed is False
    assert toxresult_decision.source is DecisionSource.MISSING
    assert toxresult_decision.artifact_state is ArtifactState.MISSING
    toxresult_get = running_devpi.request(toxresult_url)
    assert toxresult_get.status == 200
    assert toxresult_get.body == toxresult_content
    toxresult_head = running_devpi.request(toxresult_url, method="HEAD")
    assert toxresult_head.status == 200
    assert toxresult_head.body == b""
    toxresult_length = int(toxresult_head.headers["Content-Length"])
    assert toxresult_length == len(toxresult_content)

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
    metadata_content_v2 = _wheel_metadata(content_v2)
    sha256_v2 = hashlib.sha256(content_v2).hexdigest()
    running_devpi.api("upload", str(wheel_v2))
    direct_url_v2, _ = _direct_url(running_devpi, "2.0.0")
    assert running_devpi.request(direct_url).body == content
    _assert_blocked(
        running_devpi,
        direct_url_v2,
        artifact_content=content_v2,
        metadata_content=metadata_content_v2,
        sha256=sha256_v2,
    )

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
    _assert_blocked(
        running_devpi,
        direct_url_v2,
        artifact_content=content_v2,
        metadata_content=metadata_content_v2,
        sha256=sha256_v2,
    )
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
    _assert_blocked(
        running_devpi,
        direct_url,
        artifact_content=content,
        metadata_content=metadata_content,
        sha256=sha256,
    )
    running_devpi.restart()
    _assert_blocked(
        running_devpi,
        direct_url,
        artifact_content=content,
        metadata_content=metadata_content,
        sha256=sha256,
    )
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
    _assert_blocked(
        running_devpi,
        direct_url,
        artifact_content=content,
        metadata_content=metadata_content,
        sha256=sha256,
    )
    revoked_lock_environment = _uv_environment(tmp_path / "revoked-lock")
    revoked_venv = tmp_path / "revoked-lock-venv"
    revoked_lock_environment["UV_PROJECT_ENVIRONMENT"] = str(revoked_venv)
    revoked_sync = _uv(
        running_devpi,
        ["sync", "--locked", "--no-cache", "--no-install-project"],
        environment=revoked_lock_environment,
        cwd=lock_project,
    )
    _assert_revoked_lock_blocked_by_guardian(
        revoked_sync,
        direct_url=direct_url,
        wheel_filename=wheel.name,
    )
    blocked_pip_venv = tmp_path / "pip-exact-blocked-venv"
    pip_blocked = _pip_install_exact(
        running_devpi,
        venv=blocked_pip_venv,
    )
    assert pip_blocked.returncode != 0
    pip_blocked_output = f"{pip_blocked.stdout}\n{pip_blocked.stderr}"
    assert "404" in pip_blocked_output
    assert wheel.name in pip_blocked_output
    pip_direct_path = urllib.parse.urlsplit(direct_url).path.replace(
        "/+f/",
        "/%2Bf/",
    )
    assert pip_direct_path in pip_blocked_output
    package_absent = subprocess.run(
        [
            str(blocked_pip_venv / "bin" / "python"),
            "-c",
            "import demo_guardian",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert package_absent.returncode != 0

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
    metadata_content = _wheel_metadata(artifact.content)
    upstream_requests = running_mirror_devpi.mirror_upstream_requests
    assert upstream_requests is not None
    assert not any("/packages/" in path for path in upstream_requests)

    for url in (direct_url, _metadata_url(direct_url)):
        for method in ("GET", "HEAD"):
            unavailable = running_mirror_devpi.request(url, method=method)
            assert unavailable.status == 503
            if method == "HEAD":
                assert unavailable.body == b""
            else:
                for payload in (artifact.content, metadata_content):
                    assert unavailable.body != payload
                    assert payload not in unavailable.body
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
    assert still_unavailable.body != artifact.content
    assert artifact.content not in still_unavailable.body
    assert not any("/packages/" in path for path in upstream_requests)

    parsed = urllib.parse.urlsplit(direct_url)
    missing_path = parsed.path.rsplit("/", 1)[0] + "/missing-1.0.0.whl"
    missing_identity = running_mirror_devpi.request(missing_path)
    assert missing_identity.status == 503
    assert artifact.sha256.encode() not in missing_identity.body
    assert running_mirror_devpi.status_code("/+status") == 200
