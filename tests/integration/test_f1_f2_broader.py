# Project Ruff and upstream devpi intentionally use conflicting import layouts.
# Keep devpi's no-section, from-first style in this integration-facing test.
# ruff: noqa: I001
from devpi_guardian import plugin
from devpi_guardian.verdicts.db import ConnectionFactory
from devpi_guardian.verdicts.errors import StoreUnavailable
from devpi_guardian.verdicts.models import Decision
from devpi_guardian.verdicts.store import SQLiteArtifactStore
from pathlib import Path
from tests.conftest import RecordingAuditWriter
from tests.integration.test_direct_download import Links
from tests.integration.test_direct_download import _build_wheel
from tests.integration.test_direct_download import _discover
from tests.integration.test_direct_download import _record_verdict
from tests.integration.test_pytest_devpi_server import _request
import hashlib
import os
import shutil
import subprocess
import sys
import urllib.parse
import pytest


pytestmark = [pytest.mark.integration, pytest.mark.notransaction]


def simple_artifacts(response):
    return {
        (anchor.text, anchor["href"].rsplit("sha256=", 1)[-1])
        for anchor in response.html.select("a")
    }


def make_guardian_testapp(makemapp, maketestapp, makexom):
    xom = makexom(plugins=[plugin])
    testapp = maketestapp(xom)
    mapp = makemapp(testapp)
    mapp.create_and_login_user("guard", password="123")
    return xom, testapp, mapp


@pytest.mark.nomocking
def test_guardian_filters_mirror_cache_miss_hit_and_stale(
    makemapp,
    maketestapp,
    makexom,
    simpypi,
) -> None:
    xom, testapp, mapp = make_guardian_testapp(
        makemapp,
        maketestapp,
        makexom,
    )

    project = "mirror-proof"
    filename = "mirror_proof-1.0-py3-none-any.whl"
    content = b"deterministic mirror artifact"
    digest = hashlib.sha256(content).hexdigest()
    simpypi.add_release(project, pkgver=f"{filename}#sha256={digest}")
    simpypi.add_file(f"/{project}/{filename}", content)
    mapp.create_index(
        "guard/mirror",
        indexconfig={"type": "mirror", "mirror_url": simpypi.simpleurl},
    )
    mapp.create_index(
        "guard/guardian",
        indexconfig={"type": "guardian", "bases": ["guard/mirror"]},
    )

    db_path = Path(xom.config.server_path) / "guardian" / "guardian.db"
    store = SQLiteArtifactStore(
        ConnectionFactory(db_path),
        RecordingAuditWriter(),
    )
    _discover(
        store,
        sha256=digest,
        content=content,
        version="1.0",
        filename=filename,
        direct_url=f"{simpypi.baseurl}/{project}/{filename}",
        stage="guard/mirror",
        project=project,
    )
    _record_verdict(store, digest, Decision.ALLOW)

    simple_path = f"/guard/guardian/+simple/{project}/"
    expected = {(filename, digest)}
    simpypi.clear_requests()

    first = testapp.get(simple_path)

    assert simple_artifacts(first) == expected
    assert [path for path, _headers in simpypi.requests] == [
        "/simple/",
        f"/simple/{project}/",
    ]

    simpypi.clear_requests()
    second = testapp.get(simple_path)
    assert simple_artifacts(second) == expected
    assert simpypi.requests == []

    mapp.modify_index(
        "guard/mirror",
        {"type": "mirror", "mirror_cache_expiry": 0},
    )
    simpypi.remove_project(project)
    simpypi.clear_requests()
    stale = testapp.get(simple_path)
    assert simple_artifacts(stale) == expected
    assert f"/simple/{project}/" in [path for path, _ in simpypi.requests]


def test_guardian_filters_each_result_from_multiple_bases(
    makemapp,
    maketestapp,
    makexom,
    monkeypatch,
) -> None:
    xom, testapp, mapp = make_guardian_testapp(
        makemapp,
        maketestapp,
        makexom,
    )
    project = "multi-base-proof"
    releases = [
        ("guard/base-one", "1.0", b"base one allowed", Decision.ALLOW),
        ("guard/base-one", "2.0", b"base one denied", Decision.DENY),
        ("guard/base-two", "3.0", b"base two allowed", Decision.ALLOW),
        ("guard/base-two", "4.0", b"base two unscanned", None),
    ]
    for stage in ("guard/base-one", "guard/base-two"):
        mapp.create_index(stage)
        for release_stage, version, content, _decision in releases:
            if release_stage == stage:
                filename = f"multi-base-proof-{version}.tar.gz"
                mapp.upload_file_pypi(filename, content, project, version)
    mapp.create_index(
        "guard/guardian",
        indexconfig={
            "type": "guardian",
            "bases": ["guard/base-one", "guard/base-two"],
        },
    )

    db_path = Path(xom.config.server_path) / "guardian" / "guardian.db"
    store = SQLiteArtifactStore(
        ConnectionFactory(db_path),
        RecordingAuditWriter(),
    )
    expected_allowed = set()
    expected_per_base = {}
    for stage, version, content, decision in releases:
        filename = f"multi-base-proof-{version}.tar.gz"
        digest = hashlib.sha256(content).hexdigest()
        expected_per_base.setdefault(stage, set()).add((filename, digest))
        if decision is None:
            continue
        _discover(
            store,
            sha256=digest,
            content=content,
            version=version,
            filename=filename,
            direct_url=f"http://localhost/{stage}/+f/{digest[:3]}/{filename}",
            stage=stage,
            project=project,
        )
        _record_verdict(store, digest, decision)
        if decision is Decision.ALLOW:
            expected_allowed.add((filename, digest))

    for stage, expected in expected_per_base.items():
        response = testapp.get(f"/{stage}/+simple/{project}/")
        assert simple_artifacts(response) == expected

    real_reader = plugin.get_verdict_reader(xom)

    class RecordingReader:
        def __init__(self):
            self.calls = []

        def get_effective_decisions(self, sha256s):
            self.calls.append(tuple(sha256s))
            return real_reader.get_effective_decisions(sha256s)

    recording_reader = RecordingReader()
    monkeypatch.setattr(
        xom,
        "_devpi_guardian_verdict_reader",
        recording_reader,
    )
    guardian = testapp.get(f"/guard/guardian/+simple/{project}/")
    assert simple_artifacts(guardian) == expected_allowed
    assert len(recording_reader.calls) == 2
    assert {frozenset(call) for call in recording_reader.calls} == {
        frozenset(digest for _filename, digest in expected)
        for expected in expected_per_base.values()
    }
    assert {name for name, _digest in expected_allowed} == {
        "multi-base-proof-1.0.tar.gz",
        "multi-base-proof-3.0.tar.gz",
    }


def test_store_unavailable_fails_html_and_json_simple_requests(
    makemapp,
    maketestapp,
    makexom,
    monkeypatch,
) -> None:
    xom, testapp, mapp = make_guardian_testapp(
        makemapp,
        maketestapp,
        makexom,
    )
    project = "unavailable-proof"
    filename = "unavailable-proof-1.0.tar.gz"
    content = b"must never appear in a service unavailable response"
    digest = hashlib.sha256(content).hexdigest()
    mapp.create_index("guard/unavailable-base")
    mapp.upload_file_pypi(filename, content, project, "1.0")
    mapp.create_index(
        "guard/unavailable-guardian",
        indexconfig={
            "type": "guardian",
            "bases": ["guard/unavailable-base"],
        },
    )

    class UnavailableReader:
        def get_effective_decisions(self, _sha256s):
            raise StoreUnavailable("forced integration failure")

    monkeypatch.setattr(
        xom,
        "_devpi_guardian_verdict_reader",
        UnavailableReader(),
    )
    simple_path = f"/guard/unavailable-guardian/+simple/{project}/"
    response_variants = (
        testapp.get(simple_path, status=503),
        testapp.get(
            simple_path,
            headers={"Accept": "application/vnd.pypi.simple.v1+json"},
            status=503,
        ),
    )
    for response in response_variants:
        assert response.status_code == 503
        assert response.headers["Retry-After"] == "5"
        assert filename not in response.text
        assert digest not in response.text
        assert content not in response.body


def test_guardian_index_rejects_upload_through_devpi_readonly_core(
    makemapp,
    maketestapp,
    makexom,
) -> None:
    _xom, testapp, mapp = make_guardian_testapp(
        makemapp,
        maketestapp,
        makexom,
    )
    mapp.create_index("guard/readonly-base")
    mapp.create_index(
        "guard/readonly-guardian",
        indexconfig={
            "type": "guardian",
            "bases": ["guard/readonly-base"],
        },
    )
    filename = "readonly-proof-1.0.tar.gz"
    project = "readonly-proof"

    response = mapp.upload_file_pypi(
        filename,
        b"this upload must be rejected",
        project,
        "1.0",
        indexname="guard/readonly-guardian",
        register=False,
        code=405,
    )

    assert response.status_code == 405
    assert "read only" in response.text
    simple = testapp.get(
        f"/guard/readonly-guardian/+simple/{project}/",
        status=404,
    )
    assert filename not in simple.text


def test_pip_and_uv_install_only_the_allowed_version(
    devpi_server,
    tmp_path: Path,
) -> None:
    base_stage = f"{devpi_server.user}/installer-source"
    guardian_stage = f"{devpi_server.user}/installer-guardian"
    devpi_server.api("index", "-c", base_stage, "bases=")

    releases = []
    for version in ("21.0.0", "22.0.0"):
        wheel = _build_wheel(tmp_path, version)
        content = wheel.read_bytes()
        releases.append(
            {
                "version": version,
                "filename": wheel.name,
                "content": content,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
        devpi_server.api("upload", "--index", base_stage, str(wheel))

    devpi_server.api(
        "index",
        "-c",
        guardian_stage,
        "type=guardian",
        f"bases={base_stage}",
    )
    base_url = f"{devpi_server.uri.rstrip('/')}/"
    base_simple = urllib.parse.urljoin(
        base_url,
        f"/{base_stage}/+simple/demo-guardian/",
    )
    status, body = _request(base_simple)
    assert status == 200
    parser = Links()
    parser.feed(body.decode("utf-8"))
    direct_urls = {}
    for anchor in parser.anchors:
        href = anchor["href"]
        assert href is not None
        parsed = urllib.parse.urlsplit(href)
        digest = urllib.parse.parse_qs(parsed.fragment)["sha256"][0]
        direct_urls[digest] = urllib.parse.urljoin(base_simple, href)

    allowed = releases[0]
    db_path = Path(devpi_server.server_dir) / "guardian" / "guardian.db"
    store = SQLiteArtifactStore(
        ConnectionFactory(db_path),
        RecordingAuditWriter(),
    )
    _discover(
        store,
        sha256=allowed["sha256"],
        content=allowed["content"],
        version=allowed["version"],
        filename=allowed["filename"],
        direct_url=direct_urls[allowed["sha256"]],
        stage=base_stage,
    )
    _record_verdict(store, allowed["sha256"], Decision.ALLOW)

    index_url = urllib.parse.urljoin(base_url, f"/{guardian_stage}/+simple/")
    environment = os.environ.copy()
    environment["NO_PROXY"] = "127.0.0.1,localhost,::1"
    environment["no_proxy"] = environment["NO_PROXY"]
    for name in ("PIP_EXTRA_INDEX_URL", "UV_EXTRA_INDEX_URL"):
        environment.pop(name, None)

    pip = shutil.which("pip")
    assert pip is not None, "pip is required for the installer proof"
    installers = [
        (
            "pip",
            [
                pip,
                "install",
                "--disable-pip-version-check",
                "--isolated",
                "--no-input",
                "--no-deps",
                "--no-cache-dir",
                "--retries",
                "0",
            ],
        )
    ]
    uv = shutil.which("uv")
    if uv is not None:
        installers.append(
            (
                "uv",
                [
                    uv,
                    "--no-config",
                    "pip",
                    "install",
                    "--no-deps",
                    "--no-cache",
                    "--no-python-downloads",
                    "--python",
                    sys.executable,
                ],
            )
        )

    for installer, command in installers:
        allowed_target = tmp_path / f"{installer}-allowed"
        allowed_command = [
            *command,
            "--index-url",
            index_url,
            "--target",
            str(allowed_target),
            "demo-guardian==21.0.0",
        ]
        allowed_result = subprocess.run(
            allowed_command,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert allowed_result.returncode == 0, allowed_result.stderr
        assert (allowed_target / "demo_guardian" / "__init__.py").is_file()

        blocked_target = tmp_path / f"{installer}-blocked"
        blocked_result = subprocess.run(
            [
                *command,
                "--index-url",
                index_url,
                "--target",
                str(blocked_target),
                "demo-guardian==22.0.0",
            ],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert blocked_result.returncode != 0
        assert not (blocked_target / "demo_guardian").exists()
