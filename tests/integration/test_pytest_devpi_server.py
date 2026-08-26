from __future__ import annotations

# Project Ruff and upstream devpi intentionally use conflicting import layouts.
# Keep devpi's no-section, from-first style in this integration-facing test.
# ruff: noqa: I001
from devpi_guardian.verdicts.db import ConnectionFactory
from devpi_guardian.verdicts.models import ArtifactState, Decision, ManualOverrideInput
from devpi_guardian.verdicts.reader import SQLiteVerdictReader
from devpi_guardian.verdicts.store import SQLiteArtifactStore
from datetime import UTC, datetime
from pathlib import Path
from tests.conftest import RecordingAuditWriter
from tests.integration.test_direct_download import Links
from tests.integration.test_direct_download import _build_wheel
from tests.integration.test_direct_download import _discover
from tests.integration.test_direct_download import _manual_allow
import hashlib
import json
import pytest
import urllib.error
import urllib.parse
import urllib.request
import time

pytestmark = pytest.mark.integration
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _manual_decision(store, sha256: str, decision: Decision) -> None:
    store.set_manual_override(
        ManualOverrideInput(
            sha256,
            decision,
            "integration-admin",
            "integration verdict",
            datetime.now(UTC),
        )
    )


def _wait_for_terminal(db_path: Path, sha256: str) -> None:
    reader = SQLiteVerdictReader(ConnectionFactory(db_path))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            state = reader.get_artifact_details(sha256).summary.state
        except Exception:  # worker may be between discovery transactions
            state = None
        if state in {
            ArtifactState.ALLOW,
            ArtifactState.REVIEW,
            ArtifactState.DENY,
            ArtifactState.ERROR,
        }:
            return
        time.sleep(0.05)
    raise AssertionError(f"artifact {sha256} did not reach a terminal state")


def _request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    request = urllib.request.Request(  # noqa: S310,RUF100 - loopback only
        url,
        method=method,
        headers=headers or {},
    )
    try:
        with _OPENER.open(request, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        with error:
            return error.code, error.read()


def test_official_devpi_server_fixture_exercises_guardian_routes(
    devpi_server,
    tmp_path: Path,
) -> None:
    wheel = _build_wheel(tmp_path, "1.0.0")
    content = wheel.read_bytes()
    sha256 = hashlib.sha256(content).hexdigest()
    devpi_server.api("upload", str(wheel))

    base_url = f"{devpi_server.uri.rstrip('/')}/"
    stage = f"{devpi_server.user}/{devpi_server.index}"
    simple_path = f"/{stage}/+simple/demo-guardian/"
    simple_url = urllib.parse.urljoin(base_url, simple_path)
    simple_status, simple_body = _request(simple_url)
    assert simple_status == 200
    parser = Links()
    parser.feed(simple_body.decode("utf-8"))
    wheel_links = [
        anchor["href"]
        for anchor in parser.anchors
        if wheel.name in urllib.parse.unquote(anchor.get("href") or "")
    ]
    assert len(wheel_links) == 1
    direct_url = urllib.parse.urljoin(simple_url, wheel_links[0] or "")
    assert f"/{devpi_server.user}/{devpi_server.index}/+f/" in direct_url

    for method in ("GET", "HEAD"):
        status, body = _request(direct_url, method=method)
        assert status == 404
        assert content not in body
        assert sha256.encode() not in body
        if method == "HEAD":
            assert body == b""

    guardian_db = Path(devpi_server.server_dir) / "guardian" / "guardian.db"
    assert guardian_db.is_file()
    store = SQLiteArtifactStore(
        ConnectionFactory(guardian_db),
        RecordingAuditWriter(),
    )
    _discover(
        store,
        sha256=sha256,
        content=content,
        version="1.0.0",
        filename=wheel.name,
        direct_url=direct_url,
        stage=f"{devpi_server.user}/{devpi_server.index}",
    )
    _wait_for_terminal(guardian_db, sha256)
    _manual_allow(store, sha256, "integration allow")

    assert _request(direct_url) == (200, content)
    allowed_head_status, allowed_head_body = _request(
        direct_url,
        method="HEAD",
    )
    assert allowed_head_status == 200
    assert allowed_head_body == b""

    plus_e_url = urllib.parse.urljoin(
        base_url,
        f"/{devpi_server.user}/{devpi_server.index}/+e/"
        "missing/demo_guardian-9.9.9-py3-none-any.whl",
    )
    for method in ("GET", "HEAD"):
        status, body = _request(plus_e_url, method=method)
        assert status == 503
        assert content not in body
        assert sha256.encode() not in body
        if method == "HEAD":
            assert body == b""


def test_guardian_index_filters_real_simple_responses_and_downloads(
    devpi_server,
    tmp_path: Path,
) -> None:
    base_stage = f"{devpi_server.user}/guardian-source"
    guardian_stage = f"{devpi_server.user}/guardian-protected"
    devpi_server.api("index", "-c", base_stage, "bases=")

    releases = []
    for version in ("11.0.0", "12.0.0", "13.0.0"):
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
    base_simple_path = f"/{base_stage}/+simple/demo-guardian/"
    guardian_simple_path = f"/{guardian_stage}/+simple/demo-guardian/"
    base_simple_url = urllib.parse.urljoin(base_url, base_simple_path)
    guardian_simple_url = urllib.parse.urljoin(base_url, guardian_simple_path)

    base_status, base_body = _request(base_simple_url)
    assert base_status == 200
    base_parser = Links()
    base_parser.feed(base_body.decode("utf-8"))

    def html_record(anchor):
        href = anchor.get("href")
        assert href is not None
        parsed = urllib.parse.urlsplit(href)
        hashes = urllib.parse.parse_qs(parsed.fragment)
        sha256_values = hashes.get("sha256")
        assert sha256_values is not None
        return {
            "filename": urllib.parse.unquote(parsed.path.rsplit("/", 1)[-1]),
            "sha256": sha256_values[0],
            "requires-python": anchor.get("data-requires-python"),
            "yanked": anchor.get("data-yanked"),
            "core-metadata": anchor.get("data-core-metadata"),
            "dist-info-metadata": anchor.get("data-dist-info-metadata"),
        }

    base_html = [html_record(anchor) for anchor in base_parser.anchors]
    direct_urls = {
        record["sha256"]: urllib.parse.urljoin(
            base_simple_url,
            anchor["href"] or "",
        )
        for record, anchor in zip(base_html, base_parser.anchors, strict=True)
    }
    expected_digests = {release["sha256"] for release in releases}
    assert {record["sha256"] for record in base_html} == expected_digests

    guardian_db = Path(devpi_server.server_dir) / "guardian" / "guardian.db"
    store = SQLiteArtifactStore(
        ConnectionFactory(guardian_db),
        RecordingAuditWriter(),
    )
    allowed, denied, unscanned = releases
    for release, decision in (
        (allowed, Decision.ALLOW),
        (denied, Decision.DENY),
    ):
        digest = release["sha256"]
        _discover(
            store,
            sha256=digest,
            content=release["content"],
            version=release["version"],
            filename=release["filename"],
            direct_url=direct_urls[digest],
            stage=base_stage,
        )
        _wait_for_terminal(guardian_db, digest)
        _manual_decision(store, digest, decision)

    guardian_status, guardian_body = _request(guardian_simple_url)
    assert guardian_status == 200
    guardian_parser = Links()
    guardian_parser.feed(guardian_body.decode("utf-8"))
    guardian_html = [html_record(anchor) for anchor in guardian_parser.anchors]
    assert guardian_html == [
        record for record in base_html if record["sha256"] == allowed["sha256"]
    ]

    json_headers = {"Accept": "application/vnd.pypi.simple.v1+json"}

    def json_records(url):
        status, body = _request(url, headers=json_headers)
        assert status == 200
        payload = json.loads(body)
        return [
            {
                "filename": item["filename"],
                "sha256": item["hashes"]["sha256"],
                "requires-python": item.get("requires-python"),
                "yanked": item.get("yanked"),
                "core-metadata": item.get("core-metadata"),
            }
            for item in payload["files"]
        ]

    base_json = json_records(base_simple_url)
    guardian_json = json_records(guardian_simple_url)
    assert guardian_json == [
        record for record in base_json if record["sha256"] == allowed["sha256"]
    ]

    assert _request(direct_urls[allowed["sha256"]]) == (
        200,
        allowed["content"],
    )
    for blocked in (denied, unscanned):
        status, body = _request(direct_urls[blocked["sha256"]])
        assert status == 404
        assert blocked["content"] not in body
