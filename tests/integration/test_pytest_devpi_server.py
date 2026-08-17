from __future__ import annotations

import hashlib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from devpi_guardian.verdicts.db import ConnectionFactory
from devpi_guardian.verdicts.models import Decision
from devpi_guardian.verdicts.store import SQLiteArtifactStore
from tests.conftest import RecordingAuditWriter
from tests.integration.test_direct_download import (
    Links,
    _build_wheel,
    _discover,
    _record_verdict,
)

pytestmark = pytest.mark.integration
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _request(url: str, *, method: str = "GET") -> tuple[int, bytes]:
    request = urllib.request.Request(url, method=method)
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
    _record_verdict(store, sha256, Decision.ALLOW)

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
