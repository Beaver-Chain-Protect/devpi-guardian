from __future__ import annotations

import hashlib
import stat
import threading
import time
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path

import pytest

from devpi_guardian.verdicts.db import ConnectionFactory
from devpi_guardian.verdicts.models import ArtifactState, Decision, ManualOverrideInput
from devpi_guardian.verdicts.reader import SQLiteVerdictReader
from devpi_guardian.verdicts.store import SQLiteArtifactStore
from devpi_guardian.worker.discovery import DiscoveryCandidate, FileDiscoverySink
from tests.conftest import RecordingAuditWriter
from tests.integration.test_direct_download import Links, _build_wheel

pytestmark = pytest.mark.integration


def _wait_until(predicate, *, timeout: float = 15.0, description: str) -> object:
    deadline = time.monotonic() + timeout
    wake = threading.Event()
    while True:
        result = predicate()
        if result:
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"timed out waiting for {description}")
        wake.wait(min(0.05, remaining))


def _direct_url(running_devpi, filename: str) -> str:
    simple_path = "/root/dev/+simple/demo-guardian/"
    response = running_devpi.request(simple_path)
    assert response.status == 200
    parser = Links()
    parser.feed(response.body.decode("utf-8"))
    hrefs = [
        anchor["href"]
        for anchor in parser.anchors
        if filename in urllib.parse.unquote(anchor.get("href") or "")
    ]
    assert len(hrefs) == 1
    return urllib.parse.urljoin(
        urllib.parse.urljoin(running_devpi.base_url, simple_path),
        hrefs[0] or "",
    )


def _metadata_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, f"{parsed.path}.metadata", parsed.query, parsed.fragment)
    )


def _cas_path(running_devpi, sha256: str) -> Path:
    root = running_devpi.server_dir.parent / f".{running_devpi.server_dir.name}-guardian-quarantine"
    return root / "objects" / "sha256" / sha256[:2] / sha256[2:4] / sha256


def _quarantine_root(running_devpi) -> Path:
    return running_devpi.server_dir.parent / f".{running_devpi.server_dir.name}-guardian-quarantine"


def _terminal(reader: SQLiteVerdictReader, sha256: str) -> bool:
    try:
        state = reader.get_artifact_details(sha256).summary.state
    except Exception:
        return False
    return state in {
        ArtifactState.ALLOW,
        ArtifactState.REVIEW,
        ArtifactState.DENY,
        ArtifactState.ERROR,
    }


def test_private_upload_reaches_cas_verdict_and_allow_only_download(
    running_devpi,
    tmp_path: Path,
) -> None:
    wheel = _build_wheel(tmp_path, "1.0.0")
    content = wheel.read_bytes()
    sha256 = hashlib.sha256(content).hexdigest()

    running_devpi.api("upload", str(wheel))
    direct_url = _direct_url(running_devpi, wheel.name)
    metadata_url = _metadata_url(direct_url)
    reader = SQLiteVerdictReader(ConnectionFactory(running_devpi.guardian_db))

    for url in (direct_url, metadata_url):
        for method in ("GET", "HEAD"):
            assert running_devpi.request(url, method=method).status == 404
    assert _wait_until(
        lambda: _cas_path(running_devpi, sha256).is_file(),
        description="private upload CAS object",
    )
    cas_path = _cas_path(running_devpi, sha256)
    quarantine_root = _quarantine_root(running_devpi)
    assert stat.S_IMODE(quarantine_root.stat().st_mode) == 0o700
    assert not quarantine_root.is_relative_to(running_devpi.server_dir)
    assert cas_path.read_bytes() == content
    assert _wait_until(
        lambda: _terminal(reader, sha256),
        description="private upload terminal verdict",
    )

    for url in (direct_url, metadata_url):
        for method in ("GET", "HEAD"):
            assert running_devpi.request(url, method=method).status == 404

    store = SQLiteArtifactStore(
        ConnectionFactory(running_devpi.guardian_db), RecordingAuditWriter()
    )
    store.set_manual_override(
        ManualOverrideInput(
            sha256,
            Decision.ALLOW,
            "integration-admin",
            "allow E2E fixture artifact",
            datetime.now(UTC),
        )
    )
    assert running_devpi.request(direct_url).status == 200
    assert running_devpi.request(direct_url).body == content
    assert running_devpi.request(direct_url, method="HEAD").status == 200
    assert running_devpi.request(metadata_url).status == 200
    assert running_devpi.request(metadata_url, method="HEAD").status == 200


def test_mirror_bytes_use_internal_stage_client_not_guardian_public_url(
    running_mirror_devpi,
) -> None:
    artifact = running_mirror_devpi.mirror_artifact
    worker = running_mirror_devpi.mirror_worker_artifact
    assert artifact is not None
    assert worker is not None
    assert running_mirror_devpi.mirror_upstream_requests is not None
    reader = SQLiteVerdictReader(ConnectionFactory(running_mirror_devpi.guardian_db))
    upstream_before_public = len(running_mirror_devpi.mirror_upstream_requests)
    assert running_mirror_devpi.request(artifact.direct_path).status in {404, 503}
    public_requests = running_mirror_devpi.mirror_upstream_requests[upstream_before_public:]
    assert all(artifact.filename not in path for path in public_requests)
    worker_url = urllib.parse.urljoin(running_mirror_devpi.base_url, worker.direct_path)
    queue = FileDiscoverySink(running_mirror_devpi.guardian_db.parent / "discovery")
    queue.discover(
        DiscoveryCandidate(
            "root/guardian",
            worker.project,
            worker.filename,
            worker.sha256,
            worker_url,
        )
    )
    _wait_until(
        lambda: _cas_path(running_mirror_devpi, worker.sha256).is_file(),
        description="mirrored worker artifact CAS object",
    )
    worker_cas = _cas_path(running_mirror_devpi, worker.sha256)
    assert worker_cas.read_bytes() == worker.content
    assert stat.S_IMODE(_quarantine_root(running_mirror_devpi).stat().st_mode) == 0o700
    assert _wait_until(
        lambda: _terminal(reader, worker.sha256),
        description="mirrored worker artifact terminal verdict",
    )
    new_requests = running_mirror_devpi.mirror_upstream_requests[upstream_before_public:]
    assert any(worker.filename in path for path in new_requests)
    assert all("/root/pypi/+e/" not in path for path in new_requests)
    assert running_mirror_devpi.request(artifact.direct_path).status in {404, 503}
