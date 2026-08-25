from __future__ import annotations

import hashlib
from io import BytesIO
from types import SimpleNamespace

from devpi_guardian.worker.quarantine import QuarantineStore
from devpi_guardian.worker.upload import PrivateUploadConnector


def test_private_upload_publishes_before_discovery_and_never_uses_url(tmp_path):
    payload = b"private wheel"
    digest = hashlib.sha256(payload).hexdigest()
    events = []

    class Entry:
        def __init__(self):
            self.hashes = {"sha256": digest}
            self.file_size = len(payload)

        def file_open_read(self):
            return BytesIO(payload)

    class Store:
        def discover_artifact(self, artifact, release):
            events.append("artifact_discovered")

    connector = PrivateUploadConnector(
        quarantine=QuarantineStore(tmp_path / "q", max_size_bytes=100),
        store=Store(),
        event=events.append,
    )
    connector.capture(
        stage="root/pypi",
        project="demo",
        version="1.0",
        link=SimpleNamespace(
            entry=Entry(), basename="demo-1.0.whl", href="https://public.invalid/+f/not-trusted"
        ),
    )
    assert events == ["quarantine_published", "artifact_discovered"]
