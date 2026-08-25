from __future__ import annotations

import hashlib
from io import BytesIO
from types import SimpleNamespace

import pytest

from devpi_guardian.worker.models import VerifiedArtifact
from devpi_guardian.worker.quarantine import QuarantineError, QuarantineStore
from devpi_guardian.worker.upload import PrivateUploadConnector


def test_private_upload_publishes_before_discovery_and_never_uses_url(tmp_path):
    payload = b"private wheel"
    digest = hashlib.sha256(payload).hexdigest()
    events = []

    class Entry:
        def __init__(self):
            self.hashes = {"sha256": digest}
            self.size_calls = 0

        def file_size(self):
            self.size_calls += 1
            return len(payload)

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
    entry = Entry()
    connector.capture(
        stage="root/pypi",
        project="demo",
        version="1.0",
        link=SimpleNamespace(
            entry=entry,
            basename="demo-1.0-py3-none-any.whl",
            href="https://public.invalid/+f/not-trusted",
        ),
    )
    assert events == ["quarantine_published", "artifact_discovered"]
    assert entry.size_calls == 1


def test_private_upload_uses_canonical_stage_and_metadata_fidelity(tmp_path):
    payload = b"private wheel"
    digest = hashlib.sha256(payload).hexdigest()

    class Entry:
        def __init__(self):
            self.hashes = {"sha256": digest}

        def file_size(self):
            return len(payload)

        def file_open_read(self):
            return BytesIO(payload)

    class Stage:
        name = "root/pypi"
        user = object()
        index = object()

    seen = []

    class Store:
        def discover_artifact(self, artifact, release):
            seen.append((artifact, release))

    PrivateUploadConnector(
        quarantine=QuarantineStore(tmp_path / "q", max_size_bytes=100),
        store=Store(),
    ).capture(
        stage=Stage(),
        project="Demo_Pkg",
        version="1.0",
        link=SimpleNamespace(entry=Entry(), basename="demo_pkg-1.0-py3-none-any.whl"),
    )
    [(artifact, release)] = seen
    assert release.stage == "root/pypi"
    assert release.project == "Demo_Pkg"
    assert release.version == "1.0"
    assert release.filename == "demo_pkg-1.0-py3-none-any.whl"
    assert artifact.sha256 == digest and artifact.size_bytes == len(payload)
    assert release.discovered_at == artifact.discovered_at


def test_private_upload_rejects_inconsistent_filename_metadata(tmp_path):
    payload = b"private wheel"
    digest = hashlib.sha256(payload).hexdigest()

    class Entry:
        def __init__(self):
            self.hashes = {"sha256": digest}

        def file_size(self):
            return len(payload)

        def file_open_read(self):
            return BytesIO(payload)

    connector = PrivateUploadConnector(
        quarantine=QuarantineStore(tmp_path / "q", max_size_bytes=100),
        store=SimpleNamespace(discover_artifact=lambda *_: None),
    )
    with pytest.raises(QuarantineError):
        connector.capture(
            stage="root/pypi",
            project="other",
            version="1.0",
            link=SimpleNamespace(entry=Entry(), basename="demo-1.0-py3-none-any.whl"),
        )


def test_verified_close_failure_prevents_event_and_discovery():
    payload = b"private wheel"
    digest = hashlib.sha256(payload).hexdigest()
    events = []

    class CloseError(BytesIO):
        def close(self):
            raise OSError("verified close failed")

    verified = VerifiedArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0",
        filename="demo-1.0-py3-none-any.whl",
        sha256=digest,
        size_bytes=len(payload),
        _stream=CloseError(payload),
    )

    class Entry:
        def __init__(self):
            self.hashes = {"sha256": digest}

        def file_size(self):
            return len(payload)

        def file_open_read(self):
            return BytesIO(payload)

    class Quarantine:
        def persist(self, candidate, chunks):
            return verified

    class Store:
        def discover_artifact(self, *args):
            events.append("artifact_discovered")

    with pytest.raises(QuarantineError):
        PrivateUploadConnector(quarantine=Quarantine(), store=Store(), event=events.append).capture(
            stage="root/pypi",
            project="demo",
            version="1.0",
            link=SimpleNamespace(entry=Entry(), basename="demo-1.0-py3-none-any.whl"),
        )
    assert events == []
