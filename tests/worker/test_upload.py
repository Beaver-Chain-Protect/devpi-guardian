from __future__ import annotations

import hashlib
from io import BytesIO
from types import SimpleNamespace

import pytest

from devpi_guardian.baseline.artifact_source import (
    _canonical_devpi_base,
    _validate_artifact_url,
)
from devpi_guardian.worker.models import VerifiedArtifact
from devpi_guardian.worker.quarantine import QuarantineError, QuarantineStore
from devpi_guardian.worker.upload import PrivateUploadConnector


def file_relpath(digest: str, filename: str, marker: str = "+f") -> str:
    if marker == "+f":
        return f"root/pypi/+f/{digest[:3]}/{digest[3:16]}/{filename}"
    return f"root/pypi/+e/abc/{filename}"


def test_private_upload_publishes_before_discovery_and_never_uses_url(tmp_path):
    payload = b"private wheel"
    digest = hashlib.sha256(payload).hexdigest()
    events = []

    class Entry:
        def __init__(self):
            self.hashes = {"sha256": digest}
            self.size_calls = 0
            self.relpath = file_relpath(digest, "demo-1.0-py3-none-any.whl")

        def file_size(self):
            self.size_calls += 1
            return len(payload)

        def file_open_read(self):
            return BytesIO(payload)

    class Store:
        def discover_artifact(self, artifact, release):
            events.append("artifact_discovered")

    quarantine = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    connector = PrivateUploadConnector(
        quarantine=quarantine,
        store=Store(),
        base_url="https://devpi.invalid/",
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
    quarantine.close()


def test_private_upload_uses_canonical_stage_and_metadata_fidelity(tmp_path):
    payload = b"private wheel"
    digest = hashlib.sha256(payload).hexdigest()

    class Entry:
        def __init__(self):
            self.hashes = {"sha256": digest}
            self.relpath = file_relpath(digest, "demo_pkg-1.0-py3-none-any.whl")

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

    quarantine = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    PrivateUploadConnector(
        quarantine=quarantine,
        store=Store(),
        base_url="https://devpi.invalid/",
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
    assert release.origin_url == (
        f"https://devpi.invalid:443/{file_relpath(digest, 'demo_pkg-1.0-py3-none-any.whl')}"
    )
    assert artifact.sha256 == digest and artifact.size_bytes == len(payload)
    assert release.discovered_at == artifact.discovered_at
    quarantine.close()


def test_private_upload_rejects_inconsistent_filename_metadata(tmp_path):
    payload = b"private wheel"
    digest = hashlib.sha256(payload).hexdigest()

    class Entry:
        def __init__(self):
            self.hashes = {"sha256": digest}
            self.relpath = file_relpath(digest, "demo-1.0-py3-none-any.whl")

        def file_size(self):
            return len(payload)

        def file_open_read(self):
            return BytesIO(payload)

    quarantine = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    connector = PrivateUploadConnector(
        quarantine=quarantine,
        store=SimpleNamespace(discover_artifact=lambda *_: None),
        base_url="https://devpi.invalid/",
    )
    with pytest.raises(QuarantineError):
        connector.capture(
            stage="root/pypi",
            project="other",
            version="1.0",
            link=SimpleNamespace(entry=Entry(), basename="demo-1.0-py3-none-any.whl"),
        )
    quarantine.close()


def test_private_upload_requires_canonical_base_url(tmp_path):
    import pytest

    for base_url in (
        "relative",
        "https://devpi.invalid//",
        "https://user:pass@devpi.invalid/",
        "https://devpi.invalid/?q=1",
        "https://devpi.invalid/#fragment",
        "https://devpi.invalid/%2e/",
    ):
        quarantine = QuarantineStore(
            tmp_path / ("q-" + str(abs(hash(base_url)))), max_size_bytes=100
        )
        with pytest.raises(ValueError):
            PrivateUploadConnector(
                quarantine=quarantine,
                store=SimpleNamespace(discover_artifact=lambda *_: None),
                base_url=base_url,
            )
        quarantine.close()


def test_private_upload_origin_matches_f6_artifact_url_grammar():
    payload = b"private wheel"
    digest = hashlib.sha256(payload).hexdigest()
    relpath = file_relpath(digest, "demo-1.0-py3-none-any.whl")
    origin = f"https://devpi.invalid:443/{relpath}"
    assert (
        _validate_artifact_url(origin, digest, _canonical_devpi_base("https://devpi.invalid"))
        == origin
    )


def test_verified_close_failure_prevents_event_and_discovery():
    payload = b"private wheel"
    digest = hashlib.sha256(payload).hexdigest()
    events = []

    class CloseError(BytesIO):
        def close(self):
            try:
                super().close()
            finally:
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
            self.relpath = file_relpath(digest, "demo-1.0-py3-none-any.whl")

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
        PrivateUploadConnector(
            quarantine=Quarantine(),
            store=Store(),
            base_url="https://devpi.invalid/",
            event=events.append,
        ).capture(
            stage="root/pypi",
            project="demo",
            version="1.0",
            link=SimpleNamespace(entry=Entry(), basename="demo-1.0-py3-none-any.whl"),
        )
    assert events == []


def test_verified_close_first_failure_retries_and_still_has_no_side_effects():
    payload = b"private wheel"
    digest = hashlib.sha256(payload).hexdigest()
    events = []

    class RetryClose(BytesIO):
        def __init__(self, value):
            super().__init__(value)
            self.attempts = 0

        def close(self):
            self.attempts += 1
            if self.attempts == 1:
                raise OSError("first close failed")
            super().close()

    verified_stream = RetryClose(payload)
    verified = VerifiedArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0",
        filename="demo-1.0-py3-none-any.whl",
        sha256=digest,
        size_bytes=len(payload),
        _stream=verified_stream,
    )

    class Entry:
        def __init__(self):
            self.hashes = {"sha256": digest}
            self.relpath = file_relpath(digest, "demo-1.0-py3-none-any.whl")

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

    import pytest

    with pytest.raises(QuarantineError):
        PrivateUploadConnector(
            quarantine=Quarantine(),
            store=Store(),
            base_url="https://devpi.invalid/",
            event=events.append,
        ).capture(
            stage="root/pypi",
            project="demo",
            version="1.0",
            link=SimpleNamespace(entry=Entry(), basename="demo-1.0-py3-none-any.whl"),
        )
    assert verified_stream.attempts == 2
    assert verified_stream.closed
    assert events == []
