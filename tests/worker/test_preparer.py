from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from devpi_guardian.verdicts.models import ClaimedArtifact
from devpi_guardian.worker.models import ArtifactCandidate
from devpi_guardian.worker.preparer import HttpArtifactPreparer, QuarantineArtifactPreparer
from devpi_guardian.worker.quarantine import QuarantineStore


class Response:
    status_code = 200

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.closed = False

    def iter_content(self, chunk_size):
        yield self.payload[:3]
        yield self.payload[3:]

    def close(self):
        self.closed = True


class Session:
    def __init__(self, payloads) -> None:
        self.payloads = payloads
        self.responses = []

    def get(self, url, *, stream, timeout):
        assert stream is True
        assert timeout == 12
        response = Response(self.payloads[url])
        self.responses.append(response)
        return response


class Source:
    def __init__(self, target, siblings) -> None:
        self.target = target
        self.siblings = siblings

    def candidate_for(self, sha256):
        assert sha256 == self.target.sha256
        return self.target

    def same_release_candidates(self, candidate):
        assert candidate is self.target
        return self.siblings


def candidate(filename: str, payload: bytes) -> ArtifactCandidate:
    return ArtifactCandidate(
        stage="root/pypi",
        project="demo",
        version="1.0.0",
        filename=filename,
        sha256=hashlib.sha256(payload).hexdigest(),
        origin_url=f"https://devpi.example/+f/{filename}",
        expected_size_bytes=len(payload),
    )


def test_preparer_downloads_target_and_one_same_release_counterpart(tmp_path) -> None:
    wheel_payload = b"wheel payload"
    sdist_payload = b"sdist payload"
    wheel = candidate("demo-1.0.0-py3-none-any.whl", wheel_payload)
    sdist = candidate("demo-1.0.0.tar.gz", sdist_payload)
    session = Session({wheel.origin_url: wheel_payload, sdist.origin_url: sdist_payload})
    preparer = HttpArtifactPreparer(
        source=Source(wheel, (wheel, sdist)),
        session=session,
        quarantine=QuarantineStore(tmp_path, max_size_bytes=1024),
        timeout=12,
    )
    claim = ClaimedArtifact(
        sha256=wheel.sha256,
        size_bytes=len(wheel_payload),
        worker_id="worker-1",
        lease_expires_at=datetime.now(UTC) + timedelta(minutes=5),
        lease_token="f" * 64,
    )

    bundle = preparer.prepare(claim)

    assert bundle.target.local_path.read_bytes() == wheel_payload
    assert bundle.same_release_wheel == bundle.target
    assert bundle.same_release_sdist is not None
    assert bundle.same_release_sdist.local_path.read_bytes() == sdist_payload
    assert all(response.closed for response in session.responses)


def test_local_preparer_reuses_discovery_quarantine_files(tmp_path) -> None:
    wheel_payload = b"wheel payload"
    sdist_payload = b"sdist payload"
    wheel = candidate("demo-1.0.0-py3-none-any.whl", wheel_payload)
    sdist = candidate("demo-1.0.0.tar.gz", sdist_payload)
    quarantine = QuarantineStore(tmp_path, max_size_bytes=1024)
    expected_wheel = quarantine.persist(wheel, [wheel_payload])
    expected_sdist = quarantine.persist(sdist, [sdist_payload])
    preparer = QuarantineArtifactPreparer(
        source=Source(wheel, (wheel, sdist)),
        quarantine=quarantine,
    )
    claim = ClaimedArtifact(
        sha256=wheel.sha256,
        size_bytes=len(wheel_payload),
        worker_id="worker-1",
        lease_expires_at=datetime.now(UTC) + timedelta(minutes=5),
        lease_token="f" * 64,
    )

    bundle = preparer.prepare(claim)

    assert bundle.target == expected_wheel
    assert bundle.same_release_sdist == expected_sdist
