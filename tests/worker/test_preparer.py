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
        self.payload, self.closed = payload, False

    def iter_content(self, chunk_size):
        yield self.payload[:3]
        yield self.payload[3:]

    def close(self):
        self.closed = True


class Session:
    def __init__(self, payloads):
        self.payloads, self.responses = payloads, []

    def get(self, url, *, stream, timeout):
        response = Response(self.payloads[url])
        self.responses.append(response)
        return response


class Source:
    def __init__(self, target, siblings):
        self.target, self.siblings = target, siblings

    def candidate_for(self, sha256):
        return self.target

    def same_release_candidates(self, candidate):
        return self.siblings


def candidate(filename: str, payload: bytes) -> ArtifactCandidate:
    return ArtifactCandidate(
        stage="root/pypi",
        project="demo",
        version="1.0.0",
        filename=filename,
        sha256=hashlib.sha256(payload).hexdigest(),
        origin_url=f"https://devpi.invalid/{filename}",
        expected_size_bytes=len(payload),
    )


def claim(item, size):
    return ClaimedArtifact(
        item.sha256, size, "worker", datetime.now(UTC) + timedelta(minutes=5), "f" * 64
    )


def test_http_preparer_closes_responses_and_returns_descriptor_streams(tmp_path):
    wheel_payload, sdist_payload = b"wheel", b"sdist"
    wheel, sdist = (
        candidate("demo-1.0.0-py3-none-any.whl", wheel_payload),
        candidate("demo-1.0.0.tar.gz", sdist_payload),
    )
    session = Session({wheel.origin_url: wheel_payload, sdist.origin_url: sdist_payload})
    bundle = HttpArtifactPreparer(
        source=Source(wheel, (wheel, sdist)),
        session=session,
        quarantine=QuarantineStore(tmp_path / "q", max_size_bytes=100),
    ).prepare(claim(wheel, len(wheel_payload)))
    with bundle.target.open_for_analysis() as stream:
        assert stream.read() == wheel_payload
    assert bundle.same_release_sdist is not None
    assert all(response.closed for response in session.responses)
    bundle.close()


def test_quarantine_preparer_closes_target_when_counterpart_fails(tmp_path):
    payload = b"wheel"
    wheel = candidate("demo-1.0.0-py3-none-any.whl", payload)
    quarantine = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    quarantine.persist(wheel, [payload])
    source = Source(wheel, (wheel, candidate("demo-1.0.0.tar.gz", b"missing")))
    bundle = QuarantineArtifactPreparer(source=source, quarantine=quarantine).prepare(
        claim(wheel, len(payload))
    )
    assert bundle.same_release_sdist is None
    bundle.close()
