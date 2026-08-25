from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from devpi_guardian.verdicts.models import ClaimedArtifact
from devpi_guardian.worker.models import ArtifactCandidate
from devpi_guardian.worker.preparer import QuarantineArtifactPreparer
from devpi_guardian.worker.quarantine import QuarantineStore


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


def test_only_descriptor_backed_preparer_is_available():
    import devpi_guardian.worker.preparer as preparer

    assert not hasattr(preparer, "HttpArtifactPreparer")


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
