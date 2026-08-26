from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from devpi_guardian.verdicts.models import ClaimedArtifact
from devpi_guardian.worker.models import ArtifactCandidate
from devpi_guardian.worker.pipeline import QuarantineWorker, WorkerCycleStatus
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
    published = quarantine.persist(wheel, [payload])
    published._stream.close()
    source = Source(wheel, (wheel, candidate("demo-1.0.0.tar.gz", b"missing")))
    bundle = QuarantineArtifactPreparer(source=source, quarantine=quarantine).prepare(
        claim(wheel, len(payload))
    )
    assert bundle.same_release_sdist is None
    bundle.close()
    quarantine.close()


@pytest.mark.parametrize("corrupt", [False, True], ids=["missing", "corrupt"])
def test_worker_fences_missing_or_corrupt_quarantine_object(tmp_path, corrupt):
    payload = b"wheel"
    wheel = candidate("demo-1.0.0-py3-none-any.whl", payload)
    quarantine = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    if corrupt:
        verified = quarantine.persist(wheel, [payload])
        verified._stream.close()
        (quarantine.root_path / quarantine.object_relative_path(wheel.sha256)).write_bytes(
            b"corrupt"
        )

    class ClaimStore:
        def __init__(self):
            self.claim = claim(wheel, len(payload))
            self.original_claim = self.claim
            self.errors = []
            self.recorded = []

        def claim_next(self, worker_id, lease_until):
            item, self.claim = self.claim, None
            return item

        def mark_analysis_error(self, item, error):
            self.errors.append((item, error))

        def record_verdict(self, item, verdict, evidence):
            raise AssertionError("verdict must not be recorded for missing CAS")

    class NeverCalled:
        def analyze(self, bundle):
            raise AssertionError("analysis must not run for missing CAS")

        def evaluate(self, target, report):
            raise AssertionError("policy must not run for missing CAS")

    store = ClaimStore()
    worker = QuarantineWorker(
        store=store,
        preparer=QuarantineArtifactPreparer(source=Source(wheel, ()), quarantine=quarantine),
        analysis_engine=NeverCalled(),
        policy_engine=NeverCalled(),
        worker_id="worker",
        now=lambda: datetime.now(UTC),
    )

    result = worker.run_once()

    assert result.status is WorkerCycleStatus.ERROR
    assert len(store.errors) == 1
    assert store.errors[0][0] == store.original_claim
    assert "quarantine" in store.errors[0][1].lower()
    quarantine.close()
