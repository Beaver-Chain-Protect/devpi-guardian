from __future__ import annotations

from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path

from devpi_guardian.analyzers import Finding
from devpi_guardian.verdicts.models import ClaimedArtifact, Decision, VerdictInput
from devpi_guardian.worker.models import (
    AnalysisBundle,
    AnalysisEvidence,
    AnalysisFileDiff,
    AnalysisReport,
    AnalysisStep,
    VerifiedArtifact,
)
from devpi_guardian.worker.pipeline import QuarantineWorker, WorkerCycleStatus

SHA256 = "a" * 64


class TrackingStream(BytesIO):
    def __init__(self, value: bytes) -> None:
        super().__init__(value)
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        super().close()


def artifact(tmp_path: Path) -> VerifiedArtifact:
    return VerifiedArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0.0",
        filename="demo-1.0.0-py3-none-any.whl",
        sha256=SHA256,
        size_bytes=5,
        _stream=BytesIO(b"wheel"),
    )


class Store:
    def __init__(self, claim: ClaimedArtifact | None) -> None:
        self.claim = claim
        self.recorded = []
        self.errors = []

    def claim_next(self, worker_id, lease_until):
        self.claim_args = worker_id, lease_until
        claim, self.claim = self.claim, None
        return claim

    def record_verdict(self, claim, verdict, evidence):
        self.recorded.append((claim, verdict, tuple(evidence)))

    def mark_analysis_error(self, claim, error):
        self.errors.append((claim, error))

    def recover_expired_claims(self, now):
        self.recovered_at = now
        return 2


class Preparer:
    def __init__(self, bundle) -> None:
        self.bundle = bundle

    def prepare(self, claim):
        self.claim = claim
        return self.bundle


class Engine:
    def __init__(self, report) -> None:
        self.report = report

    def analyze(self, bundle):
        self.bundle = bundle
        return self.report


class Policy:
    def evaluate(self, target, report):
        self.call = target, report
        return VerdictInput(
            sha256=target.sha256,
            decision=Decision.REVIEW,
            score=30,
            policy_version="policy-1",
            analyzer_version=report.analyzer_version,
            baseline_sha256=report.baseline_sha256,
            baseline_tier=report.baseline_tier,
        )


class AllowPolicy:
    def evaluate(self, target, report):
        return VerdictInput(
            sha256=target.sha256,
            decision=Decision.ALLOW,
            score=0,
            policy_version="policy-1",
            analyzer_version=report.analyzer_version,
            baseline_sha256=report.baseline_sha256,
            baseline_tier=report.baseline_tier,
        )


def make_claim(now: datetime) -> ClaimedArtifact:
    return ClaimedArtifact(
        sha256=SHA256,
        size_bytes=5,
        worker_id="worker-1",
        lease_expires_at=now + timedelta(minutes=5),
        lease_token="b" * 64,
    )


def test_worker_runs_one_analysis_and_records_attributed_evidence(tmp_path) -> None:
    now = datetime(2026, 8, 21, tzinfo=UTC)
    target = artifact(tmp_path)
    bundle = AnalysisBundle(target=target)
    finding = Finding(
        rule="credential_to_network",
        action="DENY",
        file="demo/update.py",
        line=41,
        snippet="requests.post(secret)",
        message="credential is sent to the network",
        source="os.environ",
        sink="requests.post",
    )
    report = AnalysisReport(
        analyzer_version="analyzers-1",
        has_baseline=True,
        baseline_sha256="c" * 64,
        baseline_tier="same_tag",
        evidence=(
            AnalysisEvidence(
                analyzer="F7",
                finding=finding,
                origin="diff_changed",
                baseline_tier="same_tag",
            ),
        ),
        steps=(AnalysisStep("F7", "completed"),),
        file_diff=AnalysisFileDiff(
            added=("demo/new.py",),
            changed=("demo/update.py",),
            removed=(),
        ),
    )
    store = Store(make_claim(now))
    preparer = Preparer(bundle)
    engine = Engine(report)
    policy = Policy()
    worker = QuarantineWorker(
        store=store,
        preparer=preparer,
        analysis_engine=engine,
        policy_engine=policy,
        worker_id="worker-1",
        lease_duration=timedelta(minutes=5),
        now=lambda: now,
    )

    result = worker.run_once()

    assert result.status is WorkerCycleStatus.COMPLETED
    assert result.sha256 == SHA256
    assert engine.bundle is bundle
    assert len(store.recorded) == 1
    _, verdict, evidence = store.recorded[0]
    assert verdict.decision is Decision.REVIEW
    assert len(evidence) == 2
    assert evidence[0].rule_id == "credential_to_network"
    assert evidence[0].details == {
        "analyzer": "F7",
        "baseline_tier": "same_tag",
        "fingerprint": evidence[0].details["fingerprint"],
        "origin": "diff_changed",
        "sink": "requests.post",
        "snippet": "requests.post(secret)",
        "source": "os.environ",
    }
    assert evidence[1].rule_id == "baseline_file_diff"
    assert evidence[1].action is Decision.ALLOW
    assert evidence[1].details == {
        "analyzer": "F7",
        "kind": "file_diff",
        "added": ("demo/new.py",),
        "changed": ("demo/update.py",),
        "removed": (),
    }
    assert store.errors == []
    assert target._stream.closed


def test_worker_marks_claim_error_when_preparation_fails(tmp_path) -> None:
    now = datetime(2026, 8, 21, tzinfo=UTC)
    store = Store(make_claim(now))

    class BrokenPreparer:
        def prepare(self, claim):
            raise RuntimeError("download failed")

    worker = QuarantineWorker(
        store=store,
        preparer=BrokenPreparer(),
        analysis_engine=Engine(None),
        policy_engine=Policy(),
        worker_id="worker-1",
        now=lambda: now,
    )

    result = worker.run_once()

    assert result.status is WorkerCycleStatus.ERROR
    assert result.sha256 == SHA256
    assert store.recorded == []
    assert store.errors == [(store.errors[0][0], "RuntimeError: download failed")]


def test_worker_returns_idle_without_calling_dependencies() -> None:
    now = datetime(2026, 8, 21, tzinfo=UTC)
    store = Store(None)
    worker = QuarantineWorker(
        store=store,
        preparer=object(),
        analysis_engine=object(),
        policy_engine=object(),
        worker_id="worker-1",
        now=lambda: now,
    )

    result = worker.run_once()

    assert result.status is WorkerCycleStatus.IDLE
    assert result.sha256 is None


def test_worker_recovers_expired_claims() -> None:
    now = datetime(2026, 8, 21, tzinfo=UTC)
    store = Store(None)
    worker = QuarantineWorker(
        store=store,
        preparer=object(),
        analysis_engine=object(),
        policy_engine=object(),
        worker_id="worker-1",
        now=lambda: now,
    )

    assert worker.recover_expired_claims() == 2
    assert store.recovered_at == now


def test_analysis_bundle_closes_distinct_and_shared_streams_once() -> None:
    shared = TrackingStream(b"shared")
    separate = TrackingStream(b"separate")
    target = VerifiedArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0",
        filename="demo.whl",
        sha256=SHA256,
        size_bytes=6,
        _stream=shared,
    )
    sdist = VerifiedArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0",
        filename="demo.tar.gz",
        sha256="b" * 64,
        size_bytes=6,
        _stream=shared,
    )
    wheel = VerifiedArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0",
        filename="demo2.whl",
        sha256="c" * 64,
        size_bytes=8,
        _stream=separate,
    )
    bundle = AnalysisBundle(target=target, same_release_sdist=sdist, same_release_wheel=wheel)

    bundle.close()
    bundle.close()

    assert shared.close_calls == 1
    assert separate.close_calls == 1
    assert shared.closed
    assert separate.closed


def test_worker_closes_bundle_when_analyzer_raises(tmp_path) -> None:
    now = datetime(2026, 8, 21, tzinfo=UTC)
    target = artifact(tmp_path)
    store = Store(make_claim(now))

    class BrokenEngine:
        def analyze(self, bundle):
            raise RuntimeError("analyzer failed")

    worker = QuarantineWorker(
        store=store,
        preparer=Preparer(AnalysisBundle(target=target)),
        analysis_engine=BrokenEngine(),
        policy_engine=Policy(),
        worker_id="worker-1",
        now=lambda: now,
    )

    assert worker.run_once().status is WorkerCycleStatus.ERROR
    assert target._stream.closed
    assert store.errors[0][1] == "RuntimeError: analyzer failed"


def test_worker_closes_bundle_when_policy_raises(tmp_path) -> None:
    now = datetime(2026, 8, 21, tzinfo=UTC)
    target = artifact(tmp_path)
    store = Store(make_claim(now))
    report = AnalysisReport(
        analyzer_version="analyzers-1",
        has_baseline=False,
        baseline_sha256=None,
        baseline_tier=None,
        evidence=(),
        steps=(AnalysisStep("F7", "skipped"),),
    )

    class BrokenPolicy:
        def evaluate(self, target, report):
            raise RuntimeError("policy failed")

    worker = QuarantineWorker(
        store=store,
        preparer=Preparer(AnalysisBundle(target=target)),
        analysis_engine=Engine(report),
        policy_engine=BrokenPolicy(),
        worker_id="worker-1",
        now=lambda: now,
    )

    assert worker.run_once().status is WorkerCycleStatus.ERROR
    assert target._stream.closed
    assert store.errors[0][1] == "RuntimeError: policy failed"


def test_worker_closes_bundle_when_verdict_recording_raises(tmp_path) -> None:
    now = datetime(2026, 8, 21, tzinfo=UTC)
    target = artifact(tmp_path)
    report = AnalysisReport(
        analyzer_version="analyzers-1",
        has_baseline=False,
        baseline_sha256=None,
        baseline_tier=None,
        evidence=(),
        steps=(AnalysisStep("F7", "skipped"),),
    )

    class BrokenStore(Store):
        def record_verdict(self, claim, verdict, evidence):
            raise RuntimeError("record failed")

    store = BrokenStore(make_claim(now))
    worker = QuarantineWorker(
        store=store,
        preparer=Preparer(AnalysisBundle(target=target)),
        analysis_engine=Engine(report),
        policy_engine=Policy(),
        worker_id="worker-1",
        now=lambda: now,
    )

    assert worker.run_once().status is WorkerCycleStatus.ERROR
    assert target._stream.closed
    assert store.errors[0][1] == "RuntimeError: record failed"


def test_worker_adds_configured_cooldown_to_automatic_allow(tmp_path) -> None:
    now = datetime(2026, 8, 23, tzinfo=UTC)
    target = artifact(tmp_path)
    report = AnalysisReport(
        analyzer_version="analyzers-1",
        has_baseline=False,
        baseline_sha256=None,
        baseline_tier=None,
        evidence=(),
        steps=(AnalysisStep("F7", "skipped", "no approved baseline"),),
    )
    store = Store(make_claim(now))
    worker = QuarantineWorker(
        store=store,
        preparer=Preparer(AnalysisBundle(target=target)),
        analysis_engine=Engine(report),
        policy_engine=AllowPolicy(),
        worker_id="worker-1",
        cooldown_duration=timedelta(hours=6),
        now=lambda: now,
    )

    assert worker.run_once().status is WorkerCycleStatus.COMPLETED
    verdict = store.recorded[0][1]
    assert verdict.created_at == now
    assert verdict.cooldown_until == now + timedelta(hours=6)
    assert target._stream.closed
