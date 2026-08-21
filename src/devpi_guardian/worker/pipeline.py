"""Lease-fenced F5 worker cycle."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from devpi_guardian.analyzers import finding_fingerprint
from devpi_guardian.verdicts.interfaces import ArtifactStore
from devpi_guardian.verdicts.models import Decision, EvidenceInput

from .interfaces import AnalysisEngine, ArtifactPreparer, PolicyEngine
from .models import AnalysisEvidence


class WorkerCycleStatus(StrEnum):
    IDLE = "IDLE"
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class WorkerCycle:
    status: WorkerCycleStatus
    sha256: str | None


def _evidence_input(item: AnalysisEvidence) -> EvidenceInput:
    finding = item.finding
    details = {
        "analyzer": item.analyzer,
        "fingerprint": finding_fingerprint(finding),
        "snippet": finding.snippet,
    }
    optional = {
        "baseline_tier": item.baseline_tier,
        "origin": item.origin,
        "sink": finding.sink,
        "source": finding.source,
    }
    details.update({key: value for key, value in optional.items() if value is not None})
    return EvidenceInput(
        rule_id=finding.rule,
        action=Decision(finding.action),
        file_path=finding.file,
        line=finding.line,
        message=finding.message,
        details=details,
    )


class QuarantineWorker:
    """Claim and process at most one artifact per call."""

    def __init__(
        self,
        *,
        store: ArtifactStore,
        preparer: ArtifactPreparer,
        analysis_engine: AnalysisEngine,
        policy_engine: PolicyEngine,
        worker_id: str,
        lease_duration: timedelta = timedelta(minutes=5),
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not worker_id.strip():
            raise ValueError("worker_id must not be blank")
        if lease_duration <= timedelta(0):
            raise ValueError("lease_duration must be positive")
        self._store = store
        self._preparer = preparer
        self._analysis_engine = analysis_engine
        self._policy_engine = policy_engine
        self._worker_id = worker_id
        self._lease_duration = lease_duration
        self._now = now if now is not None else lambda: datetime.now(UTC)

    def recover_expired_claims(self) -> int:
        return self._store.recover_expired_claims(self._now())

    def run_once(self) -> WorkerCycle:
        claim = self._store.claim_next(
            self._worker_id,
            self._now() + self._lease_duration,
        )
        if claim is None:
            return WorkerCycle(WorkerCycleStatus.IDLE, None)

        try:
            bundle = self._preparer.prepare(claim)
            if bundle.target.sha256 != claim.sha256:
                raise ValueError("prepared artifact does not match claimed SHA-256")
            if bundle.target.size_bytes != claim.size_bytes:
                raise ValueError("prepared artifact does not match claimed size")
            report = self._analysis_engine.analyze(bundle)
            verdict = self._policy_engine.evaluate(bundle.target, report)
            if verdict.sha256 != claim.sha256:
                raise ValueError("policy verdict does not match claimed SHA-256")
            if verdict.baseline_sha256 != report.baseline_sha256:
                raise ValueError("policy verdict does not match analyzed baseline")
            if verdict.analyzer_version != report.analyzer_version:
                raise ValueError("policy verdict does not match analyzer version")
            evidence = tuple(_evidence_input(item) for item in report.evidence)
            self._store.record_verdict(claim, verdict, evidence)
        except Exception as exc:
            message = f"{type(exc).__name__}: {str(exc)[:512]}"
            self._store.mark_analysis_error(claim, message)
            return WorkerCycle(WorkerCycleStatus.ERROR, claim.sha256)

        return WorkerCycle(WorkerCycleStatus.COMPLETED, claim.sha256)
