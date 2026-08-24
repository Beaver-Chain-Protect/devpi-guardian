"""Lease-fenced F5 worker cycle."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
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
        cooldown_duration: timedelta = timedelta(hours=24),
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not worker_id.strip():
            raise ValueError("worker_id must not be blank")
        if lease_duration <= timedelta(0):
            raise ValueError("lease_duration must be positive")
        if cooldown_duration <= timedelta(0):
            raise ValueError("cooldown_duration must be positive")
        self._store = store
        self._preparer = preparer
        self._analysis_engine = analysis_engine
        self._policy_engine = policy_engine
        self._worker_id = worker_id
        self._lease_duration = lease_duration
        self._cooldown_duration = cooldown_duration
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

        bundle = None
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
            if verdict.baseline_tier != report.baseline_tier:
                raise ValueError("policy verdict does not match analyzed baseline tier")
            if verdict.decision is Decision.ALLOW:
                completed_at = self._now()
                verdict = replace(
                    verdict,
                    created_at=completed_at,
                    cooldown_until=completed_at + self._cooldown_duration,
                )
            evidence = tuple(_evidence_input(item) for item in report.evidence)
            if report.file_diff is not None:
                evidence += (
                    EvidenceInput(
                        rule_id="baseline_file_diff",
                        action=Decision.ALLOW,
                        file_path=None,
                        line=None,
                        message="baseline file delta",
                        details={
                            "analyzer": "F7",
                            "kind": "file_diff",
                            "added": list(report.file_diff.added),
                            "changed": list(report.file_diff.changed),
                            "removed": list(report.file_diff.removed),
                        },
                    ),
                )
            bundle.close()
            bundle = None
            self._store.record_verdict(claim, verdict, evidence)
        except BaseException as primary:
            if bundle is not None:
                try:
                    bundle.close()
                except BaseException as cleanup_error:
                    primary.add_note(
                        f"bundle cleanup failed: {type(cleanup_error).__name__}: {cleanup_error}"
                    )
            notes = getattr(primary, "__notes__", ())
            message = "; ".join([f"{type(primary).__name__}: {str(primary)[:512]}", *notes])[:4096]
            try:
                self._store.mark_analysis_error(claim, message)
            except BaseException as mark_error:
                primary.add_note(
                    f"mark_analysis_error failed: {type(mark_error).__name__}: {mark_error}"
                )
                raise primary from mark_error
            return WorkerCycle(WorkerCycleStatus.ERROR, claim.sha256)

        return WorkerCycle(WorkerCycleStatus.COMPLETED, claim.sha256)
