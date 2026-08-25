"""Turn claimed metadata into descriptor-backed analysis bundles."""

from __future__ import annotations

from typing import Protocol

from devpi_guardian.baseline import artifact_kind
from devpi_guardian.verdicts.models import ClaimedArtifact

from .models import AnalysisBundle, ArtifactCandidate, VerifiedArtifact
from .quarantine import QuarantineError, QuarantineStore


class CandidateSource(Protocol):
    def candidate_for(self, sha256: str) -> ArtifactCandidate: ...

    def same_release_candidates(
        self, candidate: ArtifactCandidate
    ) -> tuple[ArtifactCandidate, ...]: ...


def _close_artifacts(primary: BaseException, *artifacts: VerifiedArtifact | None) -> None:
    seen: set[int] = set()
    for artifact in artifacts:
        if artifact is None or id(artifact._stream) in seen:
            continue
        seen.add(id(artifact._stream))
        try:
            artifact._stream.close()
        except BaseException as cleanup:
            primary.add_note(f"artifact cleanup failed: {type(cleanup).__name__}: {cleanup}")


class QuarantineArtifactPreparer:
    """Prepare claims only from objects already published in quarantine."""

    def __init__(self, *, source: CandidateSource, quarantine: QuarantineStore) -> None:
        self._source = source
        self._quarantine = quarantine

    def prepare(self, claim: ClaimedArtifact) -> AnalysisBundle:
        candidate = self._source.candidate_for(claim.sha256)
        self._check_claim(candidate, claim)
        target = self._required(candidate)
        prepared: VerifiedArtifact | None = None
        try:
            target_kind = artifact_kind(target.filename)
            sdist = target if target_kind == "sdist" else None
            wheel = target if target_kind == "wheel" else None
            counterpart_kind = "wheel" if sdist is not None else "sdist"
            for counterpart in self._source.same_release_candidates(candidate):
                if counterpart.sha256 == candidate.sha256:
                    continue
                if artifact_kind(counterpart.filename) != counterpart_kind:
                    continue
                prepared = self._quarantine.get_verified(counterpart)
                if prepared is None:
                    continue
                if counterpart_kind == "sdist":
                    sdist = prepared
                else:
                    wheel = prepared
                break
            return AnalysisBundle(target=target, same_release_sdist=sdist, same_release_wheel=wheel)
        except BaseException as primary:
            _close_artifacts(primary, target, prepared)
            raise

    def _required(self, candidate: ArtifactCandidate) -> VerifiedArtifact:
        verified = self._quarantine.get_verified(candidate)
        if verified is None:
            raise QuarantineError("verified artifact is missing from quarantine")
        return verified

    @staticmethod
    def _check_claim(candidate: ArtifactCandidate, claim: ClaimedArtifact) -> None:
        if candidate.sha256 != claim.sha256:
            raise QuarantineError("candidate does not match claimed SHA-256")
        if candidate.expected_size_bytes not in (None, claim.size_bytes):
            raise QuarantineError("candidate does not match claimed size")
