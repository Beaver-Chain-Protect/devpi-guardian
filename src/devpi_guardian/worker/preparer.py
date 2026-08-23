"""HTTP download and quarantine preparation for one claimed artifact."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from devpi_guardian.baseline import artifact_kind
from devpi_guardian.verdicts.models import ClaimedArtifact

from .models import AnalysisBundle, ArtifactCandidate, VerifiedArtifact
from .quarantine import QuarantineError, QuarantineStore

_CHUNK_SIZE = 1024 * 1024


class CandidateSource(Protocol):
    """F4-facing metadata contract required by the F5 worker."""

    def candidate_for(self, sha256: str) -> ArtifactCandidate: ...

    def same_release_candidates(
        self,
        candidate: ArtifactCandidate,
    ) -> tuple[ArtifactCandidate, ...]: ...


class HttpResponse(Protocol):
    status_code: int

    def iter_content(self, chunk_size: int) -> Iterable[bytes]: ...

    def close(self) -> None: ...


class HttpSession(Protocol):
    def get(self, url: str, *, stream: bool, timeout: float) -> HttpResponse: ...


class HttpArtifactPreparer:
    """Resolve claim metadata and produce verified local analysis paths."""

    def __init__(
        self,
        *,
        source: CandidateSource,
        session: HttpSession,
        quarantine: QuarantineStore,
        timeout: float = 30.0,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._source = source
        self._session = session
        self._quarantine = quarantine
        self._timeout = timeout

    def prepare(self, claim: ClaimedArtifact) -> AnalysisBundle:
        candidate = self._source.candidate_for(claim.sha256)
        if candidate.sha256 != claim.sha256:
            raise QuarantineError("candidate does not match claimed SHA-256")
        if candidate.expected_size_bytes not in (None, claim.size_bytes):
            raise QuarantineError("candidate does not match claimed size")

        target = self._download(candidate)
        target_kind = artifact_kind(target.filename)
        sdist = target if target_kind == "sdist" else None
        wheel = target if target_kind == "wheel" else None
        counterpart_kind = "wheel" if sdist is not None else "sdist"

        for counterpart in self._source.same_release_candidates(candidate):
            if counterpart.sha256 == candidate.sha256:
                continue
            if artifact_kind(counterpart.filename) != counterpart_kind:
                continue
            prepared = self._download(counterpart)
            if counterpart_kind == "sdist":
                sdist = prepared
            else:
                wheel = prepared
            break

        return AnalysisBundle(
            target=target,
            same_release_sdist=sdist,
            same_release_wheel=wheel,
        )

    def _download(self, candidate: ArtifactCandidate) -> VerifiedArtifact:
        response = self._session.get(
            candidate.origin_url,
            stream=True,
            timeout=self._timeout,
        )
        try:
            if getattr(response, "status_code", None) != 200:
                status = getattr(response, "status_code", None)
                raise QuarantineError(f"artifact download returned HTTP {status}")
            chunks = (chunk for chunk in response.iter_content(_CHUNK_SIZE) if chunk)
            return self._quarantine.persist(candidate, chunks)
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()
