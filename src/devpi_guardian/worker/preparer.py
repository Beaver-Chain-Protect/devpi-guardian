"""Turn claimed metadata into descriptor-backed analysis bundles."""

from __future__ import annotations

from collections.abc import Iterable
from contextlib import suppress
from typing import Protocol

from devpi_guardian.baseline import artifact_kind
from devpi_guardian.verdicts.models import ClaimedArtifact

from .models import AnalysisBundle, ArtifactCandidate, VerifiedArtifact
from .quarantine import QuarantineError, QuarantineStore

_CHUNK_SIZE = 1024 * 1024


class CandidateSource(Protocol):
    def candidate_for(self, sha256: str) -> ArtifactCandidate: ...

    def same_release_candidates(
        self, candidate: ArtifactCandidate
    ) -> tuple[ArtifactCandidate, ...]: ...


class HttpResponse(Protocol):
    status_code: int

    def iter_content(self, chunk_size: int) -> Iterable[bytes]: ...

    def close(self) -> None: ...


class HttpSession(Protocol):
    def get(self, url: str, *, stream: bool, timeout: float) -> HttpResponse: ...


def _close_bundle(bundle: AnalysisBundle) -> None:
    with suppress(BaseException):
        bundle.close()


class QuarantineArtifactPreparer:
    """Prepare claims only from objects already published in quarantine."""

    def __init__(self, *, source: CandidateSource, quarantine: QuarantineStore) -> None:
        self._source = source
        self._quarantine = quarantine

    def prepare(self, claim: ClaimedArtifact) -> AnalysisBundle:
        candidate = self._source.candidate_for(claim.sha256)
        self._check_claim(candidate, claim)
        target = self._required(candidate)
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
        except BaseException:
            bundle = AnalysisBundle(target=target)
            _close_bundle(bundle)
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


class HttpArtifactPreparer(QuarantineArtifactPreparer):
    """Compatibility preparer for an explicitly injected internal HTTP client."""

    def __init__(
        self,
        *,
        source: CandidateSource,
        session: HttpSession,
        quarantine: QuarantineStore,
        timeout: float = 30.0,
    ) -> None:
        super().__init__(source=source, quarantine=quarantine)
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._session = session
        self._timeout = timeout

    def prepare(self, claim: ClaimedArtifact) -> AnalysisBundle:
        candidate = self._source.candidate_for(claim.sha256)
        self._check_claim(candidate, claim)
        target: VerifiedArtifact | None = None
        counterpart: VerifiedArtifact | None = None
        try:
            target = self._download(candidate)
            target_kind = artifact_kind(target.filename)
            for item in self._source.same_release_candidates(candidate):
                if item.sha256 == candidate.sha256:
                    continue
                if artifact_kind(item.filename) != ("wheel" if target_kind == "sdist" else "sdist"):
                    continue
                counterpart = self._download(item)
                break
            if target_kind == "sdist":
                return AnalysisBundle(
                    target=target, same_release_sdist=target, same_release_wheel=counterpart
                )
            return AnalysisBundle(
                target=target, same_release_sdist=counterpart, same_release_wheel=target
            )
        except BaseException as primary:
            for artifact in (counterpart, target):
                if artifact is not None:
                    with suppress(BaseException):
                        artifact._stream.close()
            raise primary

    def _download(self, candidate: ArtifactCandidate) -> VerifiedArtifact:
        response = self._session.get(candidate.origin_url, stream=True, timeout=self._timeout)
        try:
            if getattr(response, "status_code", None) != 200:
                raise QuarantineError(
                    f"artifact download returned HTTP {getattr(response, 'status_code', None)}"
                )
            return self._quarantine.persist(
                candidate,
                (chunk for chunk in response.iter_content(_CHUNK_SIZE) if chunk),
            )
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()
