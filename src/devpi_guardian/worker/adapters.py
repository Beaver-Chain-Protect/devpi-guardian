"""Concrete adapters between F5 worker ports and F4's public reader."""

from __future__ import annotations

from typing import Protocol

from devpi_guardian.verdicts.models import ReleaseArtifact

from .models import ArtifactCandidate


class ReleaseMetadataReader(Protocol):
    def get_artifact_releases(self, sha256: str) -> tuple[ReleaseArtifact, ...]: ...

    def list_release_artifacts(
        self,
        project: str,
        version: str,
    ) -> tuple[ReleaseArtifact, ...]: ...


class UnknownArtifactMetadata(LookupError):
    pass


class VerdictReaderCandidateSource:
    """Resolve claimed SHA-256 metadata without reading SQLite directly."""

    def __init__(self, reader: ReleaseMetadataReader) -> None:
        self._reader = reader

    def candidate_for(self, sha256: str) -> ArtifactCandidate:
        releases = self._reader.get_artifact_releases(sha256)
        if not releases:
            raise UnknownArtifactMetadata(sha256)
        return self._candidate(releases[0])

    def same_release_candidates(
        self,
        candidate: ArtifactCandidate,
    ) -> tuple[ArtifactCandidate, ...]:
        releases = self._reader.list_release_artifacts(
            candidate.project,
            candidate.version,
        )
        return tuple(self._candidate(release) for release in releases)

    @staticmethod
    def _candidate(release: ReleaseArtifact) -> ArtifactCandidate:
        return ArtifactCandidate(
            stage=release.stage,
            project=release.project,
            version=release.version,
            filename=release.filename,
            sha256=release.sha256,
            origin_url=release.origin_url,
            expected_size_bytes=release.size_bytes,
        )
