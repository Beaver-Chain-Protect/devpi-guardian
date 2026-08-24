"""Concrete adapters between F5 worker ports and F4's public reader."""

from __future__ import annotations

from typing import Protocol

from devpi_guardian.verdicts.models import ReleaseArtifact, validate_sha256

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


class ConflictingArtifactMetadata(ValueError):
    """Release mappings disagree about one artifact's semantic identity."""


class VerdictReaderCandidateSource:
    """Resolve claimed SHA-256 metadata without reading SQLite directly."""

    def __init__(self, reader: ReleaseMetadataReader) -> None:
        self._reader = reader

    def candidate_for(self, sha256: str) -> ArtifactCandidate:
        validate_sha256(sha256)
        releases = self._reader.get_artifact_releases(sha256)
        if not releases:
            raise UnknownArtifactMetadata(sha256)
        if any(release.sha256 != sha256 for release in releases):
            raise ConflictingArtifactMetadata("release mapping digest does not match request")
        identities = {
            (release.project, release.version, release.filename, release.size_bytes)
            for release in releases
        }
        if len(identities) != 1:
            raise ConflictingArtifactMetadata("release mappings disagree on artifact identity")
        return self._candidate(sorted(releases, key=self._sort_key)[0])

    def same_release_candidates(
        self,
        candidate: ArtifactCandidate,
    ) -> tuple[ArtifactCandidate, ...]:
        releases = self._reader.list_release_artifacts(
            candidate.project,
            candidate.version,
        )
        if any(
            release.project != candidate.project or release.version != candidate.version
            for release in releases
        ):
            raise ConflictingArtifactMetadata("same-release mapping has mismatched project/version")
        by_digest: dict[str, list[ReleaseArtifact]] = {}
        for release in releases:
            validate_sha256(release.sha256)
            by_digest.setdefault(release.sha256, []).append(release)
        selected: list[ReleaseArtifact] = []
        for digest, mappings in by_digest.items():
            identities = {
                (release.project, release.version, release.filename, release.size_bytes)
                for release in mappings
            }
            if len(identities) != 1:
                raise ConflictingArtifactMetadata(f"same-release mappings disagree for {digest}")
            selected.append(sorted(mappings, key=self._sort_key)[0])
        return tuple(self._candidate(release) for release in sorted(selected, key=self._sort_key))

    @staticmethod
    def _sort_key(release: ReleaseArtifact) -> tuple[str, ...]:
        return (
            release.project,
            release.version,
            release.filename,
            release.sha256,
            release.stage,
            release.origin_url,
            str(release.size_bytes),
        )

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
