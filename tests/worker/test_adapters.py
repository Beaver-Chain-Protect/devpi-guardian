from __future__ import annotations

import pytest

from devpi_guardian.verdicts.models import ReleaseArtifact
from devpi_guardian.worker.adapters import (
    ConflictingArtifactMetadata,
    VerdictReaderCandidateSource,
)


class Reader:
    def __init__(self, releases) -> None:
        self.releases = releases

    def get_artifact_releases(self, sha256):
        return tuple(item for item in self.releases if item.sha256 == sha256)

    def list_release_artifacts(self, project, version):
        return tuple(
            item for item in self.releases if item.project == project and item.version == version
        )


def test_candidate_source_exposes_f5_metadata_contract() -> None:
    release = ReleaseArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0.0",
        filename="demo-1.0.0-py3-none-any.whl",
        sha256="a" * 64,
        origin_url="https://devpi.example/+f/demo.whl",
        size_bytes=42,
    )

    class IgnoringReader(Reader):
        def get_artifact_releases(self, sha256):
            return (release,)

    source = VerdictReaderCandidateSource(IgnoringReader((release,)))

    candidate = source.candidate_for(release.sha256)

    assert candidate.stage == release.stage
    assert candidate.project == release.project
    assert candidate.version == release.version
    assert candidate.filename == release.filename
    assert candidate.sha256 == release.sha256
    assert candidate.origin_url == release.origin_url
    assert candidate.expected_size_bytes == release.size_bytes


def test_candidate_source_rejects_wrong_requested_digest() -> None:
    release = ReleaseArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0.0",
        filename="demo.whl",
        sha256="b" * 64,
        origin_url="https://devpi.example/+f/demo.whl",
        size_bytes=42,
    )

    class IgnoringReader(Reader):
        def get_artifact_releases(self, sha256):
            return (release,)

    source = VerdictReaderCandidateSource(IgnoringReader((release,)))

    with pytest.raises(ValueError):
        source.candidate_for("a" * 64)


def test_candidate_source_rejects_conflicting_semantic_mappings() -> None:
    releases = (
        ReleaseArtifact(
            stage="root/a",
            project="demo",
            version="1.0.0",
            filename="demo.whl",
            sha256="a" * 64,
            origin_url="https://a/+f/demo.whl",
            size_bytes=42,
        ),
        ReleaseArtifact(
            stage="root/b",
            project="demo",
            version="1.0.0",
            filename="other.whl",
            sha256="a" * 64,
            origin_url="https://b/+f/other.whl",
            size_bytes=42,
        ),
    )
    source = VerdictReaderCandidateSource(Reader(releases))

    with pytest.raises(ConflictingArtifactMetadata):
        source.candidate_for("a" * 64)


def test_same_release_candidates_are_sorted_and_deduplicated() -> None:
    releases = (
        ReleaseArtifact(
            stage="root/z",
            project="demo",
            version="1.0.0",
            filename="demo.whl",
            sha256="a" * 64,
            origin_url="https://z/+f/demo.whl",
            size_bytes=42,
        ),
        ReleaseArtifact(
            stage="root/a",
            project="demo",
            version="1.0.0",
            filename="demo.whl",
            sha256="a" * 64,
            origin_url="https://a/+f/demo.whl",
            size_bytes=42,
        ),
    )
    candidate = VerdictReaderCandidateSource(Reader(releases)).candidate_for("a" * 64)
    result = VerdictReaderCandidateSource(
        Reader(tuple(reversed(releases)))
    ).same_release_candidates(candidate)

    assert len(result) == 1
    assert result[0].stage == "root/a"
