from __future__ import annotations

from devpi_guardian.verdicts.models import ReleaseArtifact
from devpi_guardian.worker.adapters import VerdictReaderCandidateSource


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
    source = VerdictReaderCandidateSource(Reader((release,)))

    candidate = source.candidate_for(release.sha256)

    assert candidate.stage == release.stage
    assert candidate.project == release.project
    assert candidate.version == release.version
    assert candidate.filename == release.filename
    assert candidate.sha256 == release.sha256
    assert candidate.origin_url == release.origin_url
    assert candidate.expected_size_bytes == release.size_bytes
