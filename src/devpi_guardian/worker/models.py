"""Stable input and output models at the F5 component boundary."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from devpi_guardian.analyzers import Finding
from devpi_guardian.verdicts.models import validate_sha256

AnalyzerName = Literal["F7", "F8", "F9"]
AnalysisStatus = Literal["completed", "skipped", "error"]


def _required(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must not be blank")


@dataclass(frozen=True, slots=True)
class ArtifactCandidate:
    """Metadata sent to F5 before artifact bytes have been trusted."""

    stage: str
    project: str
    version: str
    filename: str
    sha256: str
    origin_url: str
    expected_size_bytes: int | None = None

    def __post_init__(self) -> None:
        for field_name in ("stage", "project", "version", "filename", "origin_url"):
            _required(getattr(self, field_name), field_name)
        validate_sha256(self.sha256)
        size = self.expected_size_bytes
        if size is not None and (type(size) is not int or size < 0):
            raise ValueError("expected_size_bytes must be a non-negative integer or None")


@dataclass(frozen=True, slots=True)
class VerifiedArtifact:
    """Artifact identity and local path after F5 has verified its bytes."""

    stage: str
    project: str
    version: str
    filename: str
    sha256: str
    size_bytes: int
    local_path: Path

    def __post_init__(self) -> None:
        for field_name in ("stage", "project", "version", "filename"):
            _required(getattr(self, field_name), field_name)
        validate_sha256(self.sha256)
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            raise ValueError("size_bytes must be a non-negative integer")
        if not isinstance(self.local_path, Path):
            raise ValueError("local_path must be a pathlib.Path")


@dataclass(frozen=True, slots=True)
class AnalysisBundle:
    """Verified paths supplied to the one F5 analysis-engine entry point."""

    target: VerifiedArtifact
    same_release_sdist: VerifiedArtifact | None = None
    same_release_wheel: VerifiedArtifact | None = None


@dataclass(frozen=True, slots=True)
class AnalysisEvidence:
    """One finding plus the analysis context needed by F10."""

    analyzer: AnalyzerName
    finding: Finding
    origin: str | None = None
    baseline_tier: str | None = None


@dataclass(frozen=True, slots=True)
class AnalysisStep:
    analyzer: AnalyzerName
    status: AnalysisStatus
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class AnalysisFileDiff:
    """Persistable F7 path delta for the F11 diff endpoint."""

    added: tuple[str, ...]
    changed: tuple[str, ...]
    removed: tuple[str, ...]

    def __post_init__(self) -> None:
        for field_name in ("added", "changed", "removed"):
            value = getattr(self, field_name)
            if not isinstance(value, tuple) or not all(
                isinstance(item, str) and item.strip() for item in value
            ):
                raise ValueError(f"{field_name} must be a tuple of nonblank paths")


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    """Combined F7/F8/F9 evidence passed to the policy engine."""

    analyzer_version: str
    has_baseline: bool
    baseline_sha256: str | None
    baseline_tier: str | None
    evidence: tuple[AnalysisEvidence, ...]
    steps: tuple[AnalysisStep, ...]
    file_diff: AnalysisFileDiff | None = None

    def __post_init__(self) -> None:
        _required(self.analyzer_version, "analyzer_version")
        if self.baseline_sha256 is not None:
            validate_sha256(self.baseline_sha256)
        if self.file_diff is not None and type(self.file_diff) is not AnalysisFileDiff:
            raise ValueError("file_diff must be an AnalysisFileDiff")
