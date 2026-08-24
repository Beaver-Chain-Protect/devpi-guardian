"""Stable input and output models at the F5 component boundary."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from typing import BinaryIO, Literal

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
    """Artifact identity with an owned, already-verified binary stream."""

    stage: str
    project: str
    version: str
    filename: str
    sha256: str
    size_bytes: int
    _stream: BinaryIO = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        for field_name in ("stage", "project", "version", "filename"):
            _required(getattr(self, field_name), field_name)
        validate_sha256(self.sha256)
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            raise ValueError("size_bytes must be a non-negative integer")
        if not all(
            callable(getattr(self._stream, name, None))
            for name in ("read", "seek", "tell", "close")
        ):
            raise ValueError("_stream must be a seekable binary stream")
        try:
            position = self._stream.tell()
            sample = self._stream.read(0)
            self._stream.seek(position)
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError("_stream must be a seekable binary stream") from exc
        if not isinstance(sample, bytes):
            raise ValueError("_stream must be a binary stream")

    def open_for_analysis(self) -> AbstractContextManager[BinaryIO]:
        """Rewind the owned stream and close it when this read scope exits."""
        return _RewoundOwnedStream(self._stream)


class _RewoundOwnedStream(AbstractContextManager[BinaryIO]):
    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream

    def __enter__(self) -> BinaryIO:
        if self._stream.closed:
            raise ValueError("verified artifact stream is already closed")
        self._stream.seek(0)
        return self._stream

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self._stream.close()


@dataclass(frozen=True, slots=True)
class AnalysisBundle:
    """Verified streams supplied to the one F5 analysis-engine entry point."""

    target: VerifiedArtifact
    same_release_sdist: VerifiedArtifact | None = None
    same_release_wheel: VerifiedArtifact | None = None
    _closed_streams: set[int] = field(default_factory=set, init=False, repr=False, compare=False)

    def close(self) -> None:
        """Close every distinct owned stream exactly once."""
        for artifact in (self.target, self.same_release_sdist, self.same_release_wheel):
            if artifact is None or id(artifact._stream) in self._closed_streams:
                continue
            self._closed_streams.add(id(artifact._stream))
            if not artifact._stream.closed:
                artifact._stream.close()


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
