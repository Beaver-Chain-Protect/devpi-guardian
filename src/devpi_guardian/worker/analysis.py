"""Single F5 facade over the existing F6/F7, F8, and F9 entry points."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from pathlib import Path
from tempfile import TemporaryDirectory

from devpi_guardian.analyzers import (
    AnalysisLimits,
    Finding,
    compare_sdist_wheel_isolated,
    scan_install_surface_isolated,
)
from devpi_guardian.baseline import (
    ArtifactBytesSource,
    BaselineComparison,
    HttpArtifactBytesSource,
    ReleaseLookup,
    ReleaseRecord,
    VerdictReaderReleaseLookup,
    artifact_kind,
    compare_release_to_baseline,
)

from .models import (
    AnalysisBundle,
    AnalysisEvidence,
    AnalysisFileDiff,
    AnalysisReport,
    AnalysisStatus,
    AnalysisStep,
)

BaselineAnalyzer = Callable[..., BaselineComparison]
InstallSurfaceAnalyzer = Callable[..., list[Finding]]
SdistWheelAnalyzer = Callable[..., list[Finding]]
_DEFAULT_LIMITS = AnalysisLimits()


def build_analysis_engine(
    *,
    reader,
    session,
    analyzer_version: str,
    trusted_devpi_url: str,
    limits: AnalysisLimits = _DEFAULT_LIMITS,
    timeout: float = 30.0,
    max_bytes: int = 1_000_000_000,
) -> GuardianAnalysisEngine:
    """Wire F6/F7 with one lookup used as the HTTP origin resolver."""

    lookup = VerdictReaderReleaseLookup(reader)
    bytes_source = HttpArtifactBytesSource(
        session,
        lookup,
        trusted_devpi_url=trusted_devpi_url,
        timeout=timeout,
        max_bytes=max_bytes,
    )
    return GuardianAnalysisEngine(
        lookup=lookup,
        bytes_source=bytes_source,
        analyzer_version=analyzer_version,
        limits=limits,
        owns_bytes_source=True,
    )


def _status(findings: Sequence[Finding]) -> AnalysisStatus:
    return "error" if any(item.rule == "analyzer_error" for item in findings) else "completed"


class GuardianAnalysisEngine:
    """Run all applicable analysis features while preserving their attribution."""

    def __init__(
        self,
        *,
        lookup: ReleaseLookup,
        bytes_source: ArtifactBytesSource,
        analyzer_version: str,
        limits: AnalysisLimits = _DEFAULT_LIMITS,
        baseline_analyzer: BaselineAnalyzer = compare_release_to_baseline,
        install_surface_analyzer: InstallSurfaceAnalyzer = scan_install_surface_isolated,
        sdist_wheel_analyzer: SdistWheelAnalyzer = compare_sdist_wheel_isolated,
        owns_bytes_source: bool = False,
    ) -> None:
        if not analyzer_version.strip():
            raise ValueError("analyzer_version must not be blank")
        self._lookup = lookup
        self._bytes_source = bytes_source
        self._analyzer_version = analyzer_version
        self._limits = limits
        self._baseline_analyzer = baseline_analyzer
        self._install_surface_analyzer = install_surface_analyzer
        self._sdist_wheel_analyzer = sdist_wheel_analyzer
        self._owns_bytes_source = owns_bytes_source
        self._source_closed = False

    def close(self) -> None:
        if self._source_closed:
            return
        if self._owns_bytes_source:
            self._bytes_source.close()
        self._source_closed = True

    def __enter__(self) -> GuardianAnalysisEngine:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        try:
            self.close()
        except BaseException as cleanup_error:
            if exc_value is not None:
                exc_value.add_note(
                    f"baseline source cleanup failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
                return False
            raise
        return False

    def analyze(self, bundle: AnalysisBundle) -> AnalysisReport:
        """Analyze one verified artifact through one worker-facing call."""

        workspace = TemporaryDirectory(prefix="guardian-analysis-")

        def cleanup() -> list[tuple[str, BaseException]]:
            errors: list[tuple[str, BaseException]] = []
            try:
                workspace.cleanup()
            except BaseException as error:
                errors.append(("analysis workspace cleanup", error))
            if self._owns_bytes_source:
                try:
                    self._bytes_source.close()
                except BaseException as error:
                    errors.append(("baseline source cleanup", error))
            return errors

        try:
            paths = self._materialize(bundle, Path(workspace.name))
            report = self._analyze_paths(bundle, paths)
        except BaseException as primary:
            for label, cleanup_error in cleanup():
                primary.add_note(f"{label} failed: {type(cleanup_error).__name__}: {cleanup_error}")
            raise
        else:
            cleanup_errors = cleanup()
            if cleanup_errors:
                (_first_label, first), *additional = cleanup_errors
                for label, cleanup_error in additional:
                    first.add_note(
                        f"additional {label} failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
                raise first
            return report

    @staticmethod
    def _materialize(bundle: AnalysisBundle, workspace: Path) -> dict[int, Path]:
        """Copy owned streams to private, short-lived files for legacy analyzers."""
        paths: dict[int, Path] = {}
        identities: dict[int, tuple[str, str, str, str, str, int]] = {}
        artifacts = (bundle.target, bundle.same_release_sdist, bundle.same_release_wheel)
        for index, artifact in enumerate(item for item in artifacts if item is not None):
            stream_id = id(artifact._stream)
            identity = (
                artifact.stage,
                artifact.project,
                artifact.version,
                artifact.filename,
                artifact.sha256,
                artifact.size_bytes,
            )
            previous = identities.get(stream_id)
            if previous is not None and previous != identity:
                raise ValueError("shared stream has conflicting artifact identity")
            identities[stream_id] = identity
            if stream_id in paths:
                continue
            suffix = "".join(Path(artifact.filename).suffixes)
            destination = workspace / f"artifact-{index}{suffix}"
            with artifact.open_for_analysis() as source, destination.open("wb") as output:
                digest = hashlib.sha256()
                total = 0
                while total <= artifact.size_bytes:
                    chunk = source.read(min(1024 * 1024, artifact.size_bytes - total + 1))
                    if not chunk:
                        break
                    if total + len(chunk) > artifact.size_bytes:
                        raise ValueError("artifact stream exceeds declared size")
                    output.write(chunk)
                    digest.update(chunk)
                    total += len(chunk)
                if total != artifact.size_bytes:
                    raise ValueError("artifact stream is shorter than declared size")
                if digest.hexdigest() != artifact.sha256:
                    raise ValueError("artifact stream digest does not match metadata")
            paths[stream_id] = destination
        return paths

    def _analyze_paths(self, bundle: AnalysisBundle, paths: dict[int, Path]) -> AnalysisReport:
        target = bundle.target
        target_path = paths[id(target._stream)]
        release = ReleaseRecord(
            project=target.project,
            version=target.version,
            filename=target.filename,
            sha256=target.sha256,
            size_bytes=target.size_bytes,
        )
        comparison = self._baseline_analyzer(
            release,
            target_path,
            lookup=self._lookup,
            bytes_source=self._bytes_source,
        )

        tier = comparison.selection.tier if comparison.selection is not None else None
        evidence = [
            AnalysisEvidence(
                analyzer="F7",
                finding=finding,
                origin=origin,
                baseline_tier=tier,
            )
            for finding, origin in comparison.findings
        ]
        if not comparison.has_baseline and not comparison.findings:
            f7_step = AnalysisStep("F7", "skipped", "no approved baseline")
        else:
            f7_findings = [finding for finding, _ in comparison.findings]
            f7_step = AnalysisStep("F7", _status(f7_findings))

        f8_findings = self._install_surface_analyzer(
            str(target_path),
            limits=self._limits,
        )
        evidence.extend(AnalysisEvidence(analyzer="F8", finding=finding) for finding in f8_findings)
        steps = [f7_step, AnalysisStep("F8", _status(f8_findings))]

        sdist, wheel = self._pair(bundle)
        if sdist is None or wheel is None:
            steps.append(AnalysisStep("F9", "skipped", "same-release pair unavailable"))
        else:
            f9_findings = self._sdist_wheel_analyzer(
                str(paths[id(sdist._stream)]),
                str(paths[id(wheel._stream)]),
                limits=self._limits,
            )
            evidence.extend(
                AnalysisEvidence(analyzer="F9", finding=finding) for finding in f9_findings
            )
            steps.append(AnalysisStep("F9", _status(f9_findings)))

        baseline_diff = getattr(comparison, "diff", None)
        return AnalysisReport(
            analyzer_version=self._analyzer_version,
            has_baseline=comparison.has_baseline,
            baseline_sha256=comparison.baseline_sha256,
            baseline_tier=tier,
            evidence=tuple(evidence),
            steps=tuple(steps),
            file_diff=(
                None
                if baseline_diff is None
                else AnalysisFileDiff(
                    added=baseline_diff.files.added,
                    changed=baseline_diff.files.changed,
                    removed=baseline_diff.files.removed,
                )
            ),
        )

    @staticmethod
    def _pair(bundle: AnalysisBundle):
        target_kind = artifact_kind(bundle.target.filename)
        sdist = bundle.same_release_sdist
        wheel = bundle.same_release_wheel
        if target_kind == "sdist" and sdist is None:
            sdist = bundle.target
        elif target_kind == "wheel" and wheel is None:
            wheel = bundle.target
        return sdist, wheel
