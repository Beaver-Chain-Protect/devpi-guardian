"""Single F5 facade over the existing F6/F7, F8, and F9 entry points."""

from __future__ import annotations

from collections.abc import Callable, Sequence

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
    limits: AnalysisLimits = _DEFAULT_LIMITS,
    timeout: float = 30.0,
    max_bytes: int = 1_000_000_000,
) -> GuardianAnalysisEngine:
    """Wire F6/F7 with one lookup used as the HTTP origin resolver."""

    lookup = VerdictReaderReleaseLookup(reader)
    bytes_source = HttpArtifactBytesSource(
        session,
        lookup,
        timeout=timeout,
        max_bytes=max_bytes,
    )
    return GuardianAnalysisEngine(
        lookup=lookup,
        bytes_source=bytes_source,
        analyzer_version=analyzer_version,
        limits=limits,
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

    def analyze(self, bundle: AnalysisBundle) -> AnalysisReport:
        """Analyze one verified artifact through one worker-facing call."""

        target = bundle.target
        release = ReleaseRecord(
            project=target.project,
            version=target.version,
            filename=target.filename,
            sha256=target.sha256,
        )
        comparison = self._baseline_analyzer(
            release,
            target.local_path,
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
            str(target.local_path),
            limits=self._limits,
        )
        evidence.extend(AnalysisEvidence(analyzer="F8", finding=finding) for finding in f8_findings)
        steps = [f7_step, AnalysisStep("F8", _status(f8_findings))]

        sdist, wheel = self._pair(bundle)
        if sdist is None or wheel is None:
            steps.append(AnalysisStep("F9", "skipped", "same-release pair unavailable"))
        else:
            f9_findings = self._sdist_wheel_analyzer(
                str(sdist.local_path),
                str(wheel.local_path),
                limits=self._limits,
            )
            evidence.extend(
                AnalysisEvidence(analyzer="F9", finding=finding) for finding in f9_findings
            )
            steps.append(AnalysisStep("F9", _status(f9_findings)))

        return AnalysisReport(
            analyzer_version=self._analyzer_version,
            has_baseline=comparison.has_baseline,
            baseline_sha256=comparison.baseline_sha256,
            baseline_tier=tier,
            evidence=tuple(evidence),
            steps=tuple(steps),
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
