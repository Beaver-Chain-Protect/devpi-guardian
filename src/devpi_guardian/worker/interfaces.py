"""Narrow dependency ports used by the F5 worker."""

from __future__ import annotations

from typing import Protocol

from devpi_guardian.verdicts.models import ClaimedArtifact, VerdictInput

from .models import AnalysisBundle, AnalysisReport, VerifiedArtifact


class ArtifactPreparer(Protocol):
    """Resolve claim metadata, download it, and return owned verified streams."""

    def prepare(self, claim: ClaimedArtifact) -> AnalysisBundle: ...


class AnalysisEngine(Protocol):
    def analyze(self, bundle: AnalysisBundle) -> AnalysisReport: ...


class PolicyEngine(Protocol):
    """F10 adapter; F5 does not implement policy rules."""

    def evaluate(
        self,
        target: VerifiedArtifact,
        report: AnalysisReport,
    ) -> VerdictInput: ...
