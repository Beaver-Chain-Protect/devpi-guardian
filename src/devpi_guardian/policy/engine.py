"""The F10 policy engine."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from devpi_guardian.analyzers import Finding
from devpi_guardian.verdicts.models import (
    BaselineTier,
    Decision,
    VerdictInput,
    validate_sha256,
)
from devpi_guardian.worker.models import (
    AnalysisEvidence,
    AnalysisReport,
    AnalysisStep,
    VerifiedArtifact,
)

_ANALYZERS = frozenset(("F7", "F8", "F9"))
_STATUSES = frozenset(("completed", "skipped", "error"))
_BASELINE_TIERS = frozenset(("same_tag", "universal_wheel", "sdist"))
_DEFAULT_F7_TIER_SCORES = {
    "same_tag": 50,
    "universal_wheel": 60,
    "sdist": 70,
}
_MAX_TEXT_LENGTH = 4096


class PolicyInputError(ValueError):
    """The report is not a structurally possible F5 analysis report."""


def _validate_score(value: object, name: str) -> int:
    if type(value) is not int or not 0 <= value <= 100:
        raise ValueError(f"{name} must be an integer in the range 0..100")
    return value


def _validate_text(value: object, name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must not be blank")
    if len(value) > _MAX_TEXT_LENGTH:
        raise ValueError(f"{name} is too long")
    if any(
        ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F or 0xD800 <= ord(char) <= 0xDFFF
        for char in value
    ):
        raise ValueError(f"{name} contains a control character")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} is not valid UTF-8") from exc
    return value


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    """Immutable F10 configuration and its scoring constants."""

    name: str = "devpi-guardian-policy"
    revision: str = "1"
    algorithm_version: str = "f10-v1"
    require_baseline: bool = True
    require_f9_pair: bool = True
    score_allow: int = 0
    score_review: int = 50
    score_no_pair: int = 60
    score_no_baseline: int = 70
    score_analyzer_error: int = 90
    score_deny: int = 100
    f7_tier_scores: Mapping[str, int] = field(
        default_factory=lambda: dict(_DEFAULT_F7_TIER_SCORES),
    )
    rule_escalations: Mapping[str, str | Decision] = field(default_factory=dict)
    _scores: Mapping[str, int] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        _validate_text(self.name, "name")
        _validate_text(self.revision, "revision")
        _validate_text(self.algorithm_version, "algorithm_version")
        if type(self.require_baseline) is not bool:
            raise ValueError("require_baseline must be a bool")
        if type(self.require_f9_pair) is not bool:
            raise ValueError("require_f9_pair must be a bool")
        scores = {
            "allow": _validate_score(self.score_allow, "score_allow"),
            "review": _validate_score(self.score_review, "score_review"),
            "no_pair": _validate_score(self.score_no_pair, "score_no_pair"),
            "no_baseline": _validate_score(self.score_no_baseline, "score_no_baseline"),
            "analyzer_error": _validate_score(
                self.score_analyzer_error,
                "score_analyzer_error",
            ),
            "deny": _validate_score(self.score_deny, "score_deny"),
        }
        if not isinstance(self.f7_tier_scores, Mapping):
            raise ValueError("f7_tier_scores must be a mapping")
        tier_scores: dict[str, int] = {}
        for tier in _BASELINE_TIERS:
            if tier not in self.f7_tier_scores:
                raise ValueError(f"missing f7 tier score: {tier}")
            tier_scores[tier] = _validate_score(
                self.f7_tier_scores[tier], f"f7_tier_scores[{tier}]"
            )
        if set(self.f7_tier_scores) != set(_BASELINE_TIERS):
            raise ValueError("f7_tier_scores must contain exactly the baseline tiers")
        ordered_scores = (
            self.score_allow,
            self.score_review,
            self.score_no_pair,
            self.score_no_baseline,
            self.score_analyzer_error,
            self.score_deny,
        )
        if tuple(sorted(ordered_scores)) != ordered_scores:
            raise ValueError("coverage scores must be non-decreasing")
        if self.score_allow != 0:
            raise ValueError("score_allow must be 0")
        if self.score_review < 50:
            raise ValueError("score_review must be at least 50")
        if self.score_no_pair < 60:
            raise ValueError("score_no_pair must be at least 60")
        if self.score_no_baseline < 70:
            raise ValueError("score_no_baseline must be at least 70")
        if self.score_analyzer_error < 90:
            raise ValueError("score_analyzer_error must be at least 90")
        if self.score_deny != 100:
            raise ValueError("score_deny must be 100")
        if tier_scores["same_tag"] < 50:
            raise ValueError("same_tag score must be at least 50")
        if tier_scores["universal_wheel"] < 60:
            raise ValueError("universal_wheel score must be at least 60")
        if tier_scores["sdist"] < 70:
            raise ValueError("sdist score must be at least 70")
        if self.score_review > tier_scores["same_tag"]:
            raise ValueError("score_review must not exceed same_tag score")
        if not (
            tier_scores["same_tag"]
            < tier_scores["universal_wheel"]
            < tier_scores["sdist"]
            < self.score_deny
        ):
            raise ValueError("F7 tier scores must be strictly increasing below DENY")
        tier_order = (
            self.score_review,
            tier_scores["same_tag"],
            tier_scores["universal_wheel"],
            tier_scores["sdist"],
            self.score_deny,
        )
        if tuple(sorted(tier_order)) != tier_order:
            raise ValueError("F7 tier scores must be non-decreasing")
        if not isinstance(self.rule_escalations, Mapping):
            raise ValueError("rule_escalations must be a mapping")
        escalations: dict[str, str] = {}
        for rule, action in self.rule_escalations.items():
            _validate_text(rule, "rule escalation id")
            try:
                normalized = Decision(action)
            except (TypeError, ValueError) as exc:
                raise ValueError("rule escalation must be REVIEW or DENY") from exc
            if normalized is Decision.ALLOW:
                raise ValueError("rule escalation cannot be ALLOW")
            escalations[rule] = normalized.value
        object.__setattr__(self, "f7_tier_scores", MappingProxyType(tier_scores))
        object.__setattr__(self, "rule_escalations", MappingProxyType(escalations))
        # Keep this local snapshot to make canonical identity independent of
        # any future addition of private implementation attributes.
        object.__setattr__(self, "_scores", MappingProxyType(scores))

    @property
    def scores(self) -> Mapping[str, int]:
        return self._scores  # type: ignore[attr-defined]

    def canonical_dict(self) -> dict[str, Any]:
        """Return the complete, JSON-compatible policy identity payload."""

        return {
            "algorithm_version": self.algorithm_version,
            "coverage": {
                "require_baseline": self.require_baseline,
                "require_f9_pair": self.require_f9_pair,
            },
            "f7_tier_scores": dict(sorted(self.f7_tier_scores.items())),
            "name": self.name,
            "revision": self.revision,
            "rule_escalations": dict(sorted(self.rule_escalations.items())),
            "scores": dict(sorted(self.scores.items())),
        }


@dataclass(frozen=True, slots=True)
class PolicyAssessment:
    """Frozen, explainable policy result before adaptation to F4 storage."""

    decision: Decision
    score: int
    reason_codes: tuple[str, ...]
    policy_version: str
    analyzer_version: str
    baseline_sha256: str | None
    baseline_tier: BaselineTier | None
    created_at: datetime

    @property
    def assessed_at(self) -> datetime:
        """Compatibility alias for callers that name the timestamp assessed_at."""

        return self.created_at


class PolicyEngine:
    """Evaluate F5 reports with deterministic precedence and secure defaults."""

    def __init__(
        self,
        config: PolicyConfig | None = None,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if config is not None and type(config) is not PolicyConfig:
            raise TypeError("config must be a PolicyConfig")
        self._config = config if config is not None else PolicyConfig()
        self._now = now if now is not None else lambda: datetime.now(UTC)
        payload = json.dumps(
            self._config.canonical_dict(),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(payload).hexdigest()
        self._policy_version = f"{self._config.name}/{self._config.revision}+sha256:{digest}"
        if len(self._policy_version) > _MAX_TEXT_LENGTH:
            raise ValueError("policy_version is too long")

    @property
    def config(self) -> PolicyConfig:
        return self._config

    @property
    def policy_version(self) -> str:
        return self._policy_version

    def assess(self, report: AnalysisReport) -> PolicyAssessment:
        self._validate_report(report)
        steps = {step.analyzer: step for step in report.steps}
        reason_codes: set[str] = set()
        score = self._config.score_allow
        has_deny = False
        has_review = False

        for item in report.evidence:
            action = self._effective_action(item)
            if action is Decision.DENY:
                has_deny = True
                reason_codes.add(f"finding.deny:{item.analyzer}:{item.finding.rule}")
                score = max(score, self._config.score_deny)
            else:
                has_review = True
                reason_codes.add(f"finding.review:{item.analyzer}:{item.finding.rule}")
                finding_score = self._config.score_review
                if item.analyzer == "F7" and item.baseline_tier is not None:
                    finding_score = self._config.f7_tier_scores[item.baseline_tier]
                score = max(score, finding_score)

        for step in steps.values():
            if step.status == "error":
                has_review = True
                reason_codes.add(f"coverage.error:{step.analyzer}")
                score = max(score, self._config.score_analyzer_error)

        if self._config.require_baseline and not report.has_baseline:
            has_review = True
            reason_codes.add("coverage.no_baseline")
            score = max(score, self._config.score_no_baseline)
        if self._config.require_f9_pair and steps["F9"].status == "skipped":
            has_review = True
            reason_codes.add("coverage.no_f9_pair")
            score = max(score, self._config.score_no_pair)

        decision = Decision.DENY if has_deny else Decision.REVIEW if has_review else Decision.ALLOW
        if decision is Decision.ALLOW:
            score = self._config.score_allow
        now = self._utc_now()
        return PolicyAssessment(
            decision=decision,
            score=score,
            reason_codes=tuple(sorted(reason_codes)),
            policy_version=self._policy_version,
            analyzer_version=report.analyzer_version,
            baseline_sha256=report.baseline_sha256,
            baseline_tier=report.baseline_tier,
            created_at=now,
        )

    def evaluate(self, target: VerifiedArtifact, report: AnalysisReport) -> VerdictInput:
        """Adapt an assessment to the existing F5 ``VerdictInput`` port."""

        if type(target) is not VerifiedArtifact:
            raise TypeError("target must be a VerifiedArtifact")
        assessment = self.assess(report)
        return VerdictInput(
            sha256=target.sha256,
            decision=assessment.decision,
            score=assessment.score,
            policy_version=assessment.policy_version,
            analyzer_version=assessment.analyzer_version,
            baseline_sha256=assessment.baseline_sha256,
            baseline_tier=assessment.baseline_tier,
            created_at=assessment.created_at,
        )

    def _effective_action(self, item: AnalysisEvidence) -> Decision:
        action = Decision(item.finding.action)
        escalation = self._config.rule_escalations.get(item.finding.rule)
        if escalation is None:
            return action
        escalated = Decision(escalation)
        if action is Decision.DENY or escalated is Decision.DENY:
            return Decision.DENY
        return Decision.REVIEW

    def _utc_now(self) -> datetime:
        value = self._now()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise PolicyInputError("now must return a timezone-aware datetime")
        return value.astimezone(UTC)

    @staticmethod
    def _validate_report(report: AnalysisReport) -> None:
        if type(report) is not AnalysisReport:
            raise PolicyInputError("report must be an AnalysisReport")
        try:
            _validate_text(report.analyzer_version, "analyzer_version")
        except ValueError as exc:
            raise PolicyInputError(str(exc)) from exc
        if type(report.has_baseline) is not bool:
            raise PolicyInputError("has_baseline must be a bool")
        if not isinstance(report.steps, tuple) or len(report.steps) != 3:
            raise PolicyInputError("report must contain exactly three analyzer steps")
        steps: dict[str, AnalysisStep] = {}
        for step in report.steps:
            if type(step) is not AnalysisStep:
                raise PolicyInputError("invalid analyzer step")
            if (
                type(step.analyzer) is not str
                or step.analyzer not in _ANALYZERS
                or type(step.status) is not str
                or step.status not in _STATUSES
            ):
                raise PolicyInputError("invalid analyzer step name or status")
            if step.analyzer in steps:
                raise PolicyInputError("duplicate analyzer step")
            steps[step.analyzer] = step
        if set(steps) != _ANALYZERS:
            raise PolicyInputError("report must contain one F7, F8, and F9 step")
        if steps["F8"].status == "skipped":
            raise PolicyInputError("F8 cannot be skipped")
        if report.has_baseline:
            if (
                report.baseline_sha256 is None
                or type(report.baseline_tier) is not str
                or report.baseline_tier not in _BASELINE_TIERS
            ):
                raise PolicyInputError("selected baseline requires a SHA-256 and valid tier")
            try:
                validate_sha256(report.baseline_sha256)
            except Exception as exc:
                raise PolicyInputError("selected baseline requires a canonical SHA-256") from exc
            if steps["F7"].status == "skipped":
                raise PolicyInputError("selected baseline cannot have a skipped F7 step")
        elif report.baseline_sha256 is not None or report.baseline_tier is not None:
            raise PolicyInputError("absent baseline must have neither SHA-256 nor tier")
        elif steps["F7"].status == "completed":
            raise PolicyInputError("absent baseline cannot have a completed F7 step")
        if not isinstance(report.evidence, tuple):
            raise PolicyInputError("evidence must be a tuple")
        for item in report.evidence:
            if (
                type(item) is not AnalysisEvidence
                or type(item.analyzer) is not str
                or item.analyzer not in _ANALYZERS
            ):
                raise PolicyInputError("invalid analysis evidence")
            if type(item.finding) is not Finding:
                raise PolicyInputError("invalid finding")
            try:
                _validate_text(item.finding.rule, "finding rule")
            except ValueError as exc:
                raise PolicyInputError(str(exc)) from exc
            if item.finding.action not in ("REVIEW", "DENY"):
                raise PolicyInputError("finding action must be REVIEW or DENY")
            if steps[item.analyzer].status == "skipped":
                raise PolicyInputError("skipped analyzers cannot contribute evidence")
            if item.analyzer == "F7":
                if item.baseline_tier != report.baseline_tier:
                    raise PolicyInputError("F7 evidence baseline tier does not match report")
            elif item.baseline_tier is not None:
                raise PolicyInputError("F8/F9 evidence cannot claim a baseline tier")
