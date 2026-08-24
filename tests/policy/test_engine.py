from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from devpi_guardian.analyzers import Finding
from devpi_guardian.policy import (
    PolicyAssessment,
    PolicyConfig,
    PolicyEngine,
    PolicyInputError,
)
from devpi_guardian.verdicts.models import Decision
from devpi_guardian.worker.models import (
    AnalysisEvidence,
    AnalysisReport,
    AnalysisStep,
    VerifiedArtifact,
)

SHA = "a" * 64
BASELINE = "b" * 64
NOW = datetime(2026, 8, 24, 1, 2, 3, tzinfo=UTC)


def target() -> VerifiedArtifact:
    return VerifiedArtifact("root/pypi", "demo", "1", "demo.whl", SHA, 1, Path("demo.whl"))


def report(
    *,
    analyzer_version: str = "analyzer-1",
    baseline: bool = True,
    pair: bool = True,
    baseline_tier: str = "same_tag",
    steps: tuple[AnalysisStep, ...] | None = None,
    evidence: tuple[AnalysisEvidence, ...] = (),
) -> AnalysisReport:
    return AnalysisReport(
        analyzer_version=analyzer_version,
        has_baseline=baseline,
        baseline_sha256=BASELINE if baseline else None,
        baseline_tier=baseline_tier if baseline else None,
        evidence=evidence,
        steps=steps
        or (
            AnalysisStep("F7", "completed" if baseline else "skipped"),
            AnalysisStep("F8", "completed"),
            AnalysisStep("F9", "completed" if pair else "skipped"),
        ),
    )


def finding(rule: str = "unknown_rule", action: str = "REVIEW") -> AnalysisEvidence:
    return AnalysisEvidence(
        analyzer="F8",
        finding=Finding(rule, action, "x.py", 1, "x", "finding"),
    )


def f7_finding(action: str = "REVIEW", tier: str = "same_tag") -> AnalysisEvidence:
    return AnalysisEvidence(
        analyzer="F7",
        finding=Finding("changed_code", action, "x.py", 1, "x", "changed"),
        baseline_tier=tier,
    )


def engine(config: PolicyConfig | None = None) -> PolicyEngine:
    return PolicyEngine(config=config, now=lambda: NOW)


def test_clean_report_allows_and_propagates_exact_dto_fields() -> None:
    assessed = engine().assess(report())
    assert assessed == PolicyAssessment(
        decision=Decision.ALLOW,
        score=0,
        reason_codes=(),
        policy_version=engine().policy_version,
        analyzer_version="analyzer-1",
        baseline_sha256=BASELINE,
        baseline_tier="same_tag",
        created_at=NOW,
    )
    verdict = engine().evaluate(target(), report())
    assert verdict.sha256 == SHA
    assert verdict.decision is Decision.ALLOW
    assert verdict.score == 0
    assert verdict.policy_version == engine().policy_version
    assert verdict.analyzer_version == "analyzer-1"
    assert verdict.baseline_sha256 == BASELINE
    assert verdict.baseline_tier == "same_tag"
    assert verdict.created_at == NOW


def test_precedence_and_scores_are_order_invariant() -> None:
    evidence = (finding("review_rule"), finding("deny_rule", "DENY"))
    first = engine().assess(report(evidence=evidence))
    second = engine().assess(report(evidence=tuple(reversed(evidence))))
    assert first == second
    assert first.decision is Decision.DENY
    assert first.score == 100
    assert first.reason_codes == tuple(sorted(first.reason_codes))


def test_mixed_deny_error_and_coverage_keep_deny_and_all_namespaced_reasons() -> None:
    steps = (
        AnalysisStep("F7", "completed"),
        AnalysisStep("F8", "error"),
        AnalysisStep("F9", "skipped"),
    )
    evidence = (f7_finding(), finding("deny_rule", "DENY"))
    result = engine().assess(report(steps=steps, evidence=evidence))
    assert result.decision is Decision.DENY
    assert result.score == 100
    assert result.reason_codes == (
        "coverage.error:F8",
        "coverage.no_f9_pair",
        "finding.deny:F8:deny_rule",
        "finding.review:F7:changed_code",
    )


@pytest.mark.parametrize(
    ("baseline", "pair", "score"),
    [(False, True, 70), (True, False, 60), (False, False, 70)],
)
def test_secure_default_coverage_is_review(baseline: bool, pair: bool, score: int) -> None:
    result = engine().assess(report(baseline=baseline, pair=pair))
    assert result.decision is Decision.REVIEW
    assert result.score == score


def test_coverage_flags_can_relax_review_but_not_deny() -> None:
    config = PolicyConfig(require_baseline=False, require_f9_pair=False)
    assert engine(config).assess(report(baseline=False, pair=False)).decision is Decision.ALLOW
    denied = engine(config).assess(
        report(baseline=False, pair=False, evidence=(finding(action="DENY"),))
    )
    assert denied.decision is Decision.DENY
    assert denied.score == 100


def test_error_is_review_with_score_90_and_f7_tier_scoring() -> None:
    error_steps = (
        AnalysisStep("F7", "completed"),
        AnalysisStep("F8", "error"),
        AnalysisStep("F9", "completed"),
    )
    assert engine().assess(report(steps=error_steps)).score == 90
    for tier, expected in (("same_tag", 50), ("universal_wheel", 60), ("sdist", 70)):
        assert (
            engine().assess(report(baseline_tier=tier, evidence=(f7_finding(tier=tier),))).score
            == expected
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"score_review": 51, "score_no_pair": 50},
        {"score_no_pair": 61, "score_no_baseline": 60},
        {"score_no_baseline": 71, "score_analyzer_error": 70},
        {"score_analyzer_error": 91, "score_deny": 90},
        {
            "score_review": 61,
            "f7_tier_scores": {"same_tag": 50, "universal_wheel": 60, "sdist": 70},
        },
        {"f7_tier_scores": {"same_tag": 51, "universal_wheel": 50, "sdist": 70}},
        {"f7_tier_scores": {"same_tag": 50, "universal_wheel": 71, "sdist": 70}},
        {"f7_tier_scores": {"same_tag": 50, "universal_wheel": 60, "sdist": 101}},
    ],
)
def test_config_score_ordering_cannot_invert_semantics(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        PolicyConfig(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"score_allow": 1},
        {"score_review": 49},
        {"score_no_pair": 59},
        {"score_no_baseline": 69},
        {"score_analyzer_error": 89},
        {"score_deny": 99},
        {
            "f7_tier_scores": {
                "same_tag": 50,
                "universal_wheel": 60,
                "sdist": 60,
            }
        },
        {
            "f7_tier_scores": {
                "same_tag": 50,
                "universal_wheel": 60,
                "sdist": 100,
            }
        },
    ],
)
def test_config_score_floors_and_anchors_are_required(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        PolicyConfig(**changes)


def test_all_zero_scores_are_rejected() -> None:
    with pytest.raises(ValueError):
        PolicyConfig(
            score_allow=0,
            score_review=0,
            score_no_pair=0,
            score_no_baseline=0,
            score_analyzer_error=0,
            score_deny=0,
            f7_tier_scores={"same_tag": 0, "universal_wheel": 0, "sdist": 0},
        )


def test_custom_scores_can_only_raise_review_floors_and_change_digest() -> None:
    config = PolicyConfig(
        score_review=55,
        score_no_pair=65,
        score_no_baseline=75,
        score_analyzer_error=95,
        f7_tier_scores={"same_tag": 55, "universal_wheel": 65, "sdist": 75},
    )
    assert PolicyEngine(config).policy_version != PolicyEngine().policy_version
    assert engine(config).assess(report(baseline=False, pair=False)).score == 75


@pytest.mark.parametrize(
    "value",
    ["a" * 4097, "analyzer\x7f1", "analyzer\u00801", "analyzer\ud800"],
)
def test_analyzer_version_bounds_and_controls_are_rejected(value: str) -> None:
    with pytest.raises(PolicyInputError):
        engine().assess(report(analyzer_version=value))


def test_long_policy_version_is_bounded_and_accepted() -> None:
    policy = PolicyEngine(PolicyConfig(name="n" * 300), now=lambda: NOW)
    assert 256 < len(policy.policy_version) <= 4096
    assert policy.assess(report()).policy_version == policy.policy_version


def test_policy_engine_rejects_policy_version_over_f4_bound() -> None:
    with pytest.raises(ValueError, match="policy_version"):
        PolicyEngine(PolicyConfig(name="n" * 4096))


def test_config_digest_is_canonical_and_config_is_immutable() -> None:
    one = PolicyConfig(rule_escalations={"b": "DENY", "a": "REVIEW"})
    two = PolicyConfig(rule_escalations={"a": "REVIEW", "b": "DENY"})
    assert PolicyEngine(one).policy_version == PolicyEngine(two).policy_version
    with pytest.raises(TypeError):
        one.rule_escalations["new"] = "DENY"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        one.require_baseline = False  # type: ignore[misc]


def test_config_mappings_are_snapshotted_and_behavioral_digest_changes() -> None:
    tiers = {"same_tag": 50, "universal_wheel": 60, "sdist": 70}
    escalations = {"future": "REVIEW"}
    config = PolicyConfig(f7_tier_scores=tiers, rule_escalations=escalations)
    version = PolicyEngine(config).policy_version
    tiers["same_tag"] = 51
    escalations["future"] = "DENY"
    assert config.f7_tier_scores["same_tag"] == 50
    assert config.rule_escalations["future"] == "REVIEW"
    assert PolicyEngine(config).policy_version == version

    variants = (
        PolicyConfig(require_baseline=False),
        PolicyConfig(require_f9_pair=False),
        PolicyConfig(
            score_review=51,
            f7_tier_scores={"same_tag": 51, "universal_wheel": 60, "sdist": 70},
        ),
        PolicyConfig(algorithm_version="f10-v2"),
        PolicyConfig(rule_escalations={"future": "REVIEW"}),
    )
    assert len({PolicyEngine(item).policy_version for item in (*variants, PolicyConfig())}) == 6


@pytest.mark.parametrize(
    "bad",
    [
        (AnalysisStep("F7", "completed"), AnalysisStep("F8", "completed")),
        (
            AnalysisStep("F7", "completed"),
            AnalysisStep("F8", "skipped"),
            AnalysisStep("F9", "completed"),
        ),
    ],
)
def test_structurally_impossible_reports_are_rejected(bad: tuple[AnalysisStep, ...]) -> None:
    with pytest.raises(PolicyInputError):
        engine().assess(report(steps=bad))


@pytest.mark.parametrize(
    "steps",
    [
        (
            AnalysisStep("F7", "completed"),
            AnalysisStep("F7", "completed"),
            AnalysisStep("F9", "completed"),
        ),
        (
            AnalysisStep("F7", "completed"),
            AnalysisStep("F8", "completed"),
            AnalysisStep("F10", "completed"),
        ),
        (
            AnalysisStep("F7", "completed"),
            AnalysisStep("F8", "unknown"),
            AnalysisStep("F9", "completed"),
        ),
    ],
)
def test_duplicate_unknown_and_invalid_steps_are_rejected(steps: tuple[AnalysisStep, ...]) -> None:
    with pytest.raises(PolicyInputError):
        engine().assess(report(steps=steps))


def test_no_baseline_cannot_have_completed_f7() -> None:
    steps = (
        AnalysisStep("F7", "completed"),
        AnalysisStep("F8", "completed"),
        AnalysisStep("F9", "completed"),
    )
    with pytest.raises(PolicyInputError):
        engine().assess(report(baseline=False, steps=steps))


def test_no_baseline_may_have_f7_error() -> None:
    steps = (
        AnalysisStep("F7", "error"),
        AnalysisStep("F8", "completed"),
        AnalysisStep("F9", "completed"),
    )
    result = engine().assess(report(baseline=False, steps=steps))
    assert result.decision is Decision.REVIEW
    assert "coverage.error:F7" in result.reason_codes


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: object.__setattr__(value, "baseline_sha256", "not-a-sha"),
        lambda value: object.__setattr__(value, "baseline_sha256", None),
        lambda value: object.__setattr__(value, "baseline_tier", "bad-tier"),
    ],
)
def test_selected_baseline_pairing_sha_and_tier_are_validated(mutate) -> None:
    value = report()
    mutate(value)
    with pytest.raises(PolicyInputError):
        engine().assess(value)


def test_skipped_analyzer_evidence_and_bad_baseline_evidence_are_rejected() -> None:
    with pytest.raises(PolicyInputError):
        engine().assess(
            report(
                baseline=False,
                steps=(
                    AnalysisStep("F7", "skipped"),
                    AnalysisStep("F8", "completed"),
                    AnalysisStep("F9", "completed"),
                ),
                evidence=(AnalysisEvidence("F7", finding().finding),),
            )
        )
    with pytest.raises(PolicyInputError):
        engine().assess(
            report(evidence=(AnalysisEvidence("F8", finding().finding, baseline_tier="same_tag"),))
        )


def test_unknown_analyzer_and_action_are_rejected() -> None:
    with pytest.raises(PolicyInputError):
        engine().assess(report(evidence=(AnalysisEvidence("F10", finding().finding),)))
    with pytest.raises(PolicyInputError):
        engine().assess(report(evidence=(finding(action="ALLOW"),)))


def test_deny_finding_cannot_be_downgraded_by_review_escalation() -> None:
    config = PolicyConfig(rule_escalations={"deny_rule": "REVIEW"})
    result = engine(config).assess(report(evidence=(finding("deny_rule", "DENY"),)))
    assert result.decision is Decision.DENY


def test_rule_control_characters_are_rejected() -> None:
    with pytest.raises(PolicyInputError):
        engine().assess(report(evidence=(finding("bad\nrule"),)))


def test_naive_clock_is_rejected_and_non_utc_clock_is_normalized() -> None:
    with pytest.raises(PolicyInputError):
        PolicyEngine(now=lambda: datetime(2026, 8, 24)).assess(report())
    plus_nine = datetime(2026, 8, 24, 10, 2, 3, tzinfo=timezone(timedelta(hours=9)))
    result = PolicyEngine(now=lambda: plus_nine).assess(report())
    assert result.created_at == datetime(2026, 8, 24, 1, 2, 3, tzinfo=UTC)


def test_evaluate_rejects_wrong_target_type() -> None:
    with pytest.raises(TypeError):
        engine().evaluate(object(), report())  # type: ignore[arg-type]


def test_scores_use_maximum_and_are_cardinality_invariant() -> None:
    steps = (
        AnalysisStep("F7", "skipped"),
        AnalysisStep("F8", "error"),
        AnalysisStep("F9", "skipped"),
    )
    one = engine().assess(report(baseline=False, steps=steps))
    duplicate = engine().assess(
        report(baseline=False, steps=steps, evidence=(finding("same"), finding("same")))
    )
    assert one.decision is Decision.REVIEW
    assert one.score == 90
    assert duplicate.score == one.score


def test_unknown_rule_ids_are_forward_compatible_and_escalatable() -> None:
    config = PolicyConfig(rule_escalations={"future_rule": "DENY"})
    item = finding("future_rule", "REVIEW")
    result = engine(config).assess(report(evidence=(item,)))
    assert result.decision is Decision.DENY
