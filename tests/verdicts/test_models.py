import json
import math
from datetime import UTC, datetime, timedelta

import pytest

from devpi_guardian.verdicts.errors import InvalidSha256
from devpi_guardian.verdicts.models import (
    ArtifactInput,
    ArtifactState,
    ClaimedArtifact,
    Decision,
    DecisionSource,
    EvidenceInput,
    ManualOverrideInput,
    VerdictInput,
    validate_sha256,
)

SHA256 = "a" * 64


def make_evidence(details: dict[str, object] | None = None) -> EvidenceInput:
    return EvidenceInput(
        rule_id="RULE-1",
        action=Decision.REVIEW,
        file_path="pyproject.toml",
        line=1,
        message="needs review",
        details={} if details is None else details,
    )


def test_validate_sha256_accepts_canonical_lowercase_ascii_digest() -> None:
    assert validate_sha256(SHA256) == SHA256


@pytest.mark.parametrize(
    "value",
    ["_" * 64, "a_" * 31 + "aa", "\u0660" * 64, None, b"a" * 64, 123],
)
def test_validate_sha256_rejects_non_ascii_or_non_string_values(
    value: object,
) -> None:
    with pytest.raises(InvalidSha256):
        validate_sha256(value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["", "A" * 64, "g" * 64, "a" * 63, "a" * 65])
def test_validate_sha256_rejects_noncanonical_values(value: str) -> None:
    with pytest.raises(InvalidSha256):
        validate_sha256(value)


def test_artifact_input_rejects_negative_size() -> None:
    with pytest.raises(ValueError, match="size_bytes"):
        ArtifactInput(sha256=SHA256, size_bytes=-1)


def test_manual_override_requires_nonblank_actor_and_reason() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="actor"):
        ManualOverrideInput(
            sha256=SHA256,
            decision=Decision.ALLOW,
            actor=" ",
            reason="reviewed",
            created_at=now,
        )


def test_manual_override_requires_nonblank_reason() -> None:
    with pytest.raises(ValueError, match="reason"):
        ManualOverrideInput(
            sha256=SHA256,
            decision=Decision.ALLOW,
            actor="admin",
            reason=" ",
            created_at=datetime.now(UTC),
        )


def test_manual_override_requires_future_expiry() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="expires_at"):
        ManualOverrideInput(
            sha256=SHA256,
            decision=Decision.ALLOW,
            actor="admin",
            reason="temporary exception",
            created_at=now,
            expires_at=now - timedelta(seconds=1),
        )


def test_public_enums_have_locked_wire_values() -> None:
    assert [state.value for state in ArtifactState] == [
        "DISCOVERED",
        "SCANNING",
        "ALLOW",
        "REVIEW",
        "DENY",
        "ERROR",
        "MISSING",
    ]
    assert [decision.value for decision in Decision] == [
        "ALLOW",
        "REVIEW",
        "DENY",
    ]
    assert [source.value for source in DecisionSource] == [
        "AUTOMATED",
        "MANUAL_OVERRIDE",
        "MISSING",
    ]


def test_evidence_details_snapshot_is_immune_to_original_mutation() -> None:
    original = {"nested": {"items": [1, 2]}, "top_items": ["before"]}
    item = make_evidence(original)

    original["nested"]["items"].append(3)  # type: ignore[index]
    original["top_items"].append("after")  # type: ignore[union-attr]

    assert item.details == {
        "nested": {"items": (1, 2)},
        "top_items": ("before",),
    }


def test_evidence_details_rejects_top_level_and_nested_mutation() -> None:
    item = make_evidence({"nested": {"items": [1, 2]}})

    with pytest.raises(TypeError):
        item.details["new"] = "value"
    with pytest.raises(TypeError):
        item.details["nested"]["items"][0] = 3  # type: ignore[index]


def test_evidence_details_is_directly_json_serializable() -> None:
    item = make_evidence({"nested": {"items": [2, 1]}, "enabled": True})

    assert (
        json.dumps(
            item.details,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        == '{"enabled":true,"nested":{"items":[2,1]}}'
    )


@pytest.mark.parametrize(
    "details",
    [
        {"valid": 1, 2: "top-level integer key"},
        {"nested": {"valid": 1, 2: "nested integer key"}},
        {"nested": {"valid": 1, False: "nested boolean key"}},
    ],
)
def test_evidence_details_rejects_non_string_object_keys(
    details: dict[object, object],
) -> None:
    with pytest.raises(ValueError):
        make_evidence(details)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "details",
    [
        {"unsupported": object()},
        {"not_finite": math.nan},
        {"not_finite": math.inf},
    ],
)
def test_evidence_details_rejects_non_json_values(
    details: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        make_evidence(details)


@pytest.mark.parametrize("line", [0, -1])
def test_evidence_line_must_be_positive(line: int) -> None:
    with pytest.raises(ValueError, match="line"):
        EvidenceInput(
            rule_id="RULE-1",
            action=Decision.REVIEW,
            file_path=None,
            line=line,
            message="needs review",
        )


@pytest.mark.parametrize("field_name", ["rule_id", "message"])
def test_evidence_text_fields_must_not_be_blank(field_name: str) -> None:
    values = {
        "rule_id": "RULE-1",
        "action": Decision.REVIEW,
        "file_path": None,
        "line": None,
        "message": "needs review",
    }
    values[field_name] = " "

    with pytest.raises(ValueError, match=field_name):
        EvidenceInput(**values)  # type: ignore[arg-type]


def test_evidence_action_must_be_a_decision() -> None:
    with pytest.raises(ValueError, match="action"):
        EvidenceInput(
            rule_id="RULE-1",
            action="REVIEW",  # type: ignore[arg-type]
            file_path=None,
            line=None,
            message="needs review",
        )


def test_verdict_decision_must_be_a_decision() -> None:
    with pytest.raises(ValueError, match="decision"):
        VerdictInput(
            sha256=SHA256,
            decision="ALLOW",  # type: ignore[arg-type]
            score=0.0,
            policy_version="policy-1",
            analyzer_version="analyzer-1",
            baseline_sha256=None,
        )


@pytest.mark.parametrize(
    "score",
    [math.nan, math.inf, -math.inf, True, "0", None],
)
def test_verdict_score_must_be_finite_number(score: object) -> None:
    with pytest.raises(ValueError, match="score"):
        VerdictInput(
            sha256=SHA256,
            decision=Decision.ALLOW,
            score=score,  # type: ignore[arg-type]
            policy_version="policy-1",
            analyzer_version="analyzer-1",
            baseline_sha256=None,
        )


def test_verdict_score_normalizes_int_to_float() -> None:
    verdict = VerdictInput(
        sha256=SHA256,
        decision=Decision.ALLOW,
        score=1,
        policy_version="policy-1",
        analyzer_version="analyzer-1",
        baseline_sha256=None,
    )

    assert verdict.score == 1.0
    assert isinstance(verdict.score, float)


def test_claimed_artifact_carries_opaque_lease_token() -> None:
    claim = ClaimedArtifact(
        sha256=SHA256,
        size_bytes=1,
        worker_id="worker",
        lease_expires_at=datetime.now(UTC) + timedelta(minutes=5),
        lease_token="b" * 64,
    )

    assert claim.lease_token == "b" * 64


def test_manual_override_decision_must_be_a_decision() -> None:
    with pytest.raises(ValueError, match="decision"):
        ManualOverrideInput(
            sha256=SHA256,
            decision="ALLOW",  # type: ignore[arg-type]
            actor="admin",
            reason="reviewed",
            created_at=datetime.now(UTC),
        )
