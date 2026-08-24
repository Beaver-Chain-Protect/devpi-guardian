from __future__ import annotations

import json
from dataclasses import replace

import pytest

from devpi_guardian.analyzers import (
    dumps_report,
    finding_fingerprint,
    finding_from_dict,
    finding_to_dict,
    findings_to_report,
    report_schema_text,
)
from devpi_guardian.analyzers.types import make_finding


def _finding(file: str, line: int):
    return make_finding(
        rule="example_rule",
        action="REVIEW",
        file=file,
        line=line,
        snippet="example()",
        message="검토가 필요합니다.",
    )


def test_finding_dictionary_round_trip() -> None:
    original = _finding("demo/core.py", 3)
    assert finding_from_dict(finding_to_dict(original)) == original


def test_fingerprint_tracks_evidence_not_action_or_message() -> None:
    original = _finding("demo/core.py", 3)
    policy_changed = replace(original, action="DENY", message="정책 문구 변경")
    evidence_changed = replace(original, line=4)
    assert finding_fingerprint(original) == finding_fingerprint(policy_changed)
    assert finding_fingerprint(original) != finding_fingerprint(evidence_changed)


def test_report_is_versioned_sorted_and_deterministic() -> None:
    findings = [_finding("z.py", 5), _finding("a.py", 2)]
    artifact_hash = "A" * 64
    first = findings_to_report(findings, analyzer="F8", artifact_sha256=artifact_hash)
    second = findings_to_report(
        list(reversed(findings)), analyzer="F8", artifact_sha256=artifact_hash
    )

    assert first == second
    assert first["schema_version"] == "1.1"
    assert first["ruleset_version"]
    assert first["artifact_sha256"] == "a" * 64
    assert [item["file"] for item in first["findings"]] == ["a.py", "z.py"]
    assert json.loads(dumps_report(findings, analyzer="F8", artifact_sha256=artifact_hash)) == first


def test_invalid_integration_data_is_rejected() -> None:
    data = finding_to_dict(_finding("demo.py", 1))
    data["action"] = "ALLOW"
    with pytest.raises(ValueError):
        finding_from_dict(data)

    with pytest.raises(ValueError):
        findings_to_report([], analyzer="F9", artifact_sha256="not-a-hash")


def test_packaged_json_schema_is_readable() -> None:
    schema = json.loads(report_schema_text())
    assert schema["properties"]["schema_version"]["const"] == "1.1"
    assert schema["$defs"]["finding"]["properties"]["action"]["enum"] == [
        "REVIEW",
        "DENY",
    ]
