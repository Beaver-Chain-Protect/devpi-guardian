"""Versioned, deterministic JSON serialization for analyzer findings."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from importlib import resources
from typing import Any, Literal

from .rules import RULESET_VERSION
from .types import Finding, make_finding, sort_findings

REPORT_SCHEMA_VERSION = "1.1"
AnalyzerName = Literal["F8", "F9"]


def finding_fingerprint(finding: Finding) -> str:
    """Stable evidence identity, intentionally independent of action/message."""

    identity = {
        "rule": finding.rule,
        "file": finding.file,
        "line": finding.line,
        "snippet": finding.snippet,
        "source": finding.source,
        "sink": finding.sink,
    }
    encoded = json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def finding_to_dict(finding: Finding) -> dict[str, object]:
    return {
        "fingerprint": finding_fingerprint(finding),
        "rule": finding.rule,
        "action": finding.action,
        "file": finding.file,
        "line": finding.line,
        "snippet": finding.snippet,
        "message": finding.message,
        "source": finding.source,
        "sink": finding.sink,
    }


def finding_from_dict(data: Mapping[str, Any]) -> Finding:
    """Validate and restore one Finding from an integration boundary."""

    expected_fields = {
        "rule",
        "action",
        "file",
        "line",
        "snippet",
        "message",
        "source",
        "sink",
        "fingerprint",
    }
    missing = expected_fields - set(data)
    unexpected = set(data) - expected_fields
    if missing or unexpected:
        raise ValueError(
            f"Finding 필드 불일치: missing={sorted(missing)}, unexpected={sorted(unexpected)}"
        )
    fingerprint = data.get("fingerprint")
    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(character not in "0123456789abcdef" for character in fingerprint)
    ):
        raise ValueError("Finding.fingerprint는 64자리 소문자 16진수여야 합니다")
    action = data.get("action")
    if action not in {"REVIEW", "DENY"}:
        raise ValueError("Finding.action은 REVIEW 또는 DENY여야 합니다")
    rule_id = data.get("rule")
    file = data.get("file")
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError("Finding.rule은 비어 있지 않은 문자열이어야 합니다")
    if not isinstance(file, str) or not file:
        raise ValueError("Finding.file은 비어 있지 않은 문자열이어야 합니다")
    line = data.get("line")
    if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
        raise ValueError("Finding.line은 null 또는 1 이상의 정수여야 합니다")

    def optional_string(name: str) -> str | None:
        value = data.get(name)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"Finding.{name}은 문자열 또는 null이어야 합니다")
        return value

    snippet = data.get("snippet")
    message = data.get("message")
    if not isinstance(snippet, str) or not isinstance(message, str):
        raise ValueError("Finding.snippet과 message는 문자열이어야 합니다")
    finding = make_finding(
        rule=rule_id,
        action=action,
        file=file,
        line=line,
        snippet=snippet,
        message=message,
        source=optional_string("source"),
        sink=optional_string("sink"),
    )
    if finding_fingerprint(finding) != fingerprint:
        raise ValueError("Finding.fingerprint가 Finding 내용과 일치하지 않습니다")
    return finding


def findings_to_report(
    findings: Sequence[Finding],
    *,
    analyzer: AnalyzerName,
    artifact_sha256: str | None = None,
) -> dict[str, object]:
    """Build a stable report without timestamps or a final security verdict."""

    if analyzer not in {"F8", "F9"}:
        raise ValueError("analyzer는 F8 또는 F9여야 합니다")
    if artifact_sha256 is not None:
        normalized_hash = artifact_sha256.strip().lower()
        if len(normalized_hash) != 64 or any(
            character not in "0123456789abcdef" for character in normalized_hash
        ):
            raise ValueError("artifact_sha256은 64자리 16진수여야 합니다")
        artifact_sha256 = normalized_hash

    ordered = sort_findings(list(findings))
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "ruleset_version": RULESET_VERSION,
        "analyzer": analyzer,
        "artifact_sha256": artifact_sha256,
        "finding_count": len(ordered),
        "findings": [finding_to_dict(finding) for finding in ordered],
    }


def dumps_report(
    findings: Sequence[Finding],
    *,
    analyzer: AnalyzerName,
    artifact_sha256: str | None = None,
    indent: int | None = 2,
) -> str:
    return json.dumps(
        findings_to_report(
            findings,
            analyzer=analyzer,
            artifact_sha256=artifact_sha256,
        ),
        ensure_ascii=False,
        indent=indent,
        sort_keys=True,
    )


def report_schema_text() -> str:
    return (
        resources.files("devpi_guardian.analyzers")
        .joinpath("schemas/finding-report-v1.schema.json")
        .read_text(encoding="utf-8")
    )
