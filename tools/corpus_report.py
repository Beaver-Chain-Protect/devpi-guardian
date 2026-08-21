"""Evaluate local F8/F9 artifact cases and emit a deterministic JSON report."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from devpi_guardian.analyzers import (
    compare_sdist_wheel,
    findings_to_report,
    scan_install_surface,
)

CORPUS_REPORT_VERSION = "1.0"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _required_string(case: dict[str, Any], field: str, label: str) -> str:
    value = case.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label}.{field}는 비어 있지 않은 문자열이어야 합니다")
    return value


def _artifact_path(manifest_dir: Path, value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = manifest_dir / path
    path = path.resolve()
    if not path.is_file():
        raise ValueError(f"{label} artifact를 찾을 수 없습니다: {value}")
    return path


def build_corpus_report(manifest_path: str | Path) -> dict[str, object]:
    manifest_file = Path(manifest_path).resolve()
    data = json.loads(manifest_file.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("manifest 최상위 값은 객체여야 합니다")

    cases: list[dict[str, object]] = []
    seen_names: set[str] = set()
    action_counts: Counter[str] = Counter()
    rule_counts: Counter[str] = Counter()
    manifest_dir = manifest_file.parent

    for analyzer in ("F8", "F9"):
        raw_cases = data.get(analyzer.lower(), [])
        if not isinstance(raw_cases, list):
            raise ValueError(f"manifest.{analyzer.lower()}는 배열이어야 합니다")
        for index, raw_case in enumerate(raw_cases):
            label = f"{analyzer}[{index}]"
            if not isinstance(raw_case, dict):
                raise ValueError(f"{label}는 객체여야 합니다")
            name = _required_string(raw_case, "name", label)
            if name in seen_names:
                raise ValueError(f"중복 case 이름: {name}")
            seen_names.add(name)

            if analyzer == "F8":
                artifact_value = _required_string(raw_case, "artifact", label)
                artifact = _artifact_path(manifest_dir, artifact_value, label)
                findings = scan_install_surface(str(artifact))
                inputs = {"artifact": artifact_value}
                candidate_hash = _sha256(artifact)
            else:
                sdist_value = _required_string(raw_case, "sdist", label)
                wheel_value = _required_string(raw_case, "wheel", label)
                sdist = _artifact_path(manifest_dir, sdist_value, label)
                wheel = _artifact_path(manifest_dir, wheel_value, label)
                findings = compare_sdist_wheel(str(sdist), str(wheel))
                inputs = {"sdist": sdist_value, "wheel": wheel_value}
                candidate_hash = _sha256(wheel)

            for finding in findings:
                action_counts[finding.action] += 1
                rule_counts[finding.rule] += 1
            cases.append(
                {
                    "name": name,
                    "analyzer": analyzer,
                    "inputs": inputs,
                    "report": findings_to_report(
                        findings,
                        analyzer=analyzer,  # type: ignore[arg-type]
                        artifact_sha256=candidate_hash,
                    ),
                }
            )

    return {
        "corpus_report_version": CORPUS_REPORT_VERSION,
        "case_count": len(cases),
        "finding_count": sum(rule_counts.values()),
        "action_counts": {action: action_counts.get(action, 0) for action in ("REVIEW", "DENY")},
        "rule_counts": dict(sorted(rule_counts.items())),
        "cases": cases,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="로컬 artifact corpus를 F8/F9로 평가해 결정적인 JSON을 생성합니다."
    )
    parser.add_argument("manifest", help="corpus manifest JSON 경로")
    parser.add_argument("--output", "-o", help="출력 JSON 경로(생략하면 표준 출력)")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        report = build_corpus_report(arguments.manifest)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        _parser().error(str(exc))
    output = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        Path(arguments.output).write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
