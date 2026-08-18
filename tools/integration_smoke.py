"""Run a five-minute handoff check against the public F8/F9 API."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from devpi_guardian.analyzers import (
    compare_sdist_wheel,
    finding_from_dict,
    finding_to_dict,
    findings_to_report,
    scan_install_surface,
)

from .demo_scenario import create_demo

_EXPECTED_F8 = {"executable_pth"}
_EXPECTED_F9 = {
    "wheel_only_credential_network",
    "wheel_only_executable_pth",
}


def verify_integration(output_dir: str | Path = ".demo") -> dict[str, object]:
    """Create safe synthetic artifacts and validate the public handoff contract."""

    sdist, wheel, report_path = create_demo(output_dir)
    f8_findings = scan_install_surface(str(wheel))
    f9_findings = compare_sdist_wheel(str(sdist), str(wheel))

    f8_rules = {finding.rule for finding in f8_findings}
    f9_rules = {finding.rule for finding in f9_findings}
    if not f8_rules >= _EXPECTED_F8:
        raise AssertionError(f"F8 expected rules missing: {sorted(_EXPECTED_F8 - f8_rules)}")
    if not f9_rules >= _EXPECTED_F9:
        raise AssertionError(f"F9 expected rules missing: {sorted(_EXPECTED_F9 - f9_rules)}")
    if any(finding.action != "DENY" for finding in [*f8_findings, *f9_findings]):
        raise AssertionError("synthetic attack findings must all be DENY")

    for finding in [*f8_findings, *f9_findings]:
        encoded = finding_to_dict(finding)
        if finding_from_dict(encoded) != finding:
            raise AssertionError("Finding JSON round-trip changed the evidence")
        if len(str(encoded["fingerprint"])) != 64:
            raise AssertionError("Finding fingerprint is not SHA-256 length")

    f8_report = findings_to_report(f8_findings, analyzer="F8")
    f9_report = findings_to_report(f9_findings, analyzer="F9")
    if f8_report["schema_version"] != f9_report["schema_version"]:
        raise AssertionError("F8/F9 report schema versions differ")

    return {
        "status": "ok",
        "schema_version": f8_report["schema_version"],
        "ruleset_version": f8_report["ruleset_version"],
        "f8": {
            "finding_count": len(f8_findings),
            "rules": sorted(f8_rules),
        },
        "f9": {
            "finding_count": len(f9_findings),
            "rules": sorted(f9_rules),
        },
        "demo_report": str(report_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="F8/F9 공개 API와 JSON 계약을 합성 artifact로 빠르게 확인합니다."
    )
    parser.add_argument("--output-dir", default=".demo")
    arguments = parser.parse_args()
    try:
        result = verify_integration(arguments.output_dir)
    except (OSError, ValueError, AssertionError) as exc:
        print(f"integration smoke test: FAILED: {exc}")
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
