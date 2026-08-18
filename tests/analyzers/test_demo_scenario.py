from __future__ import annotations

import json
from pathlib import Path

from tools.demo_scenario import create_demo


def test_demo_scenario_generates_detected_artifacts(tmp_path: Path) -> None:
    sdist, wheel, report_path = create_demo(tmp_path / "demo")
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert sdist.is_file() and wheel.is_file()
    assert {item["rule"] for item in report["f8"]["findings"]} == {"executable_pth"}
    assert {
        "wheel_only_credential_network",
        "wheel_only_executable_pth",
    } <= {item["rule"] for item in report["f9"]["findings"]}
    assert all(
        len(item["fingerprint"]) == 64
        for section in (report["f8"], report["f9"])
        for item in section["findings"]
    )
