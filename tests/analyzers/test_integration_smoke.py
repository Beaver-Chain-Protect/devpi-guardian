from __future__ import annotations

from pathlib import Path

from tools.integration_smoke import verify_integration


def test_public_handoff_contract(tmp_path: Path) -> None:
    result = verify_integration(tmp_path / "handoff")
    assert result["status"] == "ok"
    assert result["schema_version"] == "1.1"
    assert result["f8"] == {
        "finding_count": 1,
        "rules": ["executable_pth"],
    }
    assert result["f9"] == {
        "finding_count": 2,
        "rules": [
            "wheel_only_credential_network",
            "wheel_only_executable_pth",
        ],
    }
