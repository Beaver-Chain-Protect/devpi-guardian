from __future__ import annotations

import pytest

from devpi_guardian.analyzers import (
    AnalysisLimits,
    compare_sdist_wheel_isolated,
    scan_install_surface_isolated,
)


def test_isolated_f8_returns_findings(make_wheel) -> None:
    artifact = make_wheel({"sitecustomize.py": "VALUE = 1\n"})
    findings = scan_install_surface_isolated(
        str(artifact), limits=AnalysisLimits(timeout_seconds=10)
    )
    assert [item.rule for item in findings] == ["customize_module"]


def test_isolated_f9_returns_findings(make_sdist, make_wheel) -> None:
    sdist = make_sdist({"demo/__init__.py": ""})
    wheel = make_wheel({"demo/__init__.py": "", "demo.pth": "import os\n"})
    findings = compare_sdist_wheel_isolated(
        str(sdist), str(wheel), limits=AnalysisLimits(timeout_seconds=10)
    )
    assert [item.rule for item in findings] == ["wheel_only_executable_pth"]


def test_isolated_timeout_returns_analyzer_error(make_wheel) -> None:
    artifact = make_wheel({"demo/__init__.py": ""})
    findings = scan_install_surface_isolated(
        str(artifact), limits=AnalysisLimits(timeout_seconds=0.000001)
    )
    assert [item.rule for item in findings] == ["analyzer_error"]
    assert "timeout" in findings[0].snippet


def test_invalid_limits_are_rejected() -> None:
    with pytest.raises(ValueError):
        AnalysisLimits(timeout_seconds=0)
    with pytest.raises(ValueError):
        AnalysisLimits(memory_limit_mb=32)
