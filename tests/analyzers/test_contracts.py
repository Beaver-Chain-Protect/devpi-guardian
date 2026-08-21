from __future__ import annotations

import random
import time
from pathlib import Path

import pytest

from devpi_guardian.analyzers import compare_sdist_wheel, scan_install_surface


@pytest.mark.parametrize("payload", [b"", b"plain text", b"PK\x03\x04truncated"])
def test_malformed_wheel_never_leaks_exception(tmp_path: Path, payload: bytes) -> None:
    artifact = tmp_path / "malformed.whl"
    artifact.write_bytes(payload)
    findings = scan_install_surface(str(artifact))
    assert findings
    assert all(item.rule == "analyzer_error" for item in findings)


def test_nested_archive_is_treated_as_inert_data(make_wheel) -> None:
    artifact = make_wheel(
        {
            "demo/__init__.py": "VALUE = 1\n",
            "demo/vendor/nested.zip": b"not opened or executed",
        }
    )
    assert scan_install_surface(str(artifact)) == []


def test_seeded_malformed_archive_fuzz_never_leaks_exception(
    tmp_path: Path,
) -> None:
    random_source = random.Random(8102026)
    for index in range(32):
        artifact = tmp_path / f"fuzz-{index}.whl"
        artifact.write_bytes(random_source.randbytes(index * 17))
        findings = scan_install_surface(str(artifact))
        assert findings
        assert findings[0].rule == "analyzer_error"


def test_f9_missing_wheel_returns_evidence_not_exception(make_sdist, tmp_path: Path) -> None:
    sdist = make_sdist({"demo/__init__.py": ""})
    findings = compare_sdist_wheel(str(sdist), str(tmp_path / "missing.whl"))
    assert findings and findings[0].rule == "analyzer_error"


def test_roughly_ten_megabyte_artifact_finishes_under_30_seconds(
    make_wheel,
) -> None:
    payload = random.Random(2026).randbytes(9_000_000)
    artifact = make_wheel(
        {"demo/__init__.py": "", "demo/data.bin": payload},
        name="large-1.0.0-py3-none-any.whl",
    )
    started = time.perf_counter()
    scan_install_surface(str(artifact))
    assert time.perf_counter() - started < 30.0
