from __future__ import annotations

import json
from pathlib import Path

from tools.corpus_report import build_corpus_report


def test_offline_corpus_report_aggregates_f8_and_f9(make_sdist, make_wheel, tmp_path: Path) -> None:
    f8_artifact = make_wheel({"sitecustomize.py": "VALUE = 1\n"}, name="f8-demo.whl")
    sdist = make_sdist({"demo/__init__.py": ""}, name="pair-demo.tar.gz")
    wheel = make_wheel(
        {"demo/__init__.py": "", "demo.pth": "import os\n"},
        name="pair-demo.whl",
    )
    manifest = tmp_path / "corpus.json"
    manifest.write_text(
        json.dumps(
            {
                "f8": [{"name": "startup-hook", "artifact": f8_artifact.name}],
                "f9": [
                    {
                        "name": "wheel-only-pth",
                        "sdist": sdist.name,
                        "wheel": wheel.name,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = build_corpus_report(manifest)
    assert report["case_count"] == 2
    assert report["action_counts"]["DENY"] == 2
    assert report["rule_counts"] == {
        "customize_module": 1,
        "wheel_only_executable_pth": 1,
    }
    assert [case["name"] for case in report["cases"]] == [
        "startup-hook",
        "wheel-only-pth",
    ]


def test_corpus_manifest_rejects_missing_artifact(tmp_path: Path) -> None:
    manifest = tmp_path / "corpus.json"
    manifest.write_text(
        json.dumps({"f8": [{"name": "missing", "artifact": "missing.whl"}], "f9": []}),
        encoding="utf-8",
    )
    try:
        build_corpus_report(manifest)
    except ValueError as exc:
        assert "찾을 수 없습니다" in str(exc)
    else:
        raise AssertionError("missing artifact must be rejected")
