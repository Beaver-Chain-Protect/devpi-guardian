from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from devpi_guardian.analyzers import Finding
from devpi_guardian.worker.analysis import GuardianAnalysisEngine, build_analysis_engine
from devpi_guardian.worker.models import AnalysisBundle, VerifiedArtifact


def verified(path: Path, filename: str, sha256: str) -> VerifiedArtifact:
    path.write_bytes(b"artifact")
    return VerifiedArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0.0",
        filename=filename,
        sha256=sha256,
        size_bytes=8,
        local_path=path,
    )


def finding(rule: str) -> Finding:
    return Finding(
        rule=rule,
        action="REVIEW",
        file="setup.py",
        line=1,
        snippet=rule,
        message=rule,
    )


def test_engine_exposes_one_call_and_keeps_f7_f8_f9_attribution(tmp_path) -> None:
    wheel = verified(tmp_path / "target.whl", "demo-1.0.0-py3-none-any.whl", "a" * 64)
    sdist = verified(tmp_path / "target.tar.gz", "demo-1.0.0.tar.gz", "b" * 64)
    calls = []

    def baseline(target, artifact_path, *, lookup, bytes_source):
        calls.append(("F7", target.filename, Path(artifact_path)))
        return SimpleNamespace(
            has_baseline=True,
            baseline_sha256="c" * 64,
            selection=SimpleNamespace(tier="same_tag"),
            diff=SimpleNamespace(
                files=SimpleNamespace(
                    added=("demo/new.py",),
                    changed=("demo/core.py",),
                    removed=(),
                )
            ),
            findings=((finding("f7_rule"), "diff_changed"),),
        )

    def install_surface(path, *, limits):
        calls.append(("F8", Path(path)))
        return [finding("f8_rule")]

    def sdist_wheel(sdist_path, wheel_path, *, limits):
        calls.append(("F9", Path(sdist_path), Path(wheel_path)))
        return [finding("f9_rule")]

    engine = GuardianAnalysisEngine(
        lookup=object(),
        bytes_source=object(),
        analyzer_version="analyzers-1",
        baseline_analyzer=baseline,
        install_surface_analyzer=install_surface,
        sdist_wheel_analyzer=sdist_wheel,
    )

    report = engine.analyze(
        AnalysisBundle(target=wheel, same_release_sdist=sdist),
    )

    assert [item.analyzer for item in report.evidence] == ["F7", "F8", "F9"]
    assert report.file_diff is not None
    assert report.file_diff.added == ("demo/new.py",)
    assert report.file_diff.changed == ("demo/core.py",)
    assert [item.finding.rule for item in report.evidence] == [
        "f7_rule",
        "f8_rule",
        "f9_rule",
    ]
    assert report.evidence[0].origin == "diff_changed"
    assert report.evidence[0].baseline_tier == "same_tag"
    assert report.baseline_sha256 == "c" * 64
    assert [step.status for step in report.steps] == ["completed"] * 3
    assert [call[0] for call in calls] == ["F7", "F8", "F9"]


def test_engine_skips_f7_without_baseline_and_f9_without_pair(tmp_path) -> None:
    target = verified(tmp_path / "target.whl", "demo-1.0.0-py3-none-any.whl", "a" * 64)

    def baseline(*args, **kwargs):
        return SimpleNamespace(
            has_baseline=False,
            baseline_sha256=None,
            selection=None,
            findings=(),
        )

    engine = GuardianAnalysisEngine(
        lookup=object(),
        bytes_source=object(),
        analyzer_version="analyzers-1",
        baseline_analyzer=baseline,
        install_surface_analyzer=lambda path, *, limits: [],
        sdist_wheel_analyzer=lambda *args, **kwargs: pytest.fail("F9 must be skipped"),
    )

    report = engine.analyze(AnalysisBundle(target=target))

    assert [(step.analyzer, step.status) for step in report.steps] == [
        ("F7", "skipped"),
        ("F8", "completed"),
        ("F9", "skipped"),
    ]


def test_build_analysis_engine_reuses_lookup_as_http_origin_resolver() -> None:
    class Reader:
        def list_allowed_releases(self, project):
            return ()

    engine = build_analysis_engine(
        reader=Reader(),
        session=object(),
        analyzer_version="analyzers-1",
    )

    assert engine._bytes_source._resolver is engine._lookup
