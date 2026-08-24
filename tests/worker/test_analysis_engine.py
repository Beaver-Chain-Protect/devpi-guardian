from __future__ import annotations

from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest

from devpi_guardian.analyzers import Finding
from devpi_guardian.worker.analysis import GuardianAnalysisEngine, build_analysis_engine
from devpi_guardian.worker.models import AnalysisBundle, VerifiedArtifact


def verified(path: Path, filename: str, sha256: str) -> VerifiedArtifact:
    return VerifiedArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0.0",
        filename=filename,
        sha256=sha256,
        size_bytes=8,
        _stream=BytesIO(b"artifact"),
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

    bundle = AnalysisBundle(target=wheel, same_release_sdist=sdist)
    report = engine.analyze(bundle)
    bundle.close()
    assert wheel._stream.closed
    assert sdist._stream.closed

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

    bundle = AnalysisBundle(target=target)
    report = engine.analyze(bundle)
    bundle.close()
    assert target._stream.closed

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
        trusted_devpi_url="https://devpi.example",
    )

    assert engine._bytes_source._resolver is engine._lookup


def test_verified_artifact_owns_stream_and_analysis_scope_rewinds_and_closes() -> None:
    stream = BytesIO(b"artifact")
    stream.read(2)
    artifact = VerifiedArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0.0",
        filename="demo-1.0.0.tar.gz",
        sha256="a" * 64,
        size_bytes=8,
        _stream=stream,
    )

    assert not hasattr(artifact, "local_path")
    assert not hasattr(artifact, "path")
    assert not hasattr(artifact, "origin_url")
    with artifact.open_for_analysis() as opened:
        assert opened.read() == b"artifact"
    assert stream.closed


@pytest.mark.parametrize(
    ("field", "value"),
    [("stage", ""), ("sha256", "A" * 64), ("size_bytes", -1)],
)
def test_verified_artifact_validation_failure_closes_owned_stream(field, value) -> None:
    stream = BytesIO(b"artifact")
    values = {
        "stage": "root/pypi",
        "project": "demo",
        "version": "1.0.0",
        "filename": "demo-1.0.0.tar.gz",
        "sha256": "a" * 64,
        "size_bytes": 8,
        "_stream": stream,
    }
    values[field] = value

    with pytest.raises(ValueError):
        VerifiedArtifact(**values)
    assert stream.closed


class NonSeekableBinary:
    def __init__(self) -> None:
        self.closed = False

    def read(self, size=-1):
        return b"artifact"

    def close(self):
        self.closed = True


class TextStream:
    def __init__(self) -> None:
        from io import StringIO

        self._stream = StringIO("artifact")

    @property
    def closed(self):
        return self._stream.closed

    def read(self, size=-1):
        return self._stream.read(size)

    def seek(self, position):
        return self._stream.seek(position)

    def tell(self):
        return self._stream.tell()

    def close(self):
        return self._stream.close()


@pytest.mark.parametrize("stream", [NonSeekableBinary(), TextStream()])
def test_verified_artifact_stream_validation_failure_closes_owned_stream(stream) -> None:
    with pytest.raises(ValueError):
        VerifiedArtifact(
            stage="root/pypi",
            project="demo",
            version="1.0.0",
            filename="demo-1.0.0.tar.gz",
            sha256="a" * 64,
            size_bytes=8,
            _stream=stream,
        )
    assert stream.closed


class CloseFailStream(BytesIO):
    def __init__(self, value: bytes, message: str) -> None:
        super().__init__(value)
        self.message = message
        self.close_attempts = 0

    def close(self) -> None:
        self.close_attempts += 1
        raise RuntimeError(self.message)


class ClosePropertyRaises:
    def __init__(self) -> None:
        self.closed = False

    @property
    def close(self):
        raise RuntimeError("close lookup")


def test_verified_artifact_preserves_validation_error_when_close_lookup_fails() -> None:
    stream = ClosePropertyRaises()
    with pytest.raises(ValueError) as raised:
        VerifiedArtifact(
            stage="",
            project="demo",
            version="1.0.0",
            filename="demo-1.0.0.tar.gz",
            sha256="a" * 64,
            size_bytes=8,
            _stream=stream,
        )
    assert "stage" in str(raised.value)
    assert any("cleanup lookup failed" in note for note in raised.value.__notes__)


def test_verified_artifact_preserves_validation_error_when_cleanup_fails() -> None:
    stream = CloseFailStream(b"artifact", "cleanup")
    with pytest.raises(ValueError) as raised:
        VerifiedArtifact(
            stage="",
            project="demo",
            version="1.0.0",
            filename="demo-1.0.0.tar.gz",
            sha256="a" * 64,
            size_bytes=8,
            _stream=stream,
        )
    assert "stage" in str(raised.value)
    assert stream.close_attempts == 1
