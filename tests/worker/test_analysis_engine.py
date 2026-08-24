from __future__ import annotations

import hashlib
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
        sha256=hashlib.sha256(b"artifact").hexdigest(),
        size_bytes=len(b"artifact"),
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


class EntryClosedLookupRaises:
    def __init__(self) -> None:
        self.close_calls = 0
        self._position = 0

    @property
    def closed(self):
        raise RuntimeError("closed lookup")

    def read(self, size=-1):
        return b"artifact"

    def seek(self, position):
        self._position = position

    def tell(self):
        return self._position

    def close(self):
        self.close_calls += 1
        raise RuntimeError("entry cleanup")


class EntrySeekRaises:
    def __init__(self) -> None:
        self.seek_calls = 0
        self.close_calls = 0
        self.closed = False

    def read(self, size=-1):
        return b"artifact"

    def seek(self, position):
        self.seek_calls += 1
        if self.seek_calls > 1:
            raise RuntimeError("entry seek")

    def tell(self):
        return 0

    def close(self):
        self.close_calls += 1


@pytest.mark.parametrize("stream", [EntryClosedLookupRaises(), EntrySeekRaises()])
def test_analysis_entry_failure_closes_stream_and_preserves_primary(stream) -> None:
    artifact = VerifiedArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0.0",
        filename="demo-1.0.0.tar.gz",
        sha256=hashlib.sha256(b"artifact").hexdigest(),
        size_bytes=8,
        _stream=stream,
    )

    with pytest.raises(RuntimeError) as raised, artifact.open_for_analysis():
        pass
    assert stream.close_calls == 1
    if isinstance(stream, EntryClosedLookupRaises):
        assert any("cleanup" in note for note in raised.value.__notes__)


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


def test_analysis_scope_preserves_body_error_when_close_fails() -> None:
    stream = CloseFailStream(b"artifact", "scope cleanup")
    artifact = VerifiedArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0.0",
        filename="demo-1.0.0.tar.gz",
        sha256="a" * 64,
        size_bytes=8,
        _stream=stream,
    )

    with (
        pytest.raises(ValueError, match="body failure") as raised,
        artifact.open_for_analysis() as opened,
    ):
        opened.read()
        raise ValueError("body failure")
    assert any("scope cleanup" in note for note in raised.value.__notes__)


def _valid_stream_artifact(payload: bytes, *, filename: str = "demo-1.0.0.whl") -> VerifiedArtifact:
    return VerifiedArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0.0",
        filename=filename,
        sha256=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
        _stream=BytesIO(payload),
    )


def _materialization_engine(calls: list[Path]):
    def baseline(*args, **kwargs):
        calls.append(Path(args[1]))
        return SimpleNamespace(
            has_baseline=False,
            baseline_sha256=None,
            selection=None,
            findings=(),
        )

    return GuardianAnalysisEngine(
        lookup=object(),
        bytes_source=object(),
        analyzer_version="analyzers-1",
        baseline_analyzer=baseline,
        install_surface_analyzer=lambda path, *, limits: calls.append(Path(path)) or [],
        sdist_wheel_analyzer=lambda *args, **kwargs: pytest.fail("F9 must be skipped"),
    )


@pytest.mark.parametrize(
    ("payload", "size", "sha256"),
    [
        (b"artifact-plus", 8, hashlib.sha256(b"artifact-plus").hexdigest()),
        (b"short", 8, hashlib.sha256(b"short").hexdigest()),
        (b"artifact", 8, "b" * 64),
    ],
)
def test_materialization_rejects_excess_short_or_mismatched_digest(payload, size, sha256) -> None:
    stream = BytesIO(payload)
    artifact = VerifiedArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0.0",
        filename="demo-1.0.0.whl",
        sha256=sha256,
        size_bytes=size,
        _stream=stream,
    )
    calls: list[Path] = []

    with pytest.raises(ValueError):
        _materialization_engine(calls).analyze(AnalysisBundle(target=artifact))
    assert calls == []
    assert stream.closed


def test_materialization_accepts_exact_bytes_and_closes_stream() -> None:
    payload = b"artifact"
    artifact = _valid_stream_artifact(payload)
    calls: list[Path] = []

    report = _materialization_engine(calls).analyze(AnalysisBundle(target=artifact))

    assert report.steps[0].status == "skipped"
    assert len(calls) == 2
    assert artifact._stream.closed


def test_shared_stream_conflicting_identity_fails_before_analyzers() -> None:
    payload = b"artifact"
    stream = BytesIO(payload)
    first = VerifiedArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0.0",
        filename="demo-1.0.0.whl",
        sha256=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
        _stream=stream,
    )
    second = VerifiedArtifact(
        stage="root/pypi",
        project="demo",
        version="1.0.0",
        filename="other-1.0.0.whl",
        sha256=first.sha256,
        size_bytes=first.size_bytes,
        _stream=stream,
    )
    calls: list[Path] = []

    with pytest.raises(ValueError, match="shared stream"):
        _materialization_engine(calls).analyze(
            AnalysisBundle(target=first, same_release_wheel=second)
        )
    assert calls == []
    assert first._stream.closed
    assert stream.closed


class TrackingBytesSource:
    def __init__(self) -> None:
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class FailingBytesSource(TrackingBytesSource):
    def __init__(self) -> None:
        super().__init__()
        self.fail = True

    def close(self) -> None:
        self.close_calls += 1
        if self.fail:
            raise RuntimeError("source close")


def test_owned_engine_close_retries_after_failure_and_is_idempotent() -> None:
    source = FailingBytesSource()
    engine = GuardianAnalysisEngine(
        lookup=object(),
        bytes_source=source,
        analyzer_version="analyzers-1",
        owns_bytes_source=True,
    )

    with pytest.raises(RuntimeError, match="source close"):
        engine.close()
    source.fail = False
    engine.close()
    engine.close()
    assert source.close_calls == 2


def test_engine_context_preserves_body_error_when_source_close_fails() -> None:
    source = FailingBytesSource()
    engine = GuardianAnalysisEngine(
        lookup=object(),
        bytes_source=source,
        analyzer_version="analyzers-1",
        owns_bytes_source=True,
    )

    with pytest.raises(ValueError, match="body") as raised, engine:
        raise ValueError("body")
    assert any("source cleanup" in note for note in raised.value.__notes__)


def test_engine_context_propagates_source_cleanup_without_body_error() -> None:
    source = FailingBytesSource()
    engine = GuardianAnalysisEngine(
        lookup=object(),
        bytes_source=source,
        analyzer_version="analyzers-1",
        owns_bytes_source=True,
    )

    with pytest.raises(RuntimeError, match="source close"), engine:
        pass


def test_owned_bytes_source_closes_after_each_analysis_and_explicit_close() -> None:
    source = TrackingBytesSource()
    calls: list[Path] = []
    engine = GuardianAnalysisEngine(
        lookup=object(),
        bytes_source=source,
        analyzer_version="analyzers-1",
        owns_bytes_source=True,
        baseline_analyzer=lambda *args, **kwargs: SimpleNamespace(
            has_baseline=False, baseline_sha256=None, selection=None, findings=()
        ),
        install_surface_analyzer=lambda path, *, limits: calls.append(Path(path)) or [],
        sdist_wheel_analyzer=lambda *args, **kwargs: pytest.fail("F9 must be skipped"),
    )

    engine.analyze(AnalysisBundle(target=_valid_stream_artifact(b"artifact")))
    engine.analyze(AnalysisBundle(target=_valid_stream_artifact(b"artifact")))
    engine.close()
    engine.close()

    assert source.close_calls == 3


def test_injected_bytes_source_is_not_closed_unless_owned() -> None:
    source = TrackingBytesSource()
    engine = GuardianAnalysisEngine(
        lookup=object(),
        bytes_source=source,
        analyzer_version="analyzers-1",
        baseline_analyzer=lambda *args, **kwargs: SimpleNamespace(
            has_baseline=False, baseline_sha256=None, selection=None, findings=()
        ),
        install_surface_analyzer=lambda path, *, limits: [],
        sdist_wheel_analyzer=lambda *args, **kwargs: pytest.fail("F9 must be skipped"),
    )

    engine.analyze(AnalysisBundle(target=_valid_stream_artifact(b"artifact")))
    engine.close()

    assert source.close_calls == 0


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
