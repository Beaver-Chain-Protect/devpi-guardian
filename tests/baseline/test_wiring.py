"""F6 + F7 driven by the real adapters, end to end.

A real SQLite verdict store chooses the baseline, a real `requests.Session`
downloads it from a loopback HTTP server, and F7 diffs the artifact against
it. Nothing here is a test double except the server standing in for devpi.
"""

from __future__ import annotations

import hashlib
import http.server
import threading

import pytest

from devpi_guardian.baseline import ReleaseRecord
from devpi_guardian.baseline.artifact_source import HttpArtifactBytesSource
from devpi_guardian.baseline.diff import compare_release_to_baseline
from devpi_guardian.baseline.release_lookup import VerdictReaderReleaseLookup
from devpi_guardian.verdicts.models import ArtifactState, Decision
from devpi_guardian.verdicts.reader import SQLiteVerdictReader

from .artifacts import build_wheel
from .store_seed import NOW, build_store, seed_allowed, seed_artifact, seed_release
from .test_diff import BASE_UTILS, SNEAKED_UTILS

BASELINE_NAME = "demo_package-1.0.0-py3-none-any.whl"
TARGET_NAME = "demo_package-2.0.0-py3-none-any.whl"
STALE_NAME = "demo_package-0.9.0-py3-none-any.whl"


class _Server:
    """Serves a fixed path -> bytes map over loopback."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files
        self.requested: list[str] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requested.append(self.path)
                body = outer.files.get(self.path)
                if body is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> _Server:
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> bool:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        return False

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"


@pytest.fixture
def wheels(tmp_path):
    """A baseline wheel and a target that smuggles a flow into utils.py."""

    baseline = build_wheel(tmp_path / "baseline" / BASELINE_NAME, {"pkg/utils.py": BASE_UTILS})
    # Distinct bytes, so it is a distinct artifact row in the store.
    stale = build_wheel(
        tmp_path / "stale" / STALE_NAME,
        {"pkg/utils.py": BASE_UTILS.replace("os.getcwd()", "os.getenv('HOME')")},
    )
    target = build_wheel(tmp_path / "target" / TARGET_NAME, {"pkg/utils.py": SNEAKED_UTILS})
    return baseline, stale, target


def digest_of(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def file_route(digest: str, filename: str, *, base: str = "") -> str:
    return f"{base}/user/index/+f/{digest[:3]}/{digest[3:16]}/{filename}"


def wire(factory, session, trusted_devpi_url):
    lookup = VerdictReaderReleaseLookup(SQLiteVerdictReader(factory, now=lambda: NOW))
    return lookup, HttpArtifactBytesSource(session, lookup, trusted_devpi_url=trusted_devpi_url)


def target_record(sha256: str) -> ReleaseRecord:
    return ReleaseRecord(
        project="demo-package",
        version="2.0.0",
        filename=TARGET_NAME,
        sha256=sha256,
        size_bytes=0,
    )


def test_the_real_adapters_find_a_smuggled_flow_end_to_end(tmp_path, wheels):
    requests = pytest.importorskip("requests")
    baseline, stale, target = wheels
    baseline_sha = digest_of(baseline)
    stale_sha = digest_of(stale)

    with _Server({file_route(baseline_sha, BASELINE_NAME): baseline.read_bytes()}) as server:
        factory = build_store(tmp_path)
        seed_allowed(
            factory,
            baseline_sha,
            version="1.0.0",
            filename=BASELINE_NAME,
            size_bytes=baseline.stat().st_size,
            origin_url=f"{server.base_url}{file_route(baseline_sha, BASELINE_NAME)}",
        )
        # An older approved release exists too; F6 must not pick it.
        seed_allowed(
            factory,
            stale_sha,
            version="0.9.0",
            filename=STALE_NAME,
            origin_url=f"{server.base_url}{file_route(stale_sha, STALE_NAME)}",
        )

        with requests.Session() as session:
            lookup, source = wire(factory, session, server.base_url)
            with source:
                result = compare_release_to_baseline(
                    target_record(digest_of(target)),
                    target,
                    lookup=lookup,
                    bytes_source=source,
                )

    assert result.has_baseline is True
    assert result.baseline_sha256 == baseline_sha
    assert result.selection is not None
    assert result.selection.tier == "same_tag"
    assert result.selection.release.version == "1.0.0"

    assert result.diff is not None
    assert result.diff.files.changed == ("pkg/utils.py",)
    assert [(finding.rule, origin) for finding, origin in result.findings] == [
        ("baseline_new_credential_network", "diff_changed")
    ]
    assert result.findings[0][0].sink == "requests.post"

    # Only the selected baseline was fetched, from the URL F4 recorded.
    assert server.requested == [file_route(baseline_sha, BASELINE_NAME)]


def test_downloaded_baseline_files_are_gone_after_the_comparison(tmp_path, wheels):
    requests = pytest.importorskip("requests")
    baseline, _stale, target = wheels
    baseline_sha = digest_of(baseline)

    with _Server({file_route(baseline_sha, BASELINE_NAME): baseline.read_bytes()}) as server:
        factory = build_store(tmp_path)
        seed_allowed(
            factory,
            baseline_sha,
            version="1.0.0",
            filename=BASELINE_NAME,
            size_bytes=baseline.stat().st_size,
            origin_url=f"{server.base_url}{file_route(baseline_sha, BASELINE_NAME)}",
        )
        with requests.Session() as session:
            lookup, source = wire(factory, session, server.base_url)
            with source:
                compare_release_to_baseline(
                    target_record(digest_of(target)),
                    target,
                    lookup=lookup,
                    bytes_source=source,
                )
                downloaded = source.open(baseline_sha)
                assert downloaded.exists()

    assert not downloaded.exists()


def test_a_stored_baseline_size_mismatch_is_an_analyzer_error(tmp_path, wheels):
    requests = pytest.importorskip("requests")
    baseline, _stale, target = wheels
    baseline_sha = digest_of(baseline)

    with _Server({file_route(baseline_sha, BASELINE_NAME): baseline.read_bytes()}) as server:
        factory = build_store(tmp_path)
        seed_allowed(
            factory,
            baseline_sha,
            version="1.0.0",
            filename=BASELINE_NAME,
            size_bytes=baseline.stat().st_size + 1,
            origin_url=f"{server.base_url}{file_route(baseline_sha, BASELINE_NAME)}",
        )
        with requests.Session() as session:
            lookup, source = wire(factory, session, server.base_url)
            with source:
                result = compare_release_to_baseline(
                    target_record(digest_of(target)),
                    target,
                    lookup=lookup,
                    bytes_source=source,
                )

    assert result.has_baseline is True
    assert result.diff is None
    assert [finding.rule for finding, _ in result.findings] == ["analyzer_error"]
    assert "저장" in result.findings[0][0].snippet


def test_a_project_with_no_approved_release_skips_the_diff(tmp_path, wheels):
    requests = pytest.importorskip("requests")
    _baseline, _stale, target = wheels

    factory = build_store(tmp_path)
    with requests.Session() as session:
        lookup, source = wire(factory, session, "http://127.0.0.1")
        with source:
            result = compare_release_to_baseline(
                target_record(digest_of(target)),
                target,
                lookup=lookup,
                bytes_source=source,
            )

    assert result.has_baseline is False
    assert result.baseline_sha256 is None
    assert result.findings == ()


def test_an_undownloadable_baseline_is_an_analyzer_error_not_a_first_release(tmp_path, wheels):
    requests = pytest.importorskip("requests")
    baseline, _stale, target = wheels
    baseline_sha = digest_of(baseline)

    # The store approves a release the server does not serve.
    with _Server({}) as server:
        factory = build_store(tmp_path)
        seed_allowed(
            factory,
            baseline_sha,
            version="1.0.0",
            filename=BASELINE_NAME,
            size_bytes=len(b"not the approved wheel"),
            origin_url=f"{server.base_url}{file_route(baseline_sha, BASELINE_NAME)}",
        )
        with requests.Session() as session:
            lookup, source = wire(factory, session, server.base_url)
            with source:
                result = compare_release_to_baseline(
                    target_record(digest_of(target)),
                    target,
                    lookup=lookup,
                    bytes_source=source,
                )

    assert result.has_baseline is True
    assert result.baseline_sha256 == baseline_sha
    assert result.diff is None
    assert [(finding.rule, origin) for finding, origin in result.findings] == [
        ("analyzer_error", "diff_artifact")
    ]


def test_a_tampered_baseline_body_is_an_analyzer_error(tmp_path, wheels):
    requests = pytest.importorskip("requests")
    baseline, _stale, target = wheels
    baseline_sha = digest_of(baseline)

    # devpi answers with bytes that are not the approved artifact.
    with _Server({file_route(baseline_sha, BASELINE_NAME): b"not the approved wheel"}) as server:
        factory = build_store(tmp_path)
        seed_allowed(
            factory,
            baseline_sha,
            version="1.0.0",
            filename=BASELINE_NAME,
            size_bytes=len(b"not the approved wheel"),
            origin_url=f"{server.base_url}{file_route(baseline_sha, BASELINE_NAME)}",
        )
        with requests.Session() as session:
            lookup, source = wire(factory, session, server.base_url)
            with source:
                result = compare_release_to_baseline(
                    target_record(digest_of(target)),
                    target,
                    lookup=lookup,
                    bytes_source=source,
                )

    assert result.has_baseline is True
    assert result.diff is None
    assert [finding.rule for finding, _ in result.findings] == ["analyzer_error"]
    assert "ArtifactDigestMismatch" in result.findings[0][0].snippet


def test_a_review_only_project_history_yields_no_baseline(tmp_path, wheels):
    requests = pytest.importorskip("requests")
    baseline, _stale, target = wheels

    factory = build_store(tmp_path)
    seed_artifact(
        factory, digest_of(baseline), ArtifactState.REVIEW, automated=(Decision.REVIEW, "policy-1")
    )
    seed_release(factory, digest_of(baseline), version="1.0.0", filename=BASELINE_NAME)

    with requests.Session() as session:
        lookup, source = wire(factory, session, "http://127.0.0.1")
        with source:
            result = compare_release_to_baseline(
                target_record(digest_of(target)),
                target,
                lookup=lookup,
                bytes_source=source,
            )

    assert result.has_baseline is False
    assert result.findings == ()
