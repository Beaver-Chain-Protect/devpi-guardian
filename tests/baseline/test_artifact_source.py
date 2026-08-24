"""F6's ArtifactBytesSource over HTTP.

No test touches the network. Most use a fake session, which is also how the
"this class knows nothing about authentication" property is pinned down; one
runs a real `requests.Session` against a loopback server so the protocol is
proved against the library it will actually be given.
"""

from __future__ import annotations

import hashlib
import http.server
import threading
from pathlib import Path

import pytest

from devpi_guardian.baseline import ArtifactBytesSource
from devpi_guardian.baseline.artifact_source import (
    ArtifactDigestMismatch,
    ArtifactDownloadError,
    HttpArtifactBytesSource,
    OriginUrlResolver,
)

PAYLOAD = b"PK\x03\x04 pretend this is a wheel" * 100
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
OTHER_DIGEST = hashlib.sha256(b"something else").hexdigest()
URL = "https://devpi.example/root/dev/+f/aa/demo-1.0.0-py3-none-any.whl"


class DictResolver:
    def __init__(
        self,
        urls: dict[str, str] | None = None,
        sizes: dict[str, int] | None = None,
    ) -> None:
        self.urls = urls if urls is not None else {DIGEST: URL}
        self.sizes = sizes if sizes is not None else {DIGEST: len(PAYLOAD)}

    def origin_url(self, sha256: str) -> str:
        return self.urls[sha256]

    def expected_size(self, sha256: str) -> int:
        return self.sizes[sha256]


class FakeResponse:
    def __init__(self, body: bytes, status_code: int = 200) -> None:
        self.status_code = status_code
        self._body = body
        self.closed = False

    def iter_content(self, chunk_size: int):
        for offset in range(0, len(self._body), chunk_size):
            # Bound the slice to a name: `[offset : offset + chunk_size]` is
            # what the formatter produces, and flake8 reads that space as E203.
            end = offset + chunk_size
            yield self._body[offset:end]

    def close(self) -> None:
        self.closed = True


class FakeSession:
    """Records exactly what the source asked for, and nothing else exists."""

    def __init__(self, body: bytes = PAYLOAD, status_code: int = 200, error=None) -> None:
        self.body = body
        self.status_code = status_code
        self.error = error
        self.calls: list[tuple[str, dict]] = []
        self.responses: list[FakeResponse] = []

    def get(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        if self.error is not None:
            raise self.error
        response = FakeResponse(self.body, self.status_code)
        self.responses.append(response)
        return response


def make_source(session=None, resolver=None, **kwargs) -> HttpArtifactBytesSource:
    return HttpArtifactBytesSource(
        session if session is not None else FakeSession(),
        resolver if resolver is not None else DictResolver(),
        **kwargs,
    )


# --- protocol conformance -------------------------------------------------


def test_the_source_satisfies_f6_artifact_bytes_source():
    assert isinstance(make_source(), ArtifactBytesSource)


def test_a_plain_object_with_origin_url_satisfies_the_resolver_protocol():
    assert isinstance(DictResolver(), OriginUrlResolver)


# --- the happy path -------------------------------------------------------


def test_a_verified_artifact_is_written_to_a_local_path():
    with make_source() as source:
        path = source.open(DIGEST)
        assert isinstance(path, Path)
        assert path.read_bytes() == PAYLOAD


def test_the_resolved_url_is_the_one_requested():
    session = FakeSession()
    with make_source(session) as source:
        source.open(DIGEST)
    assert [url for url, _ in session.calls] == [URL]


def test_the_same_digest_is_downloaded_only_once():
    session = FakeSession()
    with make_source(session) as source:
        first = source.open(DIGEST)
        second = source.open(DIGEST)
    assert first == second
    assert len(session.calls) == 1


def test_the_response_is_closed():
    session = FakeSession()
    with make_source(session) as source:
        source.open(DIGEST)
    assert all(response.closed for response in session.responses)


# The extractor decides zip vs tar from the filename suffix, so a downloaded
# baseline must keep a recognizable name.


@pytest.mark.parametrize(
    ("url", "expected_suffix"),
    [
        ("https://devpi.example/root/dev/+f/aa/demo-1.0.0-py3-none-any.whl", ".whl"),
        ("https://devpi.example/root/dev/+f/aa/demo-1.0.0.tar.gz", ".tar.gz"),
        ("https://devpi.example/root/dev/+e/aa/demo-1.0.0.zip", ".zip"),
    ],
)
def test_the_downloaded_file_keeps_the_archive_suffix(url, expected_suffix):
    resolver = DictResolver({DIGEST: url})
    with make_source(resolver=resolver) as source:
        path = source.open(DIGEST)
    assert path.name.endswith(expected_suffix)
    assert path.name.startswith(DIGEST)


def test_a_downloaded_file_is_extractable_by_the_analyzer(tmp_path):
    from devpi_guardian.analyzers.archive import extract_artifact

    from .artifacts import build_wheel

    wheel = build_wheel(tmp_path / "demo-1.0.0-py3-none-any.whl", {"pkg/a.py": "x = 1\n"})
    body = wheel.read_bytes()
    digest = hashlib.sha256(body).hexdigest()
    resolver = DictResolver(
        {digest: "https://devpi.example/root/dev/+f/aa/demo-1.0.0-py3-none-any.whl"},
        {digest: len(body)},
    )
    with make_source(FakeSession(body=body), resolver) as source:
        extracted = extract_artifact(source.open(digest), tmp_path / "out")
        assert extracted.usable is True
        assert extracted.files == ("pkg/a.py",)


@pytest.mark.parametrize(
    "url",
    [
        "https://devpi.example",
        "https://devpi.example/",
        "https://devpi.example/root/dev/+f/aa/..",
        "https://devpi.example/root/dev/+f/aa/...",
    ],
)
def test_a_url_without_a_usable_filename_falls_back_to_the_digest(url):
    with make_source(resolver=DictResolver({DIGEST: url})) as source:
        assert source.open(DIGEST).name == DIGEST


def test_a_trailing_slash_url_uses_the_last_path_segment():
    url = "https://devpi.example/root/dev/+f/aa/"
    with make_source(resolver=DictResolver({DIGEST: url})) as source:
        assert source.open(DIGEST).name == f"{DIGEST}-aa"


def test_a_hostile_filename_in_the_url_cannot_escape_the_directory():
    url = "https://devpi.example/root/dev/+f/aa/%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    with make_source(resolver=DictResolver({DIGEST: url})) as source:
        path = source.open(DIGEST)
        assert path.parent == source._directory()
        assert "/" not in path.name


# --- authentication independence ------------------------------------------
# The point of injecting the session: this class must work identically no
# matter how (or whether) the session authenticates.


class AuthRecordingSession(FakeSession):
    """A session that authenticates entirely on its own."""

    def __init__(self, label: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.label = label
        self.headers = {"Authorization": f"Bearer {label}"}
        self.cookies = {"session": label}
        self.auth = (label, "secret")
        self.cert = f"/etc/ssl/{label}.pem"


@pytest.mark.parametrize(
    "session",
    [
        FakeSession(),
        AuthRecordingSession("token-auth"),
        AuthRecordingSession("mtls"),
    ],
    ids=["no-auth", "bearer-token", "client-cert"],
)
def test_any_session_works_regardless_of_its_authentication(session):
    with make_source(session) as source:
        assert source.open(DIGEST).read_bytes() == PAYLOAD


def test_the_source_passes_only_url_stream_and_timeout():
    # Nothing authentication-shaped is added by this class, so a session is
    # free to authenticate however it likes without this code changing.
    session = FakeSession()
    with make_source(session, timeout=12.5) as source:
        source.open(DIGEST)
    (url, kwargs) = session.calls[0]
    assert url == URL
    assert kwargs == {"stream": True, "timeout": 12.5, "allow_redirects": False}


def test_a_stored_size_mismatch_is_rejected_and_not_cached():
    resolver = DictResolver(sizes={DIGEST: len(PAYLOAD) + 1})
    with make_source(resolver=resolver) as source, pytest.raises(ArtifactDownloadError):
        source.open(DIGEST)
    assert source._downloaded == {}
    assert list(source._directory().iterdir()) == []


def test_a_session_object_with_nothing_but_get_is_enough():
    class BareSession:
        def get(self, url, **kwargs):
            return FakeResponse(PAYLOAD)

    with make_source(BareSession()) as source:
        assert source.open(DIGEST).read_bytes() == PAYLOAD


# --- digest verification --------------------------------------------------


def test_a_digest_mismatch_raises_and_leaves_no_file():
    session = FakeSession(body=b"tampered payload")
    resolver = DictResolver(sizes={DIGEST: len(b"tampered payload")})
    with make_source(session, resolver) as source:
        with pytest.raises(ArtifactDigestMismatch) as raised:
            source.open(DIGEST)
        assert DIGEST in str(raised.value)
        assert list(source._directory().iterdir()) == []


def test_a_digest_mismatch_is_a_download_error_subclass():
    assert issubclass(ArtifactDigestMismatch, ArtifactDownloadError)


def test_an_empty_response_body_still_fails_verification():
    resolver = DictResolver(sizes={DIGEST: 0})
    with (
        make_source(FakeSession(body=b""), resolver) as source,
        pytest.raises(ArtifactDigestMismatch),
    ):
        source.open(DIGEST)


@pytest.mark.parametrize("bad", ["", "not-a-digest", DIGEST.upper(), "a" * 63, 1234, None])
def test_a_malformed_digest_is_rejected_before_any_request(bad):
    session = FakeSession()
    with make_source(session) as source, pytest.raises(ArtifactDownloadError):
        source.open(bad)
    assert session.calls == []


# --- HTTP and network failures --------------------------------------------


@pytest.mark.parametrize("status", [301, 401, 403, 404, 500, 503])
def test_a_non_200_response_is_an_explicit_download_error(status):
    session = FakeSession(status_code=status)
    with make_source(session) as source, pytest.raises(ArtifactDownloadError) as raised:
        source.open(DIGEST)
    assert str(status) in str(raised.value)


@pytest.mark.parametrize(
    "error",
    [
        ConnectionError("connection refused"),
        TimeoutError("read timed out"),
        OSError("network unreachable"),
        RuntimeError("TLS handshake failed"),
    ],
    ids=["refused", "timeout", "unreachable", "tls"],
)
def test_any_session_failure_becomes_one_download_error(error):
    session = FakeSession(error=error)
    with make_source(session) as source, pytest.raises(ArtifactDownloadError) as raised:
        source.open(DIGEST)
    assert raised.value.__cause__ is error


def test_a_failure_midway_through_the_body_leaves_no_file():
    class ExplodingResponse(FakeResponse):
        def iter_content(self, chunk_size: int):
            yield PAYLOAD[:10]
            raise ConnectionError("connection reset")

    class ExplodingSession(FakeSession):
        def get(self, url, **kwargs):
            self.calls.append((url, kwargs))
            return ExplodingResponse(PAYLOAD)

    with make_source(ExplodingSession()) as source:
        with pytest.raises(ArtifactDownloadError):
            source.open(DIGEST)
        assert list(source._directory().iterdir()) == []


def test_an_unresolvable_digest_propagates_from_the_resolver():
    with make_source(resolver=DictResolver({})) as source, pytest.raises(KeyError):
        source.open(DIGEST)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://host/x.whl", "/root/dev/+f/x.whl"])
def test_a_non_http_origin_url_is_refused(url):
    session = FakeSession()
    resolver = DictResolver({DIGEST: url})
    with make_source(session, resolver) as source, pytest.raises(ArtifactDownloadError):
        source.open(DIGEST)
    assert session.calls == []


def test_an_oversized_body_is_refused():
    session = FakeSession()
    with make_source(session, max_bytes=10) as source:
        with pytest.raises(ArtifactDownloadError) as raised:
            source.open(DIGEST)
        assert "한도" in str(raised.value)
        assert list(source._directory().iterdir()) == []


def test_max_bytes_must_be_positive():
    with pytest.raises(ValueError):
        make_source(max_bytes=0)


# --- lifetime -------------------------------------------------------------


def test_leaving_the_context_removes_every_downloaded_file():
    with make_source() as source:
        path = source.open(DIGEST)
        assert path.exists()
    assert not path.exists()
    assert not path.parent.exists()


def test_close_is_idempotent_and_usable_without_a_context_manager():
    source = make_source()
    path = source.open(DIGEST)
    source.close()
    source.close()
    assert not path.exists()


def test_a_source_can_be_reused_after_close():
    session = FakeSession()
    source = make_source(session)
    source.open(DIGEST)
    source.close()
    assert source.open(DIGEST).read_bytes() == PAYLOAD
    source.close()
    assert len(session.calls) == 2


# --- against a real requests.Session ---------------------------------------


class _Handler(http.server.BaseHTTPRequestHandler):
    payload = PAYLOAD

    def do_GET(self):
        if self.path != "/artifact.whl":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.payload)))
        self.end_headers()
        self.wfile.write(self.payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def local_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_a_real_requests_session_downloads_and_verifies(local_server):
    requests = pytest.importorskip("requests")
    resolver = DictResolver({DIGEST: f"{local_server}/artifact.whl"})
    # An ordinary session with no authentication configured at all.
    with requests.Session() as session, make_source(session, resolver) as source:
        assert source.open(DIGEST).read_bytes() == PAYLOAD


def test_a_real_requests_session_reports_a_404_as_a_download_error(local_server):
    requests = pytest.importorskip("requests")
    resolver = DictResolver({DIGEST: f"{local_server}/absent.whl"})
    with (
        requests.Session() as session,
        make_source(session, resolver) as source,
        pytest.raises(ArtifactDownloadError),
    ):
        source.open(DIGEST)


def test_a_real_requests_session_rejects_a_tampered_body(local_server):
    requests = pytest.importorskip("requests")
    resolver = DictResolver(
        {OTHER_DIGEST: f"{local_server}/artifact.whl"},
        {OTHER_DIGEST: len(PAYLOAD)},
    )
    with (
        requests.Session() as session,
        make_source(session, resolver) as source,
        pytest.raises(ArtifactDigestMismatch),
    ):
        source.open(OTHER_DIGEST)


def test_a_real_requests_session_rejects_redirects_without_caching_the_target():
    requests = pytest.importorskip("requests")
    requested: list[str] = []

    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requested.append(self.path)
            if self.path == "/redirect.whl":
                self.send_response(302)
                self.send_header("Location", "/artifact.whl")
                self.end_headers()
                return
            if self.path == "/artifact.whl":
                self.send_response(200)
                self.send_header("Content-Length", str(len(PAYLOAD)))
                self.end_headers()
                self.wfile.write(PAYLOAD)
                return
            self.send_error(404)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        resolver = DictResolver(
            {DIGEST: f"http://127.0.0.1:{server.server_address[1]}/redirect.whl"}
        )
        with requests.Session() as session, make_source(session, resolver) as source:
            with pytest.raises(ArtifactDownloadError):
                source.open(DIGEST)
            assert source._downloaded == {}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert requested == ["/redirect.whl"]


def test_an_authenticated_real_session_behaves_identically(local_server):
    requests = pytest.importorskip("requests")
    session = requests.Session()
    session.headers["Authorization"] = "Bearer whatever-f5-decides"
    session.auth = ("user", "password")
    resolver = DictResolver({DIGEST: f"{local_server}/artifact.whl"})
    with session, make_source(session, resolver) as source:
        assert source.open(DIGEST).read_bytes() == PAYLOAD
