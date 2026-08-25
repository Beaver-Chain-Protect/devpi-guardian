from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import replace
from io import BytesIO
from types import SimpleNamespace

import pytest

from devpi_guardian.worker.devpi_source import (
    DevpiArtifactBytesSource,
    DevpiArtifactUnavailable,
    _OwnedResponseContext,
)
from devpi_guardian.worker.discovery_consumer import ResolvedDiscovery


class Keyfs:
    @contextmanager
    def read_transaction(self):
        yield


class Entry:
    user, index = "root", "pypi"

    def __init__(self, payload, sha256, url="https://upstream.invalid/a"):
        self.payload, self.hashes, self.url = payload, {"sha256": sha256}, url
        self.relpath = f"root/pypi/+f/{sha256[:3]}/{sha256[3:16]}/demo-1.0.whl"

    def file_exists(self):
        return self.payload is not None

    def file_open_read(self):
        return BytesIO(self.payload)


class Response:
    status_code = 200

    def __init__(self, payload):
        self.payload, self.close_calls = payload, 0

    def iter_raw(self, _size):
        yield self.payload

    def close(self):
        self.close_calls += 1

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False


class Http:
    def __init__(self, payload):
        self.payload, self.calls = payload, []

    def stream(self, method, url, *, allow_redirects):
        self.calls.append((method, url, allow_redirects))
        response = Response(self.payload)
        self.response = response
        return response


def resolved(sha256="a" * 64):
    return ResolvedDiscovery(
        "company/guardian",
        "root/pypi",
        "demo",
        "1.0",
        "demo-1.0.whl",
        sha256,
        f"root/pypi/+f/{sha256[:3]}/{sha256[3:16]}/demo-1.0.whl",
        f"https://devpi.invalid:443/root/pypi/+f/{sha256[:3]}/{sha256[3:16]}/demo-1.0.whl",
    )


def xom_for(entry, payload=b"upstream"):
    http = Http(payload)
    stage = SimpleNamespace(http=http)
    return SimpleNamespace(
        keyfs=Keyfs(),
        filestore=SimpleNamespace(get_file_entry=lambda _: entry),
        model=SimpleNamespace(getstage=lambda *_: stage),
    ), http


def source(xom, base_url="https://devpi.invalid/"):
    return DevpiArtifactBytesSource(xom, base_url=base_url)


def test_source_requires_canonical_base_url():
    xom, _ = xom_for(Entry(b"cached", "a" * 64))
    for base_url in (
        "http://:80/",
        "https://devpi.invalid:0/",
        "https://devpi.invalid:65536/",
        "https://devpi.invalid./",
        "https://devpi.invalid/%2e/",
    ):
        with pytest.raises(ValueError):
            DevpiArtifactBytesSource(xom, base_url=base_url)


def test_cached_source_closes_file_and_does_not_use_http():
    item = resolved()
    xom, http = xom_for(Entry(b"cached", item.sha256))
    assert b"".join(source(xom).iter_chunks(item)) == b"cached"
    assert http.calls == []


def test_cached_source_retries_a_failed_close():
    item = resolved()

    class RetryClose(BytesIO):
        def __init__(self, payload):
            super().__init__(payload)
            self.attempts = 0

        def close(self):
            self.attempts += 1
            if self.attempts == 1:
                raise OSError("first close failed")
            super().close()

    stream = RetryClose(b"cached")
    entry = Entry(b"cached", item.sha256)
    entry.file_open_read = lambda: stream
    xom, _ = xom_for(entry)
    with pytest.raises(DevpiArtifactUnavailable, match="artifact stream close failed"):
        b"".join(source(xom).iter_chunks(item))
    assert stream.attempts == 2 and stream.closed


def test_uncached_source_uses_internal_stage_client():
    item = resolved()
    xom, http = xom_for(Entry(None, item.sha256), b"upstream")
    assert b"".join(source(xom).iter_chunks(item)) == b"upstream"
    assert http.calls == [("GET", "https://upstream.invalid/a", False)]
    assert http.response.close_calls == 1


def test_source_rejects_metadata_mismatch():
    item = resolved()
    xom, _ = xom_for(Entry(b"bytes", "b" * 64))
    with pytest.raises(DevpiArtifactUnavailable):
        tuple(source(xom).iter_chunks(item))


def test_source_rejects_same_origin_upstream_even_without_redirects():
    item = resolved()
    xom, _ = xom_for(Entry(None, item.sha256, "https://devpi.invalid/root/pypi/+e/a"))
    with pytest.raises(DevpiArtifactUnavailable):
        tuple(source(xom).iter_chunks(item))


def test_source_rejects_mutated_resolved_origin_before_any_get():
    item = resolved()
    mutated = replace(item, origin_url="https://external.invalid/not-the-route")
    xom, http = xom_for(Entry(b"cached", item.sha256))
    with pytest.raises(DevpiArtifactUnavailable, match="origin"):
        tuple(source(xom).iter_chunks(mutated))
    assert http.calls == []


def test_source_trust_anchor_handles_ipv6_aliases_and_default_ports():
    item = replace(
        resolved(),
        origin_url="https://[::1]:443/root/pypi/+f/aaa/aaaaaaaaaaaaa/demo-1.0.whl",
    )
    xom, http = xom_for(Entry(None, item.sha256, "https://[0:0:0:0:0:0:0:1]/a"))
    with pytest.raises(DevpiArtifactUnavailable, match="configured devpi origin"):
        tuple(source(xom, "https://[0:0:0:0:0:0:0:1]/").iter_chunks(item))
    assert http.calls == []


def test_source_supports_a_mounted_trust_anchor():
    item = resolved()
    mounted = replace(
        item,
        origin_url="https://devpi.invalid:443/devpi/" + item.relpath,
    )
    xom, _ = xom_for(Entry(b"cached", item.sha256))
    assert b"".join(source(xom, "https://devpi.invalid/devpi").iter_chunks(mounted)) == b"cached"


def test_source_accepts_exact_plus_e_route():
    item = resolved()
    relpath = f"root/pypi/+e/abc/{item.filename}"
    item = replace(
        item,
        relpath=relpath,
        origin_url=f"https://devpi.invalid:443/{relpath}",
    )
    entry = Entry(b"cached", item.sha256)
    entry.relpath = relpath
    xom, _ = xom_for(entry)
    assert b"".join(source(xom).iter_chunks(item)) == b"cached"


def test_source_rejects_noncanonical_raw_relpaths():
    item = resolved()
    for bad in (
        "root//pypi/+f/aaa/bbbbbbbbbbbbb/demo-1.0.whl",
        "/root/pypi/+f/aaa/bbbbbbbbbbbbb/demo-1.0.whl",
        "root/pypi/./+f/aaa/bbbbbbbbbbbbb/demo-1.0.whl",
        "root/pypi/%2e%2e/+f/aaa/bbbbbbbbbbbbb/demo-1.0.whl",
        "root/pypi/+f/aaa/bbbbbbbbbbbbb/demo-1.0.whl\\demo-1.0.whl",
    ):
        bad_item = replace(item, relpath=bad)
        xom, _ = xom_for(Entry(b"cached", item.sha256))
        with pytest.raises(DevpiArtifactUnavailable):
            tuple(source(xom).iter_chunks(bad_item))


def test_source_snapshots_hash_mapping_once():
    item = resolved()

    class ChangingEntry(Entry):
        def __init__(self):
            super().__init__(b"cached", item.sha256)
            self.hash_calls = 0

        @property
        def hashes(self):
            self.hash_calls += 1
            return {"sha256": item.sha256}

        @hashes.setter
        def hashes(self, value):
            self._hashes = value

    entry = ChangingEntry()
    xom, _ = xom_for(entry)
    assert b"".join(source(xom).iter_chunks(item)) == b"cached"
    assert entry.hash_calls == 1


def test_exitstack_cleanup_error_is_surfaced_on_success():
    item = resolved()

    class FailingResponse(Response):
        def close(self):
            self.close_calls += 1
            raise OSError("response close failed")

    class FailingHttp(Http):
        def stream(self, method, url, *, allow_redirects):
            response = FailingResponse(self.payload)
            self.response = response
            return response

    http = FailingHttp(b"upstream")
    stage = SimpleNamespace(http=http)
    xom = SimpleNamespace(
        keyfs=Keyfs(),
        filestore=SimpleNamespace(
            get_file_entry=lambda _: Entry(None, item.sha256, "https://upstream.invalid/a")
        ),
        model=SimpleNamespace(getstage=lambda *_: stage),
    )
    with pytest.raises(DevpiArtifactUnavailable, match="response close failed"):
        tuple(source(xom).iter_chunks(item))
    assert http.response.close_calls == 2


def test_exitstack_cleanup_error_does_not_mask_body_error():
    item = resolved()

    class BrokenResponse(Response):
        def iter_raw(self, _size):
            raise ValueError("body failed")

        def close(self):
            self.close_calls += 1
            raise OSError("response close failed")

    class BrokenHttp(Http):
        def stream(self, method, url, *, allow_redirects):
            response = BrokenResponse(self.payload)
            self.response = response
            return response

    http = BrokenHttp(b"unused")
    stage = SimpleNamespace(http=http)
    xom = SimpleNamespace(
        keyfs=Keyfs(),
        filestore=SimpleNamespace(
            get_file_entry=lambda _: Entry(None, item.sha256, "https://upstream.invalid/a")
        ),
        model=SimpleNamespace(getstage=lambda *_: stage),
    )
    with pytest.raises(ValueError, match="body failed") as raised:
        tuple(source(xom).iter_chunks(item))
    assert any("upstream response cleanup failed" in note for note in raised.value.__notes__)


def test_exitstack_retries_response_close_once_when_callback_leaves_open():
    item = resolved()

    class RetryResponse(Response):
        def __init__(self, payload):
            super().__init__(payload)
            self.closed = False

        def close(self):
            self.close_calls += 1
            if self.close_calls == 1:
                raise OSError("first response close failed")
            self.closed = True

    class RetryHttp(Http):
        def stream(self, method, url, *, allow_redirects):
            response = RetryResponse(self.payload)
            self.response = response
            return response

    http = RetryHttp(b"upstream")
    stage = SimpleNamespace(http=http)
    xom = SimpleNamespace(
        keyfs=Keyfs(),
        filestore=SimpleNamespace(
            get_file_entry=lambda _: Entry(None, item.sha256, "https://upstream.invalid/a")
        ),
        model=SimpleNamespace(getstage=lambda *_: stage),
    )
    with pytest.raises(DevpiArtifactUnavailable, match="response close failed"):
        b"".join(source(xom).iter_chunks(item))
    assert http.response.close_calls == 2 and http.response.closed


def test_exitstack_unrelated_cleanup_error_does_not_reclose_response():
    response = Response(b"payload")
    unrelated = RuntimeError("unrelated cleanup failed")
    stack = ExitStack()
    stack.enter_context(_OwnedResponseContext(response))
    stack.callback(lambda: (_ for _ in ()).throw(unrelated))
    with pytest.raises(RuntimeError, match="unrelated cleanup failed"):
        stack.close()
    assert response.close_calls == 1


def test_exitstack_discharges_each_response_context_independently():
    first = Response(b"first")
    second = Response(b"second")

    class FailingContext:
        def __init__(self, response):
            self.response = response

        def __enter__(self):
            return self.response

        def __exit__(self, exc_type, exc_value, traceback):
            self.response.close_calls += 1
            raise OSError("first context cleanup failed")

    stack = ExitStack()
    stack.enter_context(_OwnedResponseContext(FailingContext(first)))
    stack.enter_context(_OwnedResponseContext(second))
    with pytest.raises(OSError, match="first context cleanup failed"):
        stack.close()
    assert first.close_calls == 2
    assert second.close_calls == 1


def test_cached_descriptor_is_streamed_after_transaction_exit():
    item = resolved()
    events = []

    class Stream(BytesIO):
        def read(self, size=-1):
            assert events == ["enter", "exit"]
            return super().read(size)

    class TxnKeyfs:
        @contextmanager
        def read_transaction(self):
            events.append("enter")
            yield
            events.append("exit")

    class TxnEntry(Entry):
        def file_open_read(self):
            return Stream(self.payload)

    http = Http(b"unused")
    stage = SimpleNamespace(http=http)
    xom = SimpleNamespace(
        keyfs=TxnKeyfs(),
        filestore=SimpleNamespace(get_file_entry=lambda _: TxnEntry(b"cached", item.sha256)),
        model=SimpleNamespace(getstage=lambda *_: stage),
    )
    assert b"".join(source(xom).iter_chunks(item)) == b"cached"
