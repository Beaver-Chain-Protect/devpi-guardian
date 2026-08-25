from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from io import BytesIO
from types import SimpleNamespace

import pytest

from devpi_guardian.worker.devpi_source import DevpiArtifactBytesSource, DevpiArtifactUnavailable
from devpi_guardian.worker.discovery_consumer import ResolvedDiscovery


class Keyfs:
    @contextmanager
    def read_transaction(self):
        yield


class Entry:
    user, index = "root", "pypi"

    def __init__(self, payload, sha256, url="https://upstream.invalid/a"):
        self.payload, self.hashes, self.url = payload, {"sha256": sha256}, url
        self.relpath = "root/pypi/+f/abc/demo-1.0.whl"

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


class Http:
    def __init__(self, payload):
        self.payload, self.calls = payload, []

    def stream(self, stack, method, url, *, allow_redirects):
        self.calls.append((method, url, allow_redirects))
        response = Response(self.payload)
        stack.callback(response.close)
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
        "root/pypi/+f/abc/demo-1.0.whl",
        "https://devpi.invalid/root/pypi/+f/abc/demo-1.0.whl",
    )


def xom_for(entry, payload=b"upstream"):
    http = Http(payload)
    stage = SimpleNamespace(http=http)
    return SimpleNamespace(
        keyfs=Keyfs(),
        filestore=SimpleNamespace(get_file_entry=lambda _: entry),
        model=SimpleNamespace(getstage=lambda *_: stage),
    ), http


def test_cached_source_closes_file_and_does_not_use_http():
    item = resolved()
    xom, http = xom_for(Entry(b"cached", item.sha256))
    assert b"".join(DevpiArtifactBytesSource(xom).iter_chunks(item)) == b"cached"
    assert http.calls == []


def test_uncached_source_uses_internal_stage_client():
    item = resolved()
    xom, http = xom_for(Entry(None, item.sha256), b"upstream")
    assert b"".join(DevpiArtifactBytesSource(xom).iter_chunks(item)) == b"upstream"
    assert http.calls == [("GET", "https://upstream.invalid/a", False)]
    assert http.response.close_calls == 1


def test_source_rejects_metadata_mismatch():
    item = resolved()
    xom, _ = xom_for(Entry(b"bytes", "b" * 64))
    with pytest.raises(DevpiArtifactUnavailable):
        tuple(DevpiArtifactBytesSource(xom).iter_chunks(item))


def test_source_rejects_same_origin_upstream_even_without_redirects():
    item = resolved()
    xom, _ = xom_for(Entry(None, item.sha256, "https://devpi.invalid/root/pypi/+e/a"))
    with pytest.raises(DevpiArtifactUnavailable):
        tuple(DevpiArtifactBytesSource(xom).iter_chunks(item))


def test_source_rejects_noncanonical_raw_relpaths():
    item = resolved()
    for bad in (
        "root//pypi/+f/abc/demo-1.0.whl",
        "/root/pypi/+f/abc/demo-1.0.whl",
        "root/pypi/./+f/abc/demo-1.0.whl",
        "root/pypi/%2e%2e/+f/abc/demo-1.0.whl",
        "root/pypi/+f/abc\\demo-1.0.whl",
    ):
        bad_item = replace(item, relpath=bad)
        xom, _ = xom_for(Entry(b"cached", item.sha256))
        with pytest.raises(DevpiArtifactUnavailable):
            tuple(DevpiArtifactBytesSource(xom).iter_chunks(bad_item))


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
    assert b"".join(DevpiArtifactBytesSource(xom).iter_chunks(item)) == b"cached"
    assert entry.hash_calls == 1


def test_exitstack_cleanup_error_is_surfaced_on_success():
    item = resolved()

    class FailingResponse(Response):
        def close(self):
            self.close_calls += 1
            raise OSError("response close failed")

    class FailingHttp(Http):
        def stream(self, stack, method, url, *, allow_redirects):
            response = FailingResponse(self.payload)
            stack.callback(response.close)
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
        tuple(DevpiArtifactBytesSource(xom).iter_chunks(item))
    assert http.response.close_calls == 1


def test_exitstack_cleanup_error_does_not_mask_body_error():
    item = resolved()

    class BrokenResponse(Response):
        def iter_raw(self, _size):
            raise ValueError("body failed")

        def close(self):
            self.close_calls += 1
            raise OSError("response close failed")

    class BrokenHttp(Http):
        def stream(self, stack, method, url, *, allow_redirects):
            response = BrokenResponse(self.payload)
            stack.callback(response.close)
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
        tuple(DevpiArtifactBytesSource(xom).iter_chunks(item))
    assert any("upstream response cleanup failed" in note for note in raised.value.__notes__)


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
    assert b"".join(DevpiArtifactBytesSource(xom).iter_chunks(item)) == b"cached"
