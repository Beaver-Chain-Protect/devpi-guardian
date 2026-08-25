from __future__ import annotations

from contextlib import contextmanager
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

    def file_exists(self):
        return self.payload is not None

    def file_open_read(self):
        return BytesIO(self.payload)


class Response:
    status_code = 200

    def __init__(self, payload):
        self.payload = payload

    def iter_raw(self, _size):
        yield self.payload


class Http:
    def __init__(self, payload):
        self.payload, self.calls = payload, []

    def stream(self, stack, method, url, *, allow_redirects):
        self.calls.append((method, url, allow_redirects))
        return Response(self.payload)


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
    assert http.calls == [("GET", "https://upstream.invalid/a", True)]


def test_source_rejects_metadata_mismatch():
    item = resolved()
    xom, _ = xom_for(Entry(b"bytes", "b" * 64))
    with pytest.raises(DevpiArtifactUnavailable):
        tuple(DevpiArtifactBytesSource(xom).iter_chunks(item))
