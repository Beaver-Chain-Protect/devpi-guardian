from __future__ import annotations

from contextlib import contextmanager
from io import BytesIO
from types import SimpleNamespace

import pytest

from devpi_guardian.worker.devpi_source import (
    DevpiArtifactBytesSource,
    DevpiArtifactUnavailable,
)
from devpi_guardian.worker.discovery_consumer import ResolvedDiscovery


class Keyfs:
    @contextmanager
    def read_transaction(self):
        yield


class Entry:
    user = "root"
    index = "pypi"

    def __init__(self, payload: bytes | None, sha256: str, url="https://pypi/artifact"):
        self.payload = payload
        self.hashes = {"sha256": sha256}
        self.url = url

    def file_exists(self):
        return self.payload is not None

    def file_open_read(self):
        assert self.payload is not None
        return BytesIO(self.payload)


class Response:
    status_code = 200

    def __init__(self, payload):
        self.payload = payload

    def iter_raw(self, _chunk_size):
        yield self.payload


class Http:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def stream(self, stack, method, url, *, allow_redirects):
        self.calls.append((method, url, allow_redirects))
        return Response(self.payload)


def resolved(sha256="a" * 64):
    return ResolvedDiscovery(
        observer_stage="company/guardian",
        source_stage="root/pypi",
        project="demo",
        version="1.0",
        filename="demo-1.0.whl",
        sha256=sha256,
        relpath="root/pypi/+f/abc/demo-1.0.whl",
        origin_url="https://devpi/root/pypi/+f/abc/demo-1.0.whl",
    )


def xom_for(entry, *, upstream_payload=b"upstream"):
    http = Http(upstream_payload)
    stage = SimpleNamespace(http=http)
    xom = SimpleNamespace(
        keyfs=Keyfs(),
        filestore=SimpleNamespace(get_file_entry=lambda relpath: entry),
        model=SimpleNamespace(getstage=lambda user, index: stage),
    )
    return xom, http


def test_source_reads_cached_devpi_file_without_public_http() -> None:
    payload = b"cached bytes"
    item = resolved()
    xom, http = xom_for(Entry(payload, item.sha256))

    chunks = tuple(DevpiArtifactBytesSource(xom).iter_chunks(item))

    assert b"".join(chunks) == payload
    assert http.calls == []


def test_source_uses_devpi_mirror_client_for_uncached_file() -> None:
    payload = b"upstream bytes"
    item = resolved()
    xom, http = xom_for(Entry(None, item.sha256), upstream_payload=payload)

    chunks = tuple(DevpiArtifactBytesSource(xom).iter_chunks(item))

    assert b"".join(chunks) == payload
    assert http.calls == [("GET", "https://pypi/artifact", True)]


def test_source_rejects_entry_with_different_advertised_hash() -> None:
    item = resolved()
    xom, _ = xom_for(Entry(b"bytes", "b" * 64))

    with pytest.raises(DevpiArtifactUnavailable):
        tuple(DevpiArtifactBytesSource(xom).iter_chunks(item))
