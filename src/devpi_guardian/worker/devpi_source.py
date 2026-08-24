"""Artifact byte access through devpi's filestore and mirror client."""

from __future__ import annotations

import contextlib
from collections.abc import Iterable

from .discovery_consumer import ResolvedDiscovery

_CHUNK_SIZE = 1024 * 1024


class DevpiArtifactUnavailable(RuntimeError):
    """The source-stage file metadata or bytes are temporarily unavailable."""


class DevpiArtifactBytesSource:
    """Read devpi-managed bytes without requesting the protected ``/+f/`` URL.

    Cached files are read from the internal filestore.  Mirror misses use the
    source stage's configured HTTP client and the upstream URL already stored
    by devpi.  No worker bypass header or public-download exception is used.
    """

    def __init__(self, xom) -> None:
        self._xom = xom

    def iter_chunks(self, resolved: ResolvedDiscovery) -> Iterable[bytes]:
        with self._xom.keyfs.read_transaction():
            entry = self._xom.filestore.get_file_entry(resolved.relpath)
            if entry is None:
                raise DevpiArtifactUnavailable("devpi file entry is missing")
            if f"{entry.user}/{entry.index}" != resolved.source_stage:
                raise DevpiArtifactUnavailable("devpi file entry belongs to another stage")
            advertised = entry.hashes.get("sha256")
            if advertised != resolved.sha256:
                raise DevpiArtifactUnavailable("devpi file entry SHA-256 does not match")

            if entry.file_exists():
                with entry.file_open_read() as stream:
                    while chunk := stream.read(_CHUNK_SIZE):
                        yield chunk
                return

            upstream_url = entry.url
            if not upstream_url:
                raise DevpiArtifactUnavailable("uncached devpi file has no upstream URL")
            stage = self._xom.model.getstage(entry.user, entry.index)
            if stage is None:
                raise DevpiArtifactUnavailable("source stage no longer exists")
            with contextlib.ExitStack() as stack:
                response = stage.http.stream(
                    stack,
                    "GET",
                    upstream_url,
                    allow_redirects=True,
                )
                if response.status_code != 200:
                    raise DevpiArtifactUnavailable(f"upstream returned HTTP {response.status_code}")
                for chunk in response.iter_raw(_CHUNK_SIZE):
                    if chunk:
                        yield chunk
