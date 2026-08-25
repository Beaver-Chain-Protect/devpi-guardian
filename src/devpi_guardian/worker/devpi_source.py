"""Read artifact bytes through devpi's internal filestore/mirror client."""

from __future__ import annotations

import contextlib
from collections.abc import Iterable
from pathlib import PurePosixPath

from devpi_guardian.verdicts.models import validate_sha256

from .discovery_consumer import ResolvedDiscovery

_CHUNK_SIZE = 1024 * 1024


class DevpiArtifactUnavailable(RuntimeError):
    pass


class DevpiArtifactBytesSource:
    def __init__(self, xom) -> None:
        self._xom = xom

    def iter_chunks(self, resolved: ResolvedDiscovery) -> Iterable[bytes]:
        validate_sha256(resolved.sha256)
        parts = PurePosixPath(resolved.relpath).parts
        if any(part in ("", ".", "..") for part in parts) or len(parts) < 5:
            raise DevpiArtifactUnavailable("invalid devpi file path")
        if "/".join(parts[:2]) != resolved.source_stage or parts[-1] != resolved.filename:
            raise DevpiArtifactUnavailable("devpi path metadata does not match discovery")
        with self._xom.keyfs.read_transaction():
            entry = self._xom.filestore.get_file_entry(resolved.relpath)
            if entry is None:
                raise DevpiArtifactUnavailable("devpi file entry is missing")
            if f"{entry.user}/{entry.index}" != resolved.source_stage:
                raise DevpiArtifactUnavailable("devpi file entry belongs to another stage")
            advertised = getattr(entry, "hashes", {}).get("sha256")
            if advertised != resolved.sha256:
                raise DevpiArtifactUnavailable("devpi file entry SHA-256 does not match")
            if entry.file_exists():
                stream = entry.file_open_read()
                try:
                    while chunk := stream.read(_CHUNK_SIZE):
                        if not isinstance(chunk, bytes):
                            raise DevpiArtifactUnavailable("devpi filestore returned non-bytes")
                        yield chunk
                finally:
                    close = getattr(stream, "close", None)
                    if callable(close):
                        close()
                return
            upstream_url = getattr(entry, "url", None)
            if not isinstance(upstream_url, str) or not upstream_url:
                raise DevpiArtifactUnavailable("uncached devpi file has no upstream URL")
            stage = self._xom.model.getstage(entry.user, entry.index)
            if stage is None:
                raise DevpiArtifactUnavailable("source stage no longer exists")
            with contextlib.ExitStack() as stack:
                response = stage.http.stream(stack, "GET", upstream_url, allow_redirects=True)
                try:
                    if getattr(response, "status_code", None) != 200:
                        raise DevpiArtifactUnavailable(
                            f"upstream returned HTTP {getattr(response, 'status_code', None)}"
                        )
                    for chunk in response.iter_raw(_CHUNK_SIZE):
                        if chunk:
                            if not isinstance(chunk, bytes):
                                raise DevpiArtifactUnavailable("upstream returned non-bytes")
                            yield chunk
                finally:
                    close = getattr(response, "close", None)
                    if callable(close):
                        close()
