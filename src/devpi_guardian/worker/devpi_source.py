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


def _close_with_primary(stream, primary: BaseException | None) -> None:
    close = getattr(stream, "close", None)
    if not callable(close):
        return
    try:
        close()
    except BaseException as error:
        if primary is None:
            raise DevpiArtifactUnavailable("artifact stream close failed") from error
        primary.add_note(f"artifact stream cleanup failed: {type(error).__name__}: {error}")


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

        stream = None
        upstream = None
        stage = None
        try:
            with self._xom.keyfs.read_transaction():
                entry = self._xom.filestore.get_file_entry(resolved.relpath)
                if entry is None:
                    raise DevpiArtifactUnavailable("devpi file entry is missing")
                entry_user = entry.user
                entry_index = entry.index
                hashes = entry.hashes
                advertised = hashes.get("sha256")
                if f"{entry_user}/{entry_index}" != resolved.source_stage:
                    raise DevpiArtifactUnavailable("devpi file entry belongs to another stage")
                if advertised != resolved.sha256:
                    raise DevpiArtifactUnavailable("devpi file entry SHA-256 does not match")
                exists = entry.file_exists()
                if exists:
                    stream = entry.file_open_read()
                else:
                    upstream = entry.url
                    stage = self._xom.model.getstage(entry_user, entry_index)
        except BaseException as primary:
            if stream is not None:
                _close_with_primary(stream, primary)
            raise

        if stream is not None:
            try:
                while chunk := stream.read(_CHUNK_SIZE):
                    if not isinstance(chunk, bytes):
                        raise DevpiArtifactUnavailable("devpi filestore returned non-bytes")
                    yield chunk
            except BaseException as primary:
                _close_with_primary(stream, primary)
                raise
            else:
                _close_with_primary(stream, None)
            return

        if not isinstance(upstream, str) or not upstream:
            raise DevpiArtifactUnavailable("uncached devpi file has no upstream URL")
        if stage is None:
            raise DevpiArtifactUnavailable("source stage no longer exists")
        with contextlib.ExitStack() as stack:
            response = stage.http.stream(stack, "GET", upstream, allow_redirects=False)
            try:
                status = getattr(response, "status_code", None)
                if status != 200:
                    raise DevpiArtifactUnavailable(f"upstream returned HTTP {status}")
                for chunk in response.iter_raw(_CHUNK_SIZE):
                    if chunk:
                        if not isinstance(chunk, bytes):
                            raise DevpiArtifactUnavailable("upstream returned non-bytes")
                        yield chunk
            except BaseException as primary:
                _close_with_primary(response, primary)
                raise
            else:
                _close_with_primary(response, None)
