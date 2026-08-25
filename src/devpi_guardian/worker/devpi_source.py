"""Read artifact bytes through devpi's internal filestore/mirror client."""

from __future__ import annotations

import contextlib
from collections.abc import Iterable
from urllib.parse import urlsplit

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
        self._validate_relpath(resolved.relpath, resolved.source_stage, resolved.filename)

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
                hashes = dict(entry.hashes)
                advertised = hashes.get("sha256")
                if (
                    not isinstance(entry_user, str)
                    or not isinstance(entry_index, str)
                    or f"{entry_user}/{entry_index}" != resolved.source_stage
                ):
                    raise DevpiArtifactUnavailable("devpi file entry belongs to another stage")
                if advertised != resolved.sha256:
                    raise DevpiArtifactUnavailable("devpi file entry SHA-256 does not match")
                entry_relpath = entry.relpath
                self._validate_relpath(entry_relpath, resolved.source_stage, resolved.filename)
                if entry_relpath != resolved.relpath:
                    raise DevpiArtifactUnavailable("devpi file entry relpath does not match")
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
        self._validate_upstream_url(upstream, resolved)
        stack = contextlib.ExitStack()
        try:
            response = stage.http.stream(stack, "GET", upstream, allow_redirects=False)
            status = getattr(response, "status_code", None)
            if status != 200:
                raise DevpiArtifactUnavailable(f"upstream returned HTTP {status}")
            for chunk in response.iter_raw(_CHUNK_SIZE):
                if chunk:
                    if not isinstance(chunk, bytes):
                        raise DevpiArtifactUnavailable("upstream returned non-bytes")
                    yield chunk
        except BaseException as primary:
            try:
                stack.close()
            except BaseException as cleanup:
                primary.add_note(
                    f"upstream response cleanup failed: {type(cleanup).__name__}: {cleanup}"
                )
            raise
        else:
            try:
                stack.close()
            except BaseException as cleanup:
                raise DevpiArtifactUnavailable("upstream response close failed") from cleanup

    @staticmethod
    def _validate_relpath(relpath: str, source_stage: str, filename: str) -> list[str]:
        if (
            not isinstance(relpath, str)
            or not relpath
            or relpath.startswith("/")
            or "//" in relpath
            or "%" in relpath
            or "\\" in relpath
            or "?" in relpath
            or "#" in relpath
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in relpath)
        ):
            raise DevpiArtifactUnavailable("invalid devpi file path")
        parts = relpath.split("/")
        if (
            any(part in ("", ".", "..") for part in parts)
            or len(parts) < 5
            or "/".join(parts[:2]) != source_stage
            or parts[2] not in ("+f", "+e")
            or parts[-1] != filename
        ):
            raise DevpiArtifactUnavailable("devpi path metadata does not match discovery")
        return parts

    @staticmethod
    def _validate_upstream_url(upstream: str, resolved: ResolvedDiscovery) -> None:
        if not isinstance(upstream, str) or any(ord(char) < 0x20 for char in upstream):
            raise DevpiArtifactUnavailable("upstream URL is not valid HTTP(S)")
        try:
            parsed = urlsplit(upstream)
            port = parsed.port
        except ValueError as error:
            raise DevpiArtifactUnavailable("upstream URL is not valid HTTP(S)") from error
        if (
            parsed.scheme.lower() not in ("http", "https")
            or not parsed.hostname
            or not parsed.hostname.isascii()
            or any(char.isspace() or char in "/?#\\" for char in parsed.hostname)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or "%" in parsed.netloc
            or "%" in parsed.path
            or "\\" in parsed.path
        ):
            raise DevpiArtifactUnavailable("upstream URL is not valid HTTP(S)")
        resolved_url = urlsplit(resolved.origin_url)
        origin = (
            parsed.scheme.lower(),
            parsed.hostname.lower(),
            port if port is not None else (443 if parsed.scheme.lower() == "https" else 80),
        )
        resolved_port = resolved_url.port
        resolved_origin = (
            resolved_url.scheme.lower(),
            resolved_url.hostname.lower() if resolved_url.hostname else None,
            resolved_port
            if resolved_port is not None
            else (443 if resolved_url.scheme.lower() == "https" else 80),
        )
        if origin == resolved_origin:
            raise DevpiArtifactUnavailable("upstream URL targets the configured devpi origin")
