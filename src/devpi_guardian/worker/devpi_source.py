"""Read artifact bytes through devpi's internal filestore/mirror client."""

from __future__ import annotations

import contextlib
from collections.abc import Iterable

from devpi_guardian.verdicts.models import validate_sha256

from .devpi_paths import DevpiBase, DevpiRouteError, validate_artifact_relpath
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
    except BaseException as first:
        try:
            closed = bool(stream.closed)
        except BaseException as state_error:
            first.add_note(f"artifact stream closed-state check failed: {state_error}")
            closed = False
        if not closed:
            try:
                close()
            except BaseException as second:
                first.add_note(
                    f"artifact stream second close failed: {type(second).__name__}: {second}"
                )
        if primary is None:
            raise DevpiArtifactUnavailable("artifact stream close failed") from first
        if primary is not None:
            primary.add_note(f"artifact stream cleanup failed: {type(first).__name__}: {first}")


class _OwnedResponseContext:
    """Keep each entered HTTP response's cleanup independent and fail-closed."""

    def __init__(self, context) -> None:
        self._context = context
        self.response = None

    def __enter__(self):
        self.response = self._context.__enter__()
        return self.response

    @staticmethod
    def _closed(response) -> bool:
        for name in ("closed", "is_closed"):
            value = getattr(response, name, None)
            if value is not None:
                return bool(value() if callable(value) else value)
        return False

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        try:
            return self._context.__exit__(exc_type, exc_value, traceback)
        except BaseException as first:
            response = self.response
            closed = False
            if response is not None:
                try:
                    closed = self._closed(response)
                except BaseException as state_error:
                    first.add_note(f"response closed-state check failed: {state_error}")
            if response is not None and not closed:
                try:
                    response.close()
                except BaseException as second:
                    first.add_note(
                        f"response second close failed: {type(second).__name__}: {second}"
                    )
            # Even a successful retry does not erase the original context
            # cleanup error; ExitStack must continue to report it.
            raise


class _OwnedResponseStack(contextlib.ExitStack):
    """Wrap every HTTP context entered by devpi's client independently."""

    def enter_context(self, cm):
        return super().enter_context(_OwnedResponseContext(cm))


class DevpiArtifactBytesSource:
    def __init__(self, xom, *, base_url: str) -> None:
        self._xom = xom
        try:
            self._base = DevpiBase.parse(base_url)
        except DevpiRouteError as error:
            raise ValueError("base_url must be a canonical HTTP(S) URL") from error

    def iter_chunks(self, resolved: ResolvedDiscovery) -> Iterable[bytes]:
        validate_sha256(resolved.sha256)
        self._validate_relpath(
            resolved.relpath, resolved.source_stage, resolved.filename, resolved.sha256
        )
        try:
            expected_origin = self._base.origin_for(resolved.relpath)
        except DevpiRouteError as error:
            raise DevpiArtifactUnavailable("resolved artifact route is not canonical") from error
        if resolved.origin_url != expected_origin:
            raise DevpiArtifactUnavailable("resolved artifact origin is not canonical")

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
                self._validate_relpath(
                    entry_relpath, resolved.source_stage, resolved.filename, resolved.sha256
                )
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
        stack = _OwnedResponseStack()
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
    def _validate_relpath(
        relpath: str, source_stage: str, filename: str, sha256: str
    ) -> tuple[str, ...]:
        try:
            return validate_artifact_relpath(
                relpath, stage=source_stage, filename=filename, sha256=sha256
            )
        except DevpiRouteError as error:
            raise DevpiArtifactUnavailable(
                "devpi path metadata does not match discovery"
            ) from error

    def _validate_upstream_url(self, upstream: str, resolved: ResolvedDiscovery) -> None:
        if not isinstance(upstream, str) or any(ord(char) < 0x20 for char in upstream):
            raise DevpiArtifactUnavailable("upstream URL is not valid HTTP(S)")
        try:
            origin = DevpiBase.endpoint_for_url(upstream)
        except DevpiRouteError as error:
            raise DevpiArtifactUnavailable("upstream URL is not valid HTTP(S)") from error
        if origin == self._base.endpoint:
            raise DevpiArtifactUnavailable("upstream URL targets the configured devpi origin")
