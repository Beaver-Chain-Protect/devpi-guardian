"""Private upload intake with quarantine-before-discovery ordering."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import PurePath

from devpi_guardian.verdicts.models import ArtifactInput, ReleaseInput, validate_sha256

from .models import ArtifactCandidate
from .quarantine import QuarantineError, QuarantineStore

_CHUNK_SIZE = 1024 * 1024


class PrivateUploadConnector:
    def __init__(
        self,
        *,
        quarantine: QuarantineStore,
        store,
        event: Callable[[str], None] | None = None,
    ) -> None:
        self._quarantine = quarantine
        self._store = store
        self._event = event

    def capture(self, *, stage, project: str, version: str, link) -> None:
        entry = getattr(link, "entry", None)
        opener = getattr(entry, "file_open_read", None)
        if not callable(opener):
            raise QuarantineError("private upload link has no file reader")
        filename = self._filename(link, entry)
        hashes = getattr(entry, "hashes", None)
        if not isinstance(hashes, Mapping) or not isinstance(hashes.get("sha256"), str):
            raise QuarantineError("private upload has no SHA-256 metadata")
        digest = validate_sha256(hashes["sha256"])
        expected_size = getattr(entry, "file_size", None)
        if expected_size is not None and (type(expected_size) is not int or expected_size < 0):
            raise QuarantineError("private upload has invalid size metadata")
        stage_name = self._stage_name(stage)
        origin = f"private-upload://{digest}"
        candidate = ArtifactCandidate(
            stage=stage_name,
            project=project,
            version=version,
            filename=filename,
            sha256=digest,
            origin_url=origin,
            expected_size_bytes=expected_size,
        )
        stream = opener()
        try:
            verified = self._quarantine.persist(candidate, self._chunks(stream))
        finally:
            close = getattr(stream, "close", None)
            if callable(close):
                with suppress(BaseException):
                    close()
        # Publish notification and discovery happen only after the verified
        # descriptor is closed, so no consumer can observe an unpersisted blob.
        with suppress(BaseException):
            verified._stream.close()
        if self._event is not None:
            self._event("quarantine_published")
        now = datetime.now(UTC)
        self._store.discover_artifact(
            ArtifactInput(verified.sha256, verified.size_bytes, now),
            ReleaseInput(
                stage=verified.stage,
                project=verified.project,
                version=verified.version,
                filename=verified.filename,
                sha256=verified.sha256,
                origin_url=origin,
                discovered_at=now,
            ),
        )

    @staticmethod
    def _chunks(stream) -> Iterable[bytes]:
        while True:
            chunk = stream.read(_CHUNK_SIZE)
            if not chunk:
                return
            if not isinstance(chunk, bytes):
                raise QuarantineError("private upload returned non-bytes")
            yield chunk

    @staticmethod
    def _filename(link, entry) -> str:
        value = getattr(link, "basename", None) or getattr(link, "filename", None)
        value = value or getattr(entry, "basename", None)
        if not isinstance(value, str) or not value.strip() or PurePath(value).name != value:
            raise QuarantineError("private upload filename metadata is invalid")
        return value

    @staticmethod
    def _stage_name(stage) -> str:
        if isinstance(stage, str):
            value = stage
        else:
            user = getattr(stage, "user", None)
            index = getattr(stage, "index", None)
            value = f"{user}/{index}" if user and index else ""
        if not value.strip():
            raise QuarantineError("private upload stage metadata is invalid")
        return value
