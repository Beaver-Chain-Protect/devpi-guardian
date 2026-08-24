"""Content-addressed storage for downloaded but unapproved artifacts."""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path

from .models import ArtifactCandidate, VerifiedArtifact


class QuarantineError(RuntimeError):
    pass


class ArtifactHashMismatch(QuarantineError):
    pass


class ArtifactSizeMismatch(QuarantineError):
    pass


class ArtifactTooLarge(QuarantineError):
    pass


def _safe_suffix(filename: str) -> str:
    lowered = filename.lower()
    for suffix in (".tar.gz", ".whl", ".zip", ".tgz", ".tar"):
        if lowered.endswith(suffix):
            return suffix
    raise QuarantineError("unsupported artifact format")


class QuarantineStore:
    def __init__(self, root: Path, *, max_size_bytes: int) -> None:
        if max_size_bytes <= 0:
            raise ValueError("max_size_bytes must be positive")
        self._root = Path(root)
        self._max_size_bytes = max_size_bytes

    def persist(
        self,
        candidate: ArtifactCandidate,
        chunks: Iterable[bytes],
    ) -> VerifiedArtifact:
        """Stream untrusted bytes, verify identity, and atomically publish locally."""

        incoming = self._root / "incoming"
        incoming.mkdir(parents=True, exist_ok=True)
        suffix = _safe_suffix(candidate.filename)
        final = self._root / "sha256" / candidate.sha256[:2] / f"{candidate.sha256}{suffix}"
        digest = hashlib.sha256()
        size = 0
        temporary: Path | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(prefix="artifact-", dir=incoming)
            temporary = Path(temporary_name)
            with os.fdopen(descriptor, "wb") as stream:
                for chunk in chunks:
                    if not isinstance(chunk, bytes):
                        raise QuarantineError("download chunks must be bytes")
                    size += len(chunk)
                    if size > self._max_size_bytes:
                        raise ArtifactTooLarge("artifact exceeds configured size limit")
                    digest.update(chunk)
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())

            if digest.hexdigest() != candidate.sha256:
                raise ArtifactHashMismatch("downloaded SHA-256 does not match advertised SHA-256")
            expected = candidate.expected_size_bytes
            if expected is not None and size != expected:
                raise ArtifactSizeMismatch("downloaded size does not match advertised size")

            final.parent.mkdir(parents=True, exist_ok=True)
            if final.exists():
                if self._verified_existing(final, candidate.sha256, size):
                    temporary.unlink()
                else:
                    raise QuarantineError("existing quarantine file failed identity verification")
            else:
                os.replace(temporary, final)
            temporary = None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

        return VerifiedArtifact(
            stage=candidate.stage,
            project=candidate.project,
            version=candidate.version,
            filename=candidate.filename,
            sha256=candidate.sha256,
            size_bytes=size,
            local_path=final,
        )

    def get_verified(self, candidate: ArtifactCandidate) -> VerifiedArtifact | None:
        """Return an already verified blob without downloading it again."""

        suffix = _safe_suffix(candidate.filename)
        path = self._root / "sha256" / candidate.sha256[:2] / f"{candidate.sha256}{suffix}"
        if not path.is_file():
            return None
        size = path.stat().st_size
        expected = candidate.expected_size_bytes
        if expected is not None and size != expected:
            raise QuarantineError("existing quarantine file has an unexpected size")
        if not self._verified_existing(path, candidate.sha256, size):
            raise QuarantineError("existing quarantine file failed identity verification")
        return VerifiedArtifact(
            stage=candidate.stage,
            project=candidate.project,
            version=candidate.version,
            filename=candidate.filename,
            sha256=candidate.sha256,
            size_bytes=size,
            local_path=path,
        )

    @staticmethod
    def _verified_existing(path: Path, sha256: str, size: int) -> bool:
        if path.stat().st_size != size:
            return False
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest() == sha256
