"""Descriptor-relative, content-addressed quarantine storage.

The store deliberately never returns a filesystem pathname as an analysis
handle.  A :class:`VerifiedArtifact` owns the descriptor that was checked,
so replacing a name in the CAS cannot change the bytes an analyzer receives.
"""

from __future__ import annotations

import hashlib
import os
import stat
import uuid
from collections.abc import Iterable
from contextlib import suppress
from pathlib import Path
from typing import BinaryIO

from devpi_guardian.verdicts.models import validate_sha256

from .models import ArtifactCandidate, VerifiedArtifact

_DIR_MODE = 0o700
_OBJECT_MODE = 0o600
_CHUNK_SIZE = 1024 * 1024


class QuarantineError(RuntimeError):
    """The bytes or quarantine filesystem failed a security contract."""


class ArtifactHashMismatch(QuarantineError):
    pass


class ArtifactSizeMismatch(QuarantineError):
    pass


class ArtifactTooLarge(QuarantineError):
    pass


def _note_cleanup(primary: BaseException, action: str, cleanup: BaseException) -> None:
    primary.add_note(f"{action} cleanup failed: {type(cleanup).__name__}: {cleanup}")


def _close_fd(fd: int, primary: BaseException | None = None) -> None:
    try:
        os.close(fd)
    except BaseException as error:
        if primary is None:
            raise
        _note_cleanup(primary, "descriptor", error)


class QuarantineStore:
    """Secure CAS rooted at an absolute, private directory."""

    def __init__(self, root: Path | str, *, max_size_bytes: int) -> None:
        if type(max_size_bytes) is not int or max_size_bytes <= 0:
            raise ValueError("max_size_bytes must be positive")
        path = Path(root)
        if not path.is_absolute():
            raise ValueError("quarantine root must be absolute")
        self._root_path = path
        self._max_size_bytes = max_size_bytes
        self._root_fd = self._open_root(path)
        self._objects_fd: int | None = None
        self._sha256_fd: int | None = None
        self._incoming_fd: int | None = None
        try:
            self._objects_fd = self._open_or_create_dir(self._root_fd, "objects")
            self._sha256_fd = self._open_or_create_dir(self._objects_fd, "sha256")
            self._incoming_fd = self._open_or_create_dir(self._root_fd, ".incoming")
        except BaseException as error:
            for name in ("_incoming_fd", "_sha256_fd", "_objects_fd", "_root_fd"):
                fd = getattr(self, name)
                if fd is not None:
                    setattr(self, name, None)
                    _close_fd(fd, error)
            raise

    @property
    def root_path(self) -> Path:
        """The configured root for diagnostics/tests (never used for I/O)."""

        return self._root_path

    def close(self) -> None:
        for name in ("_incoming_fd", "_sha256_fd", "_objects_fd", "_root_fd"):
            fd = getattr(self, name, None)
            if fd is not None:
                setattr(self, name, None)
                _close_fd(fd)

    def __enter__(self) -> QuarantineStore:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        self.close()
        return False

    @staticmethod
    def object_relative_path(sha256: str) -> Path:
        digest = validate_sha256(sha256)
        return Path("objects", "sha256", digest[:2], digest[2:4], digest)

    def persist(
        self,
        candidate: ArtifactCandidate,
        chunks: Iterable[bytes],
    ) -> VerifiedArtifact:
        """Verify and atomically publish bytes, without ever overwriting."""

        digest = validate_sha256(candidate.sha256)
        leaf_fd = self._open_leaf(digest, create=True)
        staging_name: str | None = f"artifact-{uuid.uuid4().hex}"
        staging_fd: int | None = None
        try:
            try:
                staging_fd = os.open(
                    staging_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    _OBJECT_MODE,
                    dir_fd=self._incoming_fd,
                )
            except OSError as error:
                raise QuarantineError("unable to create quarantine staging file") from error

            hasher = hashlib.sha256()
            size = 0
            try:
                with os.fdopen(staging_fd, "wb", closefd=True) as output:
                    staging_fd = None
                    for chunk in chunks:
                        if not isinstance(chunk, bytes):
                            raise QuarantineError("download chunks must be bytes")
                        size += len(chunk)
                        if size > self._max_size_bytes:
                            raise ArtifactTooLarge("artifact exceeds configured size limit")
                        hasher.update(chunk)
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            except BaseException as error:
                if hasher.hexdigest() != digest and isinstance(
                    error, (ArtifactTooLarge, QuarantineError)
                ):
                    # Preserve the primary error; this branch only documents the
                    # fact that the incomplete stream is intentionally discarded.
                    pass
                raise

            if hasher.hexdigest() != digest:
                raise ArtifactHashMismatch("downloaded SHA-256 does not match advertised SHA-256")
            expected = candidate.expected_size_bytes
            if expected is not None and size != expected:
                raise ArtifactSizeMismatch("downloaded size does not match advertised size")

            try:
                os.link(
                    staging_name,
                    digest,
                    src_dir_fd=self._incoming_fd,
                    dst_dir_fd=leaf_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                # A concurrent publisher won.  It is safe to reuse only a fully
                # verified identical object; a corrupt destination is fail-closed.
                os.unlink(staging_name, dir_fd=self._incoming_fd)
                staging_name = None
                os.fsync(self._incoming_fd)
                existing = self._open_verified_fd(leaf_fd, digest, candidate, size)
                if existing is None:
                    raise QuarantineError("existing quarantine object is corrupt") from None
                existing.close()
            if staging_name is not None:
                os.unlink(staging_name, dir_fd=self._incoming_fd)
                staging_name = None
            os.fsync(self._incoming_fd)
            os.fsync(leaf_fd)
            verified_stream = self._open_verified_fd(leaf_fd, digest, candidate, size)
            if verified_stream is None:
                raise QuarantineError("published quarantine object disappeared")
            return self._artifact(candidate, size, verified_stream)
        except BaseException as primary:
            if staging_fd is not None:
                _close_fd(staging_fd, primary)
            if staging_name is not None:
                try:
                    os.unlink(staging_name, dir_fd=self._incoming_fd)
                except FileNotFoundError:
                    pass
                except BaseException as cleanup:
                    _note_cleanup(primary, "staging", cleanup)
            raise
        finally:
            _close_fd(leaf_fd)

    def get_verified(self, candidate: ArtifactCandidate) -> VerifiedArtifact | None:
        """Open and verify a CAS object, returning its owning descriptor."""

        digest = validate_sha256(candidate.sha256)
        leaf_fd = self._open_leaf(digest, create=False)
        if leaf_fd is None:
            return None
        try:
            stream = self._open_verified_fd(leaf_fd, digest, candidate, None)
            if stream is None:
                return None
            try:
                size = os.fstat(stream.fileno()).st_size
                return self._artifact(candidate, size, stream)
            except BaseException as primary:
                try:
                    stream.close()
                except BaseException as cleanup:
                    _note_cleanup(primary, "verified stream", cleanup)
                raise
        finally:
            _close_fd(leaf_fd)

    def _artifact(
        self, candidate: ArtifactCandidate, size: int, stream: BinaryIO
    ) -> VerifiedArtifact:
        return VerifiedArtifact(
            stage=candidate.stage,
            project=candidate.project,
            version=candidate.version,
            filename=candidate.filename,
            sha256=candidate.sha256,
            size_bytes=size,
            _stream=stream,
        )

    @staticmethod
    def _open_root(path: Path) -> int:
        try:
            st = path.lstat()
            if stat.S_ISLNK(st.st_mode):
                raise QuarantineError("quarantine root must not be a symlink")
        except FileNotFoundError:
            with suppress(FileExistsError):
                path.mkdir(mode=_DIR_MODE)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as error:
            raise QuarantineError("unable to open quarantine root") from error
        try:
            st = os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode):
                raise QuarantineError("quarantine root must be a directory")
            if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != _DIR_MODE:
                raise QuarantineError("quarantine root owner or mode is unsafe")
            return fd
        except BaseException as error:
            _close_fd(fd, error)
            raise

    @staticmethod
    def _open_or_create_dir(parent_fd: int, name: str) -> int:
        with suppress(FileExistsError):
            os.mkdir(name, _DIR_MODE, dir_fd=parent_fd)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError as error:
            raise QuarantineError(f"unsafe quarantine component: {name}") from error
        try:
            st = os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
                raise QuarantineError(f"unsafe quarantine component: {name}")
            if stat.S_IMODE(st.st_mode) != _DIR_MODE:
                os.fchmod(fd, _DIR_MODE)
            return fd
        except BaseException as error:
            _close_fd(fd, error)
            raise

    def _open_leaf(self, digest: str, *, create: bool) -> int | None:
        first = (
            self._open_or_create_dir(self._sha256_fd, digest[:2])
            if create
            else self._open_existing_dir(self._sha256_fd, digest[:2])
        )
        if first is None:
            return None
        try:
            second = (
                self._open_or_create_dir(first, digest[2:4])
                if create
                else self._open_existing_dir(first, digest[2:4])
            )
            return second
        finally:
            _close_fd(first)

    @staticmethod
    def _open_existing_dir(parent_fd: int, name: str) -> int | None:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise QuarantineError(f"unsafe quarantine component: {name}") from error
        try:
            st = os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
                raise QuarantineError(f"unsafe quarantine component: {name}")
            if stat.S_IMODE(st.st_mode) != _DIR_MODE:
                raise QuarantineError(f"unsafe quarantine component mode: {name}")
            return fd
        except BaseException as error:
            _close_fd(fd, error)
            raise

    @staticmethod
    def _open_verified_fd(
        leaf_fd: int,
        digest: str,
        candidate: ArtifactCandidate,
        expected_size: int | None,
    ) -> BinaryIO | None:
        try:
            fd = os.open(digest, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=leaf_fd)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise QuarantineError("unable to open quarantine object") from error
        stream: BinaryIO | None = None
        try:
            st = os.fstat(fd)
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_uid != os.geteuid()
                or stat.S_IMODE(st.st_mode) != _OBJECT_MODE
                or st.st_nlink != 1
            ):
                raise QuarantineError("quarantine object metadata is unsafe")
            actual_size = st.st_size
            expected = candidate.expected_size_bytes
            if (expected_size is not None and actual_size != expected_size) or (
                expected is not None and actual_size != expected
            ):
                raise QuarantineError("quarantine object size does not match")
            stream = os.fdopen(fd, "rb", closefd=True)
            fd = -1
            hasher = hashlib.sha256()
            while True:
                chunk = stream.read(_CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
            if hasher.hexdigest() != digest:
                raise QuarantineError("quarantine object digest does not match")
            stream.seek(0)
            return stream
        except BaseException as primary:
            if stream is not None:
                try:
                    stream.close()
                except BaseException as cleanup:
                    _note_cleanup(primary, "object stream", cleanup)
            if fd != -1:
                _close_fd(fd, primary)
            raise
