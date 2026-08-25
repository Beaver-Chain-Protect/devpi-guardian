"""Descriptor-relative, content-addressed quarantine storage.

The store deliberately never returns a filesystem pathname as an analysis
handle.  A :class:`VerifiedArtifact` owns the descriptor that was checked,
so replacing a name in the CAS cannot change the bytes an analyzer receives.
"""

from __future__ import annotations

import hashlib
import os
import stat
import time
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import BinaryIO

from devpi_guardian.verdicts.models import validate_sha256

from .models import ArtifactCandidate, VerifiedArtifact

_DIR_MODE = 0o700
_OBJECT_MODE = 0o600
_CHUNK_SIZE = 1024 * 1024
_TRANSIENT_LINK_WINDOW = 0.1
_TRANSIENT_LINK_DELAY = 0.001


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


def close_owned(stream, label: str, primary: BaseException | None = None) -> None:
    """Close an owned stream, retrying once when the first close fails."""

    close = getattr(stream, "close", None)
    if not callable(close):
        return
    try:
        close()
        return
    except BaseException as first:
        try:
            closed = bool(stream.closed)
        except BaseException as state_error:
            first.add_note(f"{label} closed-state check failed: {state_error}")
            closed = False
        if not closed:
            try:
                close()
            except BaseException as second:
                first.add_note(f"{label} second close failed: {type(second).__name__}: {second}")
        if primary is not None:
            _note_cleanup(primary, label, first)
            return
        raise QuarantineError(f"{label} close failed") from first


class QuarantineStore:
    """Secure CAS rooted at an absolute, private directory."""

    def __init__(
        self,
        root: Path | str,
        *,
        max_size_bytes: int,
        initialize: bool = True,
    ) -> None:
        if type(max_size_bytes) is not int or max_size_bytes <= 0:
            raise ValueError("max_size_bytes must be positive")
        path = Path(root)
        if not path.is_absolute():
            raise ValueError("quarantine root must be absolute")
        self._root_path = path
        self._max_size_bytes = max_size_bytes
        self._root_fd = self._open_root(path, create=initialize)
        self._objects_fd: int | None = None
        self._sha256_fd: int | None = None
        self._incoming_fd: int | None = None
        self._state = "open_uninitialized"
        if initialize:
            self.initialize()

    def initialize(self) -> None:
        """Create and retain CAS directories after root validation/activation."""
        if self._state != "open_uninitialized":
            if self._state == "open":
                return
            raise QuarantineError("quarantine store is closed")
        try:
            self._objects_fd = self._open_or_create_dir(self._root_fd, "objects")
            self._sha256_fd = self._open_or_create_dir(self._objects_fd, "sha256")
            self._incoming_fd = self._open_or_create_dir(self._root_fd, ".incoming")
            self._state = "open"
        except BaseException as error:
            for name in ("_incoming_fd", "_sha256_fd", "_objects_fd", "_root_fd"):
                fd = getattr(self, name)
                if fd is not None:
                    setattr(self, name, None)
                    _close_fd(fd, error)
            self._state = "closed"
            raise

    def _require_open(self) -> None:
        if self._state != "open":
            raise QuarantineError("quarantine store is not initialized")

    @property
    def root_path(self) -> Path:
        """The configured root for diagnostics/tests (never used for I/O)."""

        return self._root_path

    def close(self) -> None:
        if self._state == "closed" and all(
            getattr(self, name, None) is None
            for name in ("_incoming_fd", "_sha256_fd", "_objects_fd", "_root_fd")
        ):
            return
        self._state = "closing"
        first_error: BaseException | None = None
        for name in ("_incoming_fd", "_sha256_fd", "_objects_fd", "_root_fd"):
            fd = getattr(self, name, None)
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException as error:
                    if first_error is None:
                        first_error = error
                    else:
                        _note_cleanup(first_error, "descriptor", error)
                else:
                    setattr(self, name, None)
        self._state = (
            "closed"
            if all(
                getattr(self, name, None) is None
                for name in ("_incoming_fd", "_sha256_fd", "_objects_fd", "_root_fd")
            )
            else "closing"
        )
        if first_error is not None:
            raise first_error

    def __enter__(self) -> QuarantineStore:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        if exc_value is not None:
            try:
                self.close()
            except BaseException as cleanup:
                exc_value.add_note(f"quarantine close failed: {type(cleanup).__name__}: {cleanup}")
        else:
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

        self._require_open()
        digest = validate_sha256(candidate.sha256)
        leaf_fd = self._open_leaf(digest, create=True)
        staging_name: str | None = f"artifact-{uuid.uuid4().hex}"
        staging_fd: int | None = None
        primary_error: BaseException | None = None
        result: VerifiedArtifact | None = None
        try:
            try:
                staging_fd = os.open(
                    staging_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    _OBJECT_MODE,
                    dir_fd=self._incoming_fd,
                )
                os.fchmod(staging_fd, _OBJECT_MODE)
            except OSError as error:
                raise QuarantineError("unable to create quarantine staging file") from error

            hasher = hashlib.sha256()
            size = 0
            output = os.fdopen(staging_fd, "wb", closefd=False)
            output_error: BaseException | None = None
            try:
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
                output_error = error
            try:
                close_owned(output, "staging output", output_error)
            except BaseException as close_error:
                if output_error is None:
                    output_error = close_error
                else:
                    _note_cleanup(output_error, "staging output", close_error)
            if staging_fd is not None:
                try:
                    os.close(staging_fd)
                except BaseException as close_error:
                    if output_error is None:
                        output_error = QuarantineError("staging descriptor close failed")
                    _note_cleanup(output_error, "staging descriptor", close_error)
                else:
                    staging_fd = None
            if output_error is not None:
                raise output_error

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
                existing = self._open_verified_fd(
                    leaf_fd,
                    digest,
                    candidate,
                    size,
                    retry_transient_links=True,
                )
                if existing is None:
                    raise QuarantineError("existing quarantine object is corrupt") from None
                close_owned(existing, "existing quarantine object")
            if staging_name is not None:
                os.unlink(staging_name, dir_fd=self._incoming_fd)
                staging_name = None
            os.fsync(self._incoming_fd)
            os.fsync(leaf_fd)
            verified_stream = self._open_verified_fd(leaf_fd, digest, candidate, size)
            if verified_stream is None:
                raise QuarantineError("published quarantine object disappeared")
            result = self._artifact(candidate, size, verified_stream)
            return result
        except BaseException as primary:
            primary_error = primary
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
            try:
                _close_fd(leaf_fd, primary_error)
            except BaseException as close_error:
                if result is not None:
                    close_owned(result._stream, "verified stream", close_error)
                raise

    def get_verified(self, candidate: ArtifactCandidate) -> VerifiedArtifact | None:
        """Open and verify a CAS object, returning its owning descriptor."""

        self._require_open()
        digest = validate_sha256(candidate.sha256)
        leaf_fd = self._open_leaf(digest, create=False)
        if leaf_fd is None:
            return None
        primary_error: BaseException | None = None
        result: VerifiedArtifact | None = None
        try:
            stream = self._open_verified_fd(leaf_fd, digest, candidate, None)
            if stream is None:
                return None
            try:
                size = os.fstat(stream.fileno()).st_size
                result = self._artifact(candidate, size, stream)
                return result
            except BaseException as primary:
                close_owned(stream, "verified stream", primary)
                raise
        except BaseException as primary:
            primary_error = primary
            raise
        finally:
            try:
                _close_fd(leaf_fd, primary_error)
            except BaseException as close_error:
                if result is not None:
                    close_owned(result._stream, "verified stream", close_error)
                raise

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
    def _open_root(path: Path, *, create: bool = True) -> int:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parts = path.parts[1:]
        if not parts:
            _close_fd(fd)
            raise QuarantineError("quarantine root must not be filesystem root")
        for index, name in enumerate(parts):
            if name in ("", ".", "..") or "\x00" in name:
                _close_fd(fd)
                raise QuarantineError("invalid quarantine root component")
            final = index == len(parts) - 1
            created = False
            try:
                child = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=fd,
                )
            except FileNotFoundError:
                if not final or not create:
                    _close_fd(fd)
                    raise QuarantineError("quarantine root parent does not exist") from None
                try:
                    os.mkdir(name, _DIR_MODE, dir_fd=fd)
                    created = True
                    os.chmod(name, _DIR_MODE, dir_fd=fd, follow_symlinks=False)
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=fd,
                    )
                except OSError as error:
                    _close_fd(fd, error)
                    raise QuarantineError("unable to create quarantine root") from error
            except OSError as error:
                _close_fd(fd, error)
                raise QuarantineError("unsafe quarantine root component") from error
            old_fd = fd
            fd = child
            try:
                _close_fd(old_fd)
            except BaseException as error:
                _close_fd(fd, error)
                raise
            try:
                if created:
                    os.fchmod(fd, _DIR_MODE)
                st = os.fstat(fd)
                if not stat.S_ISDIR(st.st_mode):
                    raise QuarantineError("quarantine root must be a directory")
                if final and (st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != _DIR_MODE):
                    raise QuarantineError("quarantine root owner or mode is unsafe")
            except BaseException as error:
                _close_fd(fd, error)
                raise
        return fd

    @staticmethod
    def _open_or_create_dir(parent_fd: int, name: str) -> int:
        created = False
        try:
            os.mkdir(name, _DIR_MODE, dir_fd=parent_fd)
            created = True
            os.chmod(name, _DIR_MODE, dir_fd=parent_fd, follow_symlinks=False)
        except FileExistsError:
            pass
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError as error:
            raise QuarantineError(f"unsafe quarantine component: {name}") from error
        try:
            st = os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
                raise QuarantineError(f"unsafe quarantine component: {name}")
            if not created and stat.S_IMODE(st.st_mode) != _DIR_MODE:
                raise QuarantineError(f"unsafe quarantine component mode: {name}")
            if created:
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
        second: int | None = None
        try:
            second = (
                self._open_or_create_dir(first, digest[2:4])
                if create
                else self._open_existing_dir(first, digest[2:4])
            )
            return second
        finally:
            try:
                _close_fd(first)
            except BaseException as error:
                if second is not None:
                    _close_fd(second, error)
                raise

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
        *,
        retry_transient_links: bool = False,
    ) -> BinaryIO | None:
        try:
            entry = os.stat(digest, dir_fd=leaf_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise QuarantineError("unable to inspect quarantine object") from error
        if not stat.S_ISREG(entry.st_mode):
            raise QuarantineError("quarantine object is not a regular file")
        try:
            fd = os.open(
                digest,
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                dir_fd=leaf_fd,
            )
        except FileNotFoundError:
            return None
        except OSError as error:
            raise QuarantineError("unable to open quarantine object") from error
        stream: BinaryIO | None = None
        try:
            st = os.fstat(fd)
            if retry_transient_links and st.st_nlink == 2:
                deadline = time.monotonic() + _TRANSIENT_LINK_WINDOW
                while time.monotonic() < deadline:
                    _close_fd(fd)
                    fd = -1
                    time.sleep(min(_TRANSIENT_LINK_DELAY, max(0, deadline - time.monotonic())))
                    try:
                        fd = os.open(
                            digest,
                            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                            dir_fd=leaf_fd,
                        )
                    except FileNotFoundError:
                        return None
                    st = os.fstat(fd)
                    if st.st_nlink != 2:
                        break
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
            initial = os.fstat(stream.fileno())
            hasher = hashlib.sha256()
            while True:
                chunk = stream.read(_CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
            if hasher.hexdigest() != digest:
                raise QuarantineError("quarantine object digest does not match")
            final = os.fstat(stream.fileno())
            if (
                final.st_dev != initial.st_dev
                or final.st_ino != initial.st_ino
                or final.st_uid != initial.st_uid
                or final.st_mode != initial.st_mode
                or final.st_nlink != 1
                or final.st_size != initial.st_size
                or not stat.S_ISREG(final.st_mode)
                or final.st_uid != os.geteuid()
                or stat.S_IMODE(final.st_mode) != _OBJECT_MODE
            ):
                raise QuarantineError("quarantine object changed during verification")
            stream.seek(0)
            return stream
        except BaseException as primary:
            if stream is not None:
                close_owned(stream, "object stream", primary)
            if fd != -1:
                _close_fd(fd, primary)
            raise
