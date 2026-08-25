from __future__ import annotations

import hashlib
import os
import threading
import time
from io import BytesIO
from pathlib import Path

import pytest

from devpi_guardian.worker.models import ArtifactCandidate, VerifiedArtifact
from devpi_guardian.worker.quarantine import (
    ArtifactSizeMismatch,
    QuarantineError,
    QuarantineStore,
)


def candidate(payload: bytes, *, size: int | None = None) -> ArtifactCandidate:
    return ArtifactCandidate(
        stage="root/pypi",
        project="demo",
        version="1.0",
        filename="demo-1.0-py3-none-any.whl",
        sha256=hashlib.sha256(payload).hexdigest(),
        origin_url="https://devpi.invalid/root/pypi/+f/demo.whl",
        expected_size_bytes=size,
    )


def test_store_uses_absolute_digest_path_and_verified_descriptor(tmp_path: Path) -> None:
    payload = b"artifact bytes"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = store.persist(candidate(payload), [payload[:3], payload[3:]])

    assert store.object_relative_path(item.sha256) == Path(
        "objects", "sha256", item.sha256[:2], item.sha256[2:4], item.sha256
    )
    with item.open_for_analysis() as stream:
        assert stream.read() == payload
    assert getattr(item, "local_path", None) is None
    store.close()


def test_uninitialized_store_retains_root_descriptor_without_creating_cas(tmp_path: Path) -> None:
    root = tmp_path / "q"
    root.mkdir(mode=0o700)
    store = QuarantineStore(root, max_size_bytes=100, initialize=False)

    assert list(root.iterdir()) == []
    store.initialize()
    assert (root / "objects" / "sha256").is_dir()
    assert (root / ".incoming").is_dir()
    store.close()


def test_uninitialized_and_closed_store_never_fall_back_to_cwd(tmp_path: Path, monkeypatch):
    root = tmp_path / "q"
    root.mkdir(mode=0o700)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    store = QuarantineStore(root, max_size_bytes=100, initialize=False)
    item = candidate(b"lifecycle")

    with pytest.raises(QuarantineError, match="not initialized"):
        store.persist(item, [b"lifecycle"])
    with pytest.raises(QuarantineError, match="not initialized"):
        store.get_verified(item)
    assert list(cwd.iterdir()) == []

    store.close()
    with pytest.raises(QuarantineError, match="closed"):
        store.initialize()
    with pytest.raises(QuarantineError, match="not initialized"):
        store.persist(item, [b"lifecycle"])


def test_relative_root_and_symlink_root_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        QuarantineStore(Path("relative"), max_size_bytes=100)
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "missing", target_is_directory=True)
    with pytest.raises(QuarantineError):
        QuarantineStore(link, max_size_bytes=100)


def test_symlinked_root_parent_rejected(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    parent_link = tmp_path / "parent-link"
    parent_link.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(QuarantineError):
        QuarantineStore(parent_link / "q", max_size_bytes=100)


def test_unsafe_root_parent_mode_rejected_during_descriptor_walk(tmp_path: Path) -> None:
    parent = tmp_path / "unsafe-parent"
    parent.mkdir(mode=0o700)
    parent.chmod(0o777)
    with pytest.raises(QuarantineError, match=r"parent|component|mode"):
        QuarantineStore(parent / "q", max_size_bytes=100)


def test_preexisting_component_with_unsafe_mode_rejected(tmp_path: Path) -> None:
    root = tmp_path / "q"
    root.mkdir(mode=0o700)
    (root / "objects").mkdir(mode=0o755)
    with pytest.raises(QuarantineError):
        QuarantineStore(root, max_size_bytes=100)


@pytest.mark.parametrize("component", ["objects", "sha256"])
def test_internal_component_symlink_rejected(tmp_path: Path, component: str) -> None:
    root = tmp_path / "q"
    root.mkdir(mode=0o700)
    target = tmp_path / f"{component}-target"
    target.mkdir(mode=0o700)
    if component == "sha256":
        (root / "objects").mkdir(mode=0o700)
        (root / "objects" / component).symlink_to(target, target_is_directory=True)
    else:
        (root / component).symlink_to(target, target_is_directory=True)
    with pytest.raises(QuarantineError):
        QuarantineStore(root, max_size_bytes=100)


def test_internal_prefix_symlink_rejected(tmp_path: Path) -> None:
    root = tmp_path / "q"
    store = QuarantineStore(root, max_size_bytes=100)
    digest = hashlib.sha256(b"prefix").hexdigest()
    first = root / "objects" / "sha256" / digest[:2]
    first_target = tmp_path / "prefix-target"
    first_target.mkdir(mode=0o700)
    first.symlink_to(first_target, target_is_directory=True)
    with pytest.raises(QuarantineError):
        store.get_verified(candidate(b"prefix"))
    store.close()


def test_new_directories_are_exactly_private_under_restrictive_umask(tmp_path: Path) -> None:
    original = os.umask(0o077)
    try:
        store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    finally:
        os.umask(original)
    assert (store.root_path.stat().st_mode & 0o777) == 0o700
    assert (store.root_path / "objects").stat().st_mode & 0o777 == 0o700
    store.close()


def test_close_attempts_all_descriptors_and_preserves_first_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    real_close = os.close
    calls: list[int] = []
    incoming_fd = store._incoming_fd

    def close(fd: int) -> None:
        calls.append(fd)
        if fd == incoming_fd:
            raise OSError("incoming close failed")
        real_close(fd)

    monkeypatch.setattr(os, "close", close)
    with pytest.raises(OSError, match="incoming close failed"):
        store.close()
    assert len(calls) == 4
    assert store._incoming_fd == incoming_fd
    assert store._sha256_fd is None
    assert store._objects_fd is None
    assert store._root_fd is None
    monkeypatch.undo()
    store.close()
    assert store._incoming_fd is None


def test_close_failure_cannot_reinitialize_or_escape_to_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    sentinel = tmp_path / "sentinel"
    sentinel.mkdir()
    monkeypatch.chdir(sentinel)
    incoming_fd = store._incoming_fd
    real_close = os.close

    def close(fd: int) -> None:
        if fd == incoming_fd:
            raise OSError("incoming close failed")
        real_close(fd)

    monkeypatch.setattr(os, "close", close)
    with pytest.raises(OSError, match="incoming close failed"):
        store.close()
    with pytest.raises(QuarantineError, match="closed"):
        store.initialize()
    assert list(sentinel.iterdir()) == []

    monkeypatch.undo()
    store.close()
    assert store._incoming_fd is None


def test_context_exit_preserves_active_body_error_when_close_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    real_close = os.close

    def close(fd: int) -> None:
        if fd == store._incoming_fd:
            raise OSError("close cleanup failed")
        real_close(fd)

    monkeypatch.setattr(os, "close", close)
    with pytest.raises(ValueError, match="body failed") as raised, store:
        raise ValueError("body failed")
    assert any("quarantine close failed" in note for note in raised.value.__notes__)
    monkeypatch.undo()
    store.close()


def test_root_and_object_modes_are_restricted(tmp_path: Path) -> None:
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    assert (store.root_path.stat().st_mode & 0o777) == 0o700
    payload = b"safe"
    item = store.persist(candidate(payload), [payload])
    path = store.root_path / store.object_relative_path(item.sha256)
    assert (path.stat().st_mode & 0o777) == 0o600
    assert path.stat().st_nlink == 1
    assert path.stat().st_uid == os.geteuid()
    item._stream.close()


def test_mismatch_cleans_incoming(tmp_path: Path) -> None:
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(b"advertised", size=99)
    with pytest.raises(QuarantineError):
        store.persist(item, [b"actual"])
    incoming = store.root_path / ".incoming"
    assert not incoming.exists() or not list(incoming.iterdir())
    store.close()


def test_matching_digest_with_wrong_expected_size_cleans_incoming(tmp_path: Path) -> None:
    payload = b"exact payload"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload, size=len(payload) + 1)
    with pytest.raises(ArtifactSizeMismatch):
        store.persist(item, [payload])
    assert not list((store.root_path / ".incoming").iterdir())
    store.close()


def test_corrupt_existing_object_fails_closed(tmp_path: Path) -> None:
    payload = b"correct"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload)
    item_verified = store.persist(item, [payload])
    path = store.root_path / store.object_relative_path(item.sha256)
    # The returned descriptor is owned by the caller, even when the test then
    # mutates the path to exercise fail-closed verification.
    item_verified._stream.close()
    path.write_bytes(b"corrupt")
    with pytest.raises(QuarantineError):
        store.persist(item, [payload])
    store.close()


def test_identical_concurrent_publishers_are_idempotent(tmp_path: Path) -> None:
    payload = b"concurrent bytes"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload)
    barrier = threading.Barrier(2)
    results = []

    def publish() -> None:
        barrier.wait()
        results.append(store.persist(item, [payload]))

    threads = [threading.Thread(target=publish) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 2
    for result in results:
        with result.open_for_analysis() as stream:
            assert stream.read() == payload
    store.close()


def test_loser_retries_while_winner_is_between_link_and_unlink(tmp_path: Path, monkeypatch):
    from devpi_guardian.worker import quarantine as quarantine_module

    payload = b"forced concurrent publication"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload)
    barrier = threading.Barrier(2)
    winner_linked = threading.Event()
    release_winner = threading.Event()
    results = []
    errors = []
    real_link = os.link
    real_sleep = quarantine_module.time.sleep
    first_link = True

    def link(*args, **kwargs):
        nonlocal first_link
        result = real_link(*args, **kwargs)
        if first_link:
            first_link = False
            winner_linked.set()
            assert release_winner.wait(1)
        return result

    def sleep(seconds):
        release_winner.set()
        real_sleep(seconds)

    monkeypatch.setattr(os, "link", link)
    monkeypatch.setattr(quarantine_module.time, "sleep", sleep)

    def publish() -> None:
        try:
            barrier.wait()
            results.append(store.persist(item, [payload]))
        except BaseException as error:
            errors.append(error)

    threads = [threading.Thread(target=publish) for _ in range(2)]
    for thread in threads:
        thread.start()
    assert winner_linked.wait(1)
    for thread in threads:
        thread.join(2)
    assert errors == []
    assert len(results) == 2
    for result in results:
        result._stream.close()
    store.close()


def test_persistent_extra_hardlink_fails_within_bounded_retry(tmp_path: Path, monkeypatch):
    payload = b"persistent extra link"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload)
    verified = store.persist(item, [payload])
    verified._stream.close()
    path = store.root_path / store.object_relative_path(item.sha256)
    extra = tmp_path / "persistent-link"
    os.link(path, extra)
    real_hash = hashlib.sha256
    monkeypatch.setattr(hashlib, "sha256", lambda: pytest.fail("must not hash unsafe object"))
    leaf_fd = store._open_leaf(item.sha256, create=False)
    assert leaf_fd is not None
    started = time.monotonic()
    try:
        with pytest.raises(QuarantineError):
            store._open_verified_fd(
                leaf_fd,
                item.sha256,
                item,
                None,
                retry_transient_links=True,
            )
    finally:
        os.close(leaf_fd)
        store.close()
        monkeypatch.setattr(hashlib, "sha256", real_hash)
    assert time.monotonic() - started < 0.5


def test_verified_descriptor_is_bound_when_cas_name_is_replaced(tmp_path: Path) -> None:
    payload = b"descriptor binding"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload)
    verified = store.persist(item, [payload])
    path = store.root_path / store.object_relative_path(item.sha256)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"attacker bytes")
    os.replace(replacement, path)
    with verified.open_for_analysis() as stream:
        assert stream.read() == payload
    store.close()


def test_hard_linked_object_is_rejected(tmp_path: Path) -> None:
    payload = b"one link only"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload)
    store.persist(item, [payload]).open_for_analysis().__exit__(None, None, None)
    path = store.root_path / store.object_relative_path(item.sha256)
    os.link(path, tmp_path / "hard-link")
    with pytest.raises(QuarantineError):
        store.get_verified(item)
    store.close()


def test_transient_staging_link_is_retried_before_full_verification(tmp_path: Path, monkeypatch):
    payload = b"transient staging link"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload)
    verified = store.persist(item, [payload])
    verified._stream.close()
    leaf_fd = store._open_leaf(item.sha256, create=False)
    assert leaf_fd is not None
    real_fstat = os.fstat
    calls = 0

    def fstat(fd):
        nonlocal calls
        result = real_fstat(fd)
        calls += 1
        if calls == 1:
            values = list(result)
            values[3] = 2
            return os.stat_result(values)
        return result

    monkeypatch.setattr(os, "fstat", fstat)
    try:
        stream = store._open_verified_fd(
            leaf_fd,
            item.sha256,
            item,
            None,
            retry_transient_links=True,
        )
        assert stream is not None
        with stream:
            assert stream.read() == payload
    finally:
        os.close(leaf_fd)
        store.close()


def test_hard_link_added_during_hash_is_rejected(tmp_path: Path, monkeypatch) -> None:
    payload = b"hash race"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload)
    verified = store.persist(item, [payload])
    verified._stream.close()
    path = store.root_path / store.object_relative_path(item.sha256)
    added = tmp_path / "during-hash"
    real_sha256 = hashlib.sha256

    class Hash:
        def __init__(self):
            self.inner = real_sha256()
            self.done = False

        def update(self, chunk):
            self.inner.update(chunk)
            if not self.done:
                os.link(path, added)
                self.done = True

        def hexdigest(self):
            return self.inner.hexdigest()

    monkeypatch.setattr(hashlib, "sha256", Hash)
    with pytest.raises(QuarantineError):
        store.get_verified(item)
    store.close()


def test_final_object_owner_is_revalidated(tmp_path: Path, monkeypatch) -> None:
    payload = b"owner check"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload)
    verified = store.persist(item, [payload])
    verified._stream.close()
    leaf_fd = store._open_leaf(item.sha256, create=False)
    assert leaf_fd is not None
    actual_euid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: actual_euid + 1)
    with pytest.raises(QuarantineError):
        store._open_verified_fd(leaf_fd, item.sha256, item, None)
    os.close(leaf_fd)
    store.close()


def test_failing_iterable_cleans_staging(tmp_path: Path) -> None:
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)

    def broken():
        yield b"partial"
        raise ValueError("source failed")

    with pytest.raises(ValueError, match="source failed"):
        store.persist(candidate(b"partial"), broken())
    assert not list((store.root_path / ".incoming").iterdir())
    store.close()


def test_iterator_error_remains_primary_when_staging_close_fails(
    tmp_path: Path, monkeypatch
) -> None:
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    real_fdopen = os.fdopen

    class CloseFailingOutput:
        def __init__(self, inner):
            self.inner = inner

        @property
        def closed(self):
            return self.inner.closed

        def write(self, data):
            return self.inner.write(data)

        def flush(self):
            return self.inner.flush()

        def fileno(self):
            return self.inner.fileno()

        def close(self):
            self.inner.close()
            raise OSError("staging close failed")

    monkeypatch.setattr(
        os,
        "fdopen",
        lambda fd, mode, closefd=False: CloseFailingOutput(real_fdopen(fd, mode, closefd=closefd)),
    )

    def broken():
        yield b"partial"
        raise ValueError("iterator primary")

    with pytest.raises(ValueError, match="iterator primary") as raised:
        store.persist(candidate(b"partial"), broken())
    assert any("staging output" in note for note in raised.value.__notes__)
    assert not list((store.root_path / ".incoming").iterdir())
    store.close()


def test_link_failure_cleans_staging(tmp_path: Path, monkeypatch) -> None:
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    real_link = os.link

    def fail_link(*args, **kwargs):
        raise OSError("link failed")

    monkeypatch.setattr(os, "link", fail_link)
    with pytest.raises(OSError, match="link failed"):
        store.persist(candidate(b"link failure"), [b"link failure"])
    assert not list((store.root_path / ".incoming").iterdir())
    monkeypatch.setattr(os, "link", real_link)
    store.close()


def test_fsync_failure_cleans_staging(tmp_path: Path, monkeypatch) -> None:
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    real_fsync = os.fsync

    monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("fsync failed")))
    with pytest.raises(OSError, match="fsync failed"):
        store.persist(candidate(b"fsync failure"), [b"fsync failure"])
    assert not list((store.root_path / ".incoming").iterdir())
    monkeypatch.setattr(os, "fsync", real_fsync)
    store.close()


def test_existing_corrupt_close_failure_is_fail_closed(tmp_path: Path, monkeypatch) -> None:
    payload = b"existing close"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload)
    published = store.persist(item, [payload])
    published._stream.close()
    real_open = store._open_verified_fd
    calls = 0

    class FailingClose(BytesIO):
        def close(self):
            raise OSError("existing close failed")

    def open_verified(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return FailingClose(payload)
        return real_open(*args, **kwargs)

    monkeypatch.setattr(store, "_open_verified_fd", open_verified)
    with pytest.raises(QuarantineError, match="existing quarantine object close failed"):
        store.persist(item, [payload])
    store.close()


def test_existing_close_first_failure_retries_then_fails_closed(
    tmp_path: Path, monkeypatch
) -> None:
    payload = b"existing retry"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload)
    published = store.persist(item, [payload])
    published._stream.close()
    real_open = store._open_verified_fd
    calls = 0

    class RetryClose(BytesIO):
        def __init__(self, value):
            super().__init__(value)
            self.attempts = 0

        def close(self):
            self.attempts += 1
            if self.attempts == 1:
                raise OSError("existing first close failed")
            super().close()

    existing = RetryClose(payload)

    def open_verified(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return existing
        return real_open(*args, **kwargs)

    monkeypatch.setattr(store, "_open_verified_fd", open_verified)
    with pytest.raises(QuarantineError, match="existing quarantine object close failed"):
        store.persist(item, [payload])
    assert existing.attempts == 2 and existing.closed
    store.close()


def test_final_object_unsafe_mode_is_rejected(tmp_path: Path) -> None:
    payload = b"unsafe mode"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload)
    verified = store.persist(item, [payload])
    verified._stream.close()
    path = store.root_path / store.object_relative_path(item.sha256)
    path.chmod(0o644)
    with pytest.raises(QuarantineError):
        store.get_verified(item)
    store.close()


def test_nonregular_fifo_object_is_rejected_without_blocking(tmp_path: Path) -> None:
    payload = b"fifo target"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload)
    digest = item.sha256
    leaf_fd = store._open_leaf(digest, create=True)
    os.close(leaf_fd)
    leaf = store.root_path / "objects" / "sha256" / digest[:2] / digest[2:4]
    os.mkfifo(leaf / digest, 0o600)
    with pytest.raises(QuarantineError):
        store.get_verified(item)
    store.close()


class RetryOwnedStream:
    def __init__(self, inner):
        self.inner = inner
        self.attempts = 0

    @property
    def closed(self):
        return self.inner.closed

    def read(self, size=-1):
        return self.inner.read(size)

    def seek(self, position):
        return self.inner.seek(position)

    def tell(self):
        return self.inner.tell()

    def fileno(self):
        return self.inner.fileno()

    def close(self):
        self.attempts += 1
        if self.attempts == 1:
            raise OSError("owned stream first close failed")
        self.inner.close()


def test_persist_leaf_close_failure_retries_verified_stream(tmp_path: Path, monkeypatch) -> None:
    payload = b"persist leaf close"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    holder = []

    def artifact(candidate, size, stream):
        wrapped = RetryOwnedStream(stream)
        holder.append(wrapped)
        return VerifiedArtifact(
            stage=candidate.stage,
            project=candidate.project,
            version=candidate.version,
            filename=candidate.filename,
            sha256=candidate.sha256,
            size_bytes=size,
            _stream=wrapped,
        )

    real_open_leaf = store._open_leaf

    def open_leaf(digest, *, create):
        fd = real_open_leaf(digest, create=create)
        if create:
            holder.append(fd)
        return fd

    monkeypatch.setattr(store, "_artifact", artifact)
    monkeypatch.setattr(store, "_open_leaf", open_leaf)
    real_close = os.close
    failed = False

    def close(fd):
        nonlocal failed
        if holder and fd == holder[0] and not failed:
            failed = True
            raise OSError("leaf close failed")
        real_close(fd)

    monkeypatch.setattr(os, "close", close)
    with pytest.raises(OSError, match="leaf close failed"):
        store.persist(candidate(payload), [payload])
    assert holder[1].attempts == 2 and holder[1].closed
    monkeypatch.undo()
    store.close()


def test_get_verified_leaf_close_failure_retries_verified_stream(
    tmp_path: Path, monkeypatch
) -> None:
    payload = b"get leaf close"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload)
    published = store.persist(item, [payload])
    published._stream.close()
    holder = []

    def artifact(candidate, size, stream):
        wrapped = RetryOwnedStream(stream)
        holder.append(wrapped)
        return VerifiedArtifact(
            stage=candidate.stage,
            project=candidate.project,
            version=candidate.version,
            filename=candidate.filename,
            sha256=candidate.sha256,
            size_bytes=size,
            _stream=wrapped,
        )

    real_open_leaf = store._open_leaf

    def open_leaf(digest, *, create):
        fd = real_open_leaf(digest, create=create)
        if not create:
            holder.append(fd)
        return fd

    monkeypatch.setattr(store, "_artifact", artifact)
    monkeypatch.setattr(store, "_open_leaf", open_leaf)
    real_close = os.close
    failed = False

    def close(fd):
        nonlocal failed
        if holder and fd == holder[0] and not failed:
            failed = True
            raise OSError("leaf close failed")
        real_close(fd)

    monkeypatch.setattr(os, "close", close)
    with pytest.raises(OSError, match="leaf close failed"):
        store.get_verified(item)
    assert holder[1].attempts == 2 and holder[1].closed
    monkeypatch.undo()
    store.close()
