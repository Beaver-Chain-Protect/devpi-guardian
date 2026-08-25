from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path

import pytest

from devpi_guardian.worker.models import ArtifactCandidate
from devpi_guardian.worker.quarantine import QuarantineError, QuarantineStore


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
