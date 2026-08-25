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


def test_relative_root_and_symlink_root_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        QuarantineStore(Path("relative"), max_size_bytes=100)
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "missing", target_is_directory=True)
    with pytest.raises(QuarantineError):
        QuarantineStore(link, max_size_bytes=100)


def test_root_and_object_modes_are_restricted(tmp_path: Path) -> None:
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    assert (store.root_path.stat().st_mode & 0o777) == 0o700
    payload = b"safe"
    item = store.persist(candidate(payload), [payload])
    path = store.root_path / store.object_relative_path(item.sha256)
    assert (path.stat().st_mode & 0o777) == 0o600
    assert path.stat().st_nlink == 1
    assert path.stat().st_uid == os.geteuid()


def test_mismatch_cleans_incoming(tmp_path: Path) -> None:
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(b"advertised", size=99)
    with pytest.raises(QuarantineError):
        store.persist(item, [b"actual"])
    incoming = store.root_path / ".incoming"
    assert not incoming.exists() or not list(incoming.iterdir())


def test_corrupt_existing_object_fails_closed(tmp_path: Path) -> None:
    payload = b"correct"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload)
    store.persist(item, [payload])
    path = store.root_path / store.object_relative_path(item.sha256)
    path.write_bytes(b"corrupt")
    with pytest.raises(QuarantineError):
        store.persist(item, [payload])


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


def test_hard_linked_object_is_rejected(tmp_path: Path) -> None:
    payload = b"one link only"
    store = QuarantineStore(tmp_path / "q", max_size_bytes=100)
    item = candidate(payload)
    store.persist(item, [payload]).open_for_analysis().__exit__(None, None, None)
    path = store.root_path / store.object_relative_path(item.sha256)
    os.link(path, tmp_path / "hard-link")
    with pytest.raises(QuarantineError):
        store.get_verified(item)
