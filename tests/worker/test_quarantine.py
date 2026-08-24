from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from devpi_guardian.worker.models import ArtifactCandidate
from devpi_guardian.worker.quarantine import (
    ArtifactHashMismatch,
    ArtifactSizeMismatch,
    QuarantineStore,
)


def candidate(payload: bytes, *, expected_size: int | None = None) -> ArtifactCandidate:
    return ArtifactCandidate(
        stage="root/pypi",
        project="demo",
        version="1.0.0",
        filename="demo-1.0.0-py3-none-any.whl",
        sha256=hashlib.sha256(payload).hexdigest(),
        origin_url="https://devpi.example/root/pypi/+f/abc/demo.whl",
        expected_size_bytes=expected_size,
    )


def test_quarantine_streams_and_keeps_verified_artifact_by_digest(tmp_path: Path) -> None:
    payload = b"verified wheel bytes"
    store = QuarantineStore(tmp_path, max_size_bytes=1024)

    verified = store.persist(candidate(payload), [payload[:4], payload[4:]])

    assert verified.local_path.read_bytes() == payload
    assert verified.local_path.name == f"{verified.sha256}.whl"
    assert verified.size_bytes == len(payload)
    assert list((tmp_path / "incoming").iterdir()) == []

    reused = store.get_verified(candidate(payload))

    assert reused == verified


def test_quarantine_returns_none_when_verified_file_is_absent(tmp_path: Path) -> None:
    store = QuarantineStore(tmp_path, max_size_bytes=1024)

    assert store.get_verified(candidate(b"missing")) is None


def test_quarantine_rejects_hash_mismatch_and_removes_partial_file(tmp_path: Path) -> None:
    payload = b"actual"
    item = candidate(b"advertised")
    store = QuarantineStore(tmp_path, max_size_bytes=1024)

    with pytest.raises(ArtifactHashMismatch):
        store.persist(item, [payload])

    assert list((tmp_path / "incoming").iterdir()) == []
    assert not (tmp_path / "sha256").exists()


def test_quarantine_rejects_advertised_size_mismatch(tmp_path: Path) -> None:
    payload = b"artifact"
    store = QuarantineStore(tmp_path, max_size_bytes=1024)

    with pytest.raises(ArtifactSizeMismatch):
        store.persist(candidate(payload, expected_size=len(payload) + 1), [payload])

    assert list((tmp_path / "incoming").iterdir()) == []
