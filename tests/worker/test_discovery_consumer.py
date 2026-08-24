from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from devpi_guardian.verdicts.errors import TransitionConflict
from devpi_guardian.worker.discovery import DiscoveryCandidate, FileDiscoverySink
from devpi_guardian.worker.discovery_consumer import (
    DiscoveryConsumer,
    DiscoveryCycleStatus,
    SimpleLinkResolver,
)
from devpi_guardian.worker.quarantine import QuarantineStore

NOW = datetime(2026, 8, 24, 3, 0, tzinfo=UTC)


class BytesSource:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.calls = 0

    def iter_chunks(self, resolved):
        assert resolved.relpath.startswith("root/pypi/+f/")
        self.calls += 1
        yield self.payload[:3]
        yield self.payload[3:]


class Store:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.calls = []
        self.error = error

    def discover_artifact(self, artifact, release):
        self.calls.append((artifact, release))
        if self.error is not None:
            raise self.error


def make_candidate(payload: bytes, **changes) -> DiscoveryCandidate:
    sha256 = hashlib.sha256(payload).hexdigest()
    values = {
        "stage": "company/guardian",
        "project": "demo",
        "filename": "demo-1.2.3-py3-none-any.whl",
        "sha256": sha256,
        "link_href": f"/root/pypi/+f/abc/demo-1.2.3-py3-none-any.whl#sha256={sha256}",
    }
    values.update(changes)
    return DiscoveryCandidate(**values)


def build_consumer(
    tmp_path: Path,
    payload: bytes,
    *,
    store: Store | None = None,
):
    queue = FileDiscoverySink(tmp_path / "discovery", now=lambda: NOW)
    source = BytesSource(payload)
    artifact_store = store or Store()
    consumer = DiscoveryConsumer(
        queue=queue,
        resolver=SimpleLinkResolver("https://devpi.example/"),
        bytes_source=source,
        quarantine=QuarantineStore(tmp_path / "quarantine", max_size_bytes=1024),
        store=artifact_store,
        worker_id="discovery-worker-1",
        lease_duration=timedelta(minutes=5),
        retry_delay=timedelta(0),
        now=lambda: NOW,
    )
    return queue, source, artifact_store, consumer


def test_consumer_verifies_quarantines_and_registers_f4_before_ack(tmp_path) -> None:
    payload = b"wheel bytes"
    queue, source, store, consumer = build_consumer(tmp_path, payload)
    item = make_candidate(payload)
    queue.discover(item)

    cycle = consumer.run_once()

    assert cycle.status is DiscoveryCycleStatus.COMPLETED
    assert source.calls == 1
    [(artifact, release)] = store.calls
    assert artifact.sha256 == item.sha256
    assert artifact.size_bytes == len(payload)
    assert release.stage == "root/pypi"
    assert release.project == "demo"
    assert release.version == "1.2.3"
    assert release.filename == item.filename
    assert release.origin_url == (
        "https://devpi.example/root/pypi/+f/abc/demo-1.2.3-py3-none-any.whl"
    )
    assert queue.count("COMPLETED") == 1


def test_consumer_reuses_verified_quarantine_file_when_f4_retry_is_needed(tmp_path) -> None:
    payload = b"wheel bytes"
    store = Store(error=RuntimeError("database temporarily unavailable"))
    queue, source, _, consumer = build_consumer(tmp_path, payload, store=store)
    queue.discover(make_candidate(payload))

    first = consumer.run_once()
    assert first.status is DiscoveryCycleStatus.RETRY
    assert source.calls == 1

    store.error = None
    second = consumer.run_once()

    assert second.status is DiscoveryCycleStatus.COMPLETED
    assert source.calls == 1


def test_transition_conflict_is_terminal_and_not_retried(tmp_path) -> None:
    payload = b"wheel bytes"
    store = Store(error=TransitionConflict("artifact size conflict"))
    queue, _, _, consumer = build_consumer(tmp_path, payload, store=store)
    queue.discover(make_candidate(payload))

    cycle = consumer.run_once()

    assert cycle.status is DiscoveryCycleStatus.FAILED
    assert queue.count("FAILED") == 1
    assert consumer.run_once().status is DiscoveryCycleStatus.IDLE


def test_bad_advertised_hash_is_terminal(tmp_path) -> None:
    payload = b"actual wheel bytes"
    queue, _, store, consumer = build_consumer(tmp_path, payload)
    queue.discover(make_candidate(b"different bytes"))

    cycle = consumer.run_once()

    assert cycle.status is DiscoveryCycleStatus.FAILED
    assert store.calls == []


def test_resolver_rejects_cross_origin_and_non_artifact_links() -> None:
    resolver = SimpleLinkResolver("https://devpi.example/")
    payload = b"wheel"

    for href in (
        "https://evil.example/root/pypi/+f/abc/demo.whl",
        "/root/pypi/+api",
        "/root/pypi/+f/abc/other.whl",
    ):
        try:
            resolver.resolve(make_candidate(payload, link_href=href))
        except ValueError:
            pass
        else:
            raise AssertionError(f"unsafe link accepted: {href}")
