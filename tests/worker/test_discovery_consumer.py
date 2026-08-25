from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

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
    def __init__(self, payload):
        self.payload, self.calls = payload, 0

    def iter_chunks(self, resolved):
        self.calls += 1
        yield self.payload


class Store:
    def __init__(self, error=None):
        self.calls, self.error = [], error

    def discover_artifact(self, artifact, release):
        self.calls.append((artifact, release))
        if self.error:
            raise self.error


def item(payload=b"wheel"):
    digest = hashlib.sha256(payload).hexdigest()
    return DiscoveryCandidate(
        "company/guardian",
        "demo",
        "demo-1.2.3-py3-none-any.whl",
        digest,
        f"/root/pypi/+f/abc/demo-1.2.3-py3-none-any.whl#sha256={digest}",
    )


def build(tmp_path, payload=b"wheel", store=None):
    queue = FileDiscoverySink(tmp_path / "d", now=lambda: NOW)
    source = BytesSource(payload)
    store = store or Store()
    consumer = DiscoveryConsumer(
        queue=queue,
        resolver=SimpleLinkResolver("https://devpi.invalid/"),
        bytes_source=source,
        quarantine=QuarantineStore(tmp_path / "q", max_size_bytes=100),
        store=store,
        worker_id="worker",
        lease_duration=timedelta(minutes=5),
        retry_delay=timedelta(0),
        now=lambda: NOW,
    )
    return queue, source, store, consumer


def test_consumer_persists_before_f4_and_closes_verified_stream(tmp_path):
    queue, source, store, consumer = build(tmp_path)
    queue.discover(item())
    assert consumer.run_once().status is DiscoveryCycleStatus.COMPLETED
    assert source.calls == 1 and len(store.calls) == 1 and queue.count("COMPLETED") == 1


def test_consumer_reuses_quarantine_on_retry(tmp_path):
    store = Store(RuntimeError("temporary"))
    queue, source, store, consumer = build(tmp_path, store=store)
    queue.discover(item())
    assert consumer.run_once().status is DiscoveryCycleStatus.RETRY
    store.error = None
    assert consumer.run_once().status is DiscoveryCycleStatus.COMPLETED
    assert source.calls == 1


def test_transition_conflict_is_terminal(tmp_path):
    queue, _, _, consumer = build(tmp_path, store=Store(TransitionConflict("conflict")))
    queue.discover(item())
    assert consumer.run_once().status is DiscoveryCycleStatus.FAILED
