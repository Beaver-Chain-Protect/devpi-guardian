from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from io import BytesIO

from devpi_guardian.verdicts.errors import TransitionConflict
from devpi_guardian.worker.discovery import DiscoveryCandidate, FileDiscoverySink
from devpi_guardian.worker.discovery_consumer import (
    DiscoveryConsumer,
    DiscoveryCycleStatus,
    SimpleLinkResolver,
)
from devpi_guardian.worker.models import VerifiedArtifact
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
    relpath = f"root/pypi/+f/{digest[:3]}/{digest[3:16]}/demo-1.2.3-py3-none-any.whl"
    return DiscoveryCandidate(
        "company/guardian",
        "demo",
        "demo-1.2.3-py3-none-any.whl",
        digest,
        f"/{relpath}#sha256={digest}",
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
    artifact, release = store.calls[0]
    assert artifact.sha256 == release.sha256 == item().sha256
    assert artifact.size_bytes == len(b"wheel")
    assert release.stage == "root/pypi"
    assert release.project == "demo"
    assert release.version == "1.2.3"
    assert release.filename == item().filename
    assert release.origin_url == "https://devpi.invalid:443" + item().link_href.split("#", 1)[0]
    assert artifact.discovered_at == release.discovered_at


def test_consumer_reuses_quarantine_on_retry(tmp_path):
    store = Store(RuntimeError("temporary"))
    queue, source, store, consumer = build(tmp_path, store=store)
    queue.discover(item())
    assert consumer.run_once().status is DiscoveryCycleStatus.RETRY
    store.error = None
    assert consumer.run_once().status is DiscoveryCycleStatus.COMPLETED
    assert source.calls == 1


def test_consumer_verified_close_retry_still_fences_discovery(tmp_path):
    payload = b"wheel"
    candidate = item(payload)
    queue = FileDiscoverySink(tmp_path / "d", now=lambda: NOW)

    class RetryClose(BytesIO):
        def __init__(self, value):
            super().__init__(value)
            self.attempts = 0

        def close(self):
            self.attempts += 1
            if self.attempts == 1:
                raise OSError("first close failed")
            super().close()

    stream = RetryClose(payload)
    verified = VerifiedArtifact(
        stage="root/pypi",
        project="demo",
        version="1.2.3",
        filename=candidate.filename,
        sha256=candidate.sha256,
        size_bytes=len(payload),
        _stream=stream,
    )

    class Quarantine:
        def get_verified(self, _candidate):
            return verified

    store = Store()
    consumer = DiscoveryConsumer(
        queue=queue,
        resolver=SimpleLinkResolver("https://devpi.invalid/"),
        bytes_source=BytesSource(payload),
        quarantine=Quarantine(),
        store=store,
        worker_id="worker",
        now=lambda: NOW,
    )
    queue.discover(candidate)

    result = consumer.run_once()

    assert result.status is DiscoveryCycleStatus.FAILED
    assert stream.attempts == 2 and stream.closed
    assert store.calls == []


def test_transition_conflict_is_terminal(tmp_path):
    queue, _, _, consumer = build(tmp_path, store=Store(TransitionConflict("conflict")))
    queue.discover(item())
    assert consumer.run_once().status is DiscoveryCycleStatus.FAILED


def test_resolver_rejects_noncanonical_links_and_fragments():
    payload = b"wheel"
    resolver = SimpleLinkResolver("https://devpi.invalid/")
    digest = hashlib.sha256(payload).hexdigest()
    valid = f"/{item(payload).link_href.split('#', 1)[0].lstrip('/')}#sha256={digest}"
    candidate = item(payload)
    candidate = DiscoveryCandidate(
        candidate.stage, candidate.project, candidate.filename, digest, valid
    )
    for bad in (
        valid.replace("/root/pypi", "/root//pypi"),
        valid.replace("/root/pypi", "/root/./pypi"),
        valid.replace("/root/pypi", "/root/%2e%2e/pypi"),
        valid.replace("#sha256=", "#sha256=" + "0"),
        valid.replace("#sha256=", "#other="),
        valid.replace("#sha256=" + digest, "#sha256="),
    ):
        with __import__("pytest").raises(ValueError):
            resolver.resolve(
                DiscoveryCandidate(
                    candidate.stage, candidate.project, candidate.filename, digest, bad
                )
            )
    for base in (
        "https://devpi.invalid//",
        "https://devpi.invalid/?q=1",
        "https://devpi.invalid/#fragment",
    ):
        with __import__("pytest").raises(ValueError):
            SimpleLinkResolver(base)


def test_resolver_supports_canonical_mount_and_rejects_outside_mount():
    candidate = item()
    resolver = SimpleLinkResolver("https://devpi.invalid/devpi")
    mounted = resolver.resolve(
        DiscoveryCandidate(
            candidate.stage,
            candidate.project,
            candidate.filename,
            candidate.sha256,
            "/devpi" + candidate.link_href,
        )
    )
    assert mounted.origin_url.startswith("https://devpi.invalid:443/devpi/root/pypi/+f/")
    with __import__("pytest").raises(ValueError):
        resolver.resolve(candidate)


def test_resolver_rejects_invalid_host_and_ports():
    for base in ("http://:80/", "https://devpi.invalid:0/", "https://devpi.invalid:65536/"):
        with __import__("pytest").raises(ValueError):
            SimpleLinkResolver(base)
