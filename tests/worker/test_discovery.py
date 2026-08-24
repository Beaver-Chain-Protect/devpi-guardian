from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from devpi_guardian.worker.discovery import (
    DiscoveryCandidate,
    DiscoveryQueueFull,
    DiscoveryUnavailable,
    FileDiscoverySink,
    get_discovery_sink,
    set_discovery_sink,
)

SHA256 = "a" * 64
NOW = datetime(2026, 8, 24, 1, 2, 3, tzinfo=UTC)


def candidate(**changes) -> DiscoveryCandidate:
    values = {
        "stage": "company/guardian",
        "project": "demo-package",
        "filename": "demo_package-1.0.0-py3-none-any.whl",
        "sha256": SHA256,
        "link_href": "/root/pypi/+f/aaa/demo.whl#sha256=" + SHA256,
    }
    values.update(changes)
    return DiscoveryCandidate(**values)


def test_sink_registers_identical_metadata_once(tmp_path) -> None:
    sink = FileDiscoverySink(tmp_path, now=lambda: NOW)
    item = candidate()

    assert sink.discover(item) is None
    assert sink.discover(item) is None

    assert sink.count("PENDING") == 1


def test_sink_accepts_str_subclasses_and_snapshots_builtin_strings(tmp_path) -> None:
    class NormalizedName(str):
        pass

    item = candidate(project=NormalizedName("demo-package"))

    assert type(item.project) is str
    FileDiscoverySink(tmp_path, now=lambda: NOW).discover(item)


def test_batch_registration_keeps_distinct_release_mappings(tmp_path) -> None:
    sink = FileDiscoverySink(tmp_path, now=lambda: NOW)

    sink.discover_many(
        (
            candidate(),
            candidate(
                stage="other/guardian",
                link_href="/other/guardian/+f/aaa/demo.whl#sha256=" + SHA256,
            ),
        )
    )

    assert sink.count("PENDING") == 2


def test_claim_is_atomic_and_ack_prevents_rediscovery(tmp_path) -> None:
    sink = FileDiscoverySink(tmp_path, now=lambda: NOW)
    sink.discover(candidate())

    claim = sink.claim_next("worker-1", NOW + timedelta(minutes=5))

    assert claim is not None
    assert claim.candidate == candidate()
    assert claim.attempt_count == 1
    assert sink.claim_next("worker-2", NOW + timedelta(minutes=5)) is None

    sink.complete(claim)
    sink.discover(candidate())

    assert sink.count("COMPLETED") == 1
    assert sink.count("PENDING") == 0


def test_retry_preserves_attempt_count_and_terminal_failure(tmp_path) -> None:
    clock = [NOW]
    sink = FileDiscoverySink(tmp_path, now=lambda: clock[0])
    sink.discover(candidate())
    first = sink.claim_next("worker-1", NOW + timedelta(minutes=5))
    assert first is not None

    sink.retry(first, "temporary upstream failure", delay=timedelta(seconds=10))
    assert sink.claim_next("worker-1", NOW + timedelta(minutes=5)) is None

    clock[0] += timedelta(seconds=10)
    second = sink.claim_next("worker-1", clock[0] + timedelta(minutes=5))
    assert second is not None
    assert second.attempt_count == 2

    sink.fail(second, "release mapping conflict")

    assert sink.count("FAILED") == 1
    assert sink.count("PENDING") == 0


def test_expired_processing_job_is_recovered(tmp_path) -> None:
    clock = [NOW]
    sink = FileDiscoverySink(tmp_path, now=lambda: clock[0])
    sink.discover(candidate())
    first = sink.claim_next("dead-worker", NOW + timedelta(seconds=5))
    assert first is not None

    clock[0] += timedelta(seconds=6)

    assert sink.recover_expired_claims() == 1
    recovered = sink.claim_next("worker-2", clock[0] + timedelta(minutes=5))
    assert recovered is not None
    assert recovered.attempt_count == 2


def test_queue_capacity_is_enforced_without_losing_existing_job(tmp_path) -> None:
    sink = FileDiscoverySink(tmp_path, max_active_jobs=1, now=lambda: NOW)
    sink.discover(candidate())

    with pytest.raises(DiscoveryQueueFull):
        sink.discover(candidate(project="another-project"))

    assert sink.count("PENDING") == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("stage", ""),
        ("project", ""),
        ("filename", ""),
        ("link_href", ""),
        ("sha256", "A" * 64),
    ],
)
def test_candidate_rejects_unusable_metadata(field, value) -> None:
    with pytest.raises(ValueError):
        candidate(**{field: value})


def test_xom_accessor_returns_only_the_registered_sink(tmp_path) -> None:
    xom = SimpleNamespace()
    sink = FileDiscoverySink(tmp_path, now=lambda: NOW)

    with pytest.raises(DiscoveryUnavailable):
        get_discovery_sink(xom)

    set_discovery_sink(xom, sink)

    assert get_discovery_sink(xom) is sink


def test_sink_maps_storage_failure_to_discovery_unavailable(tmp_path) -> None:
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")

    with pytest.raises(DiscoveryUnavailable):
        FileDiscoverySink(blocked).discover(candidate())


def test_discovery_lease_token_fences_stale_same_worker_claim(tmp_path) -> None:
    clock = [NOW]
    sink = FileDiscoverySink(tmp_path, now=lambda: clock[0])
    sink.discover(candidate())
    first = sink.claim_next("worker-1", NOW + timedelta(seconds=5))
    assert first is not None

    clock[0] += timedelta(seconds=6)
    assert sink.recover_expired_claims() == 1
    second = sink.claim_next("worker-1", clock[0] + timedelta(seconds=5))
    assert second is not None
    assert first.lease_token != second.lease_token

    with pytest.raises(DiscoveryUnavailable):
        sink.complete(first)
    with pytest.raises(DiscoveryUnavailable):
        sink.fail(first, "stale")
    with pytest.raises(DiscoveryUnavailable):
        sink.retry(first, "stale")

    sink.complete(second)
    assert sink.count("COMPLETED") == 1


def test_discovery_lease_rejects_forged_worker_and_token(tmp_path) -> None:
    sink = FileDiscoverySink(tmp_path, now=lambda: NOW)
    sink.discover(candidate())
    claim = sink.claim_next("worker-1", NOW + timedelta(minutes=5))
    assert claim is not None

    forged_worker = replace(claim, worker_id="worker-2")
    forged_token = replace(claim, lease_token="0" * 64)
    with pytest.raises(DiscoveryUnavailable):
        sink.complete(forged_worker)
    with pytest.raises(DiscoveryUnavailable):
        sink.complete(forged_token)
    sink.complete(claim)


def test_expired_claim_operations_are_fenced_until_recovery(tmp_path) -> None:
    clock = [NOW]
    sink = FileDiscoverySink(tmp_path, now=lambda: clock[0])
    sink.discover(candidate())
    claim = sink.claim_next("worker-1", NOW + timedelta(seconds=5))
    assert claim is not None
    clock[0] = claim.lease_expires_at

    for operation in (
        lambda: sink.complete(claim),
        lambda: sink.fail(claim, "late"),
        lambda: sink.retry(claim, "late"),
    ):
        with pytest.raises(DiscoveryUnavailable):
            operation()
    assert sink.count("PROCESSING") == 1


def test_claim_expiry_identity_is_fenced_even_before_stored_expiry(tmp_path) -> None:
    sink = FileDiscoverySink(tmp_path, now=lambda: NOW)
    sink.discover(candidate())
    claim = sink.claim_next("worker-1", NOW + timedelta(minutes=5))
    assert claim is not None
    forged = replace(claim, lease_expires_at=claim.lease_expires_at + timedelta(microseconds=1))

    with pytest.raises(DiscoveryUnavailable):
        sink.complete(forged)
    sink.complete(claim)


@pytest.mark.parametrize(
    "column", ["job_id", "candidate_json", "lease_expires_at", "lease_owner", "lease_token"]
)
def test_recovery_quarantines_corrupt_processing_rows(tmp_path, column) -> None:
    clock = [NOW]
    sink = FileDiscoverySink(tmp_path, now=lambda: clock[0])
    sink.discover(candidate())
    claim = sink.claim_next("worker-1", NOW + timedelta(seconds=5))
    assert claim is not None
    values = {
        "job_id": None,
        "candidate_json": "not-json",
        "lease_expires_at": "not-a-time",
        "lease_owner": "",
        "lease_token": "bad-token",
    }
    with sqlite3.connect(sink.path) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            f"UPDATE discovery_jobs SET {column} = ? WHERE job_id = ?",
            (values[column], claim.job_id),
        )
        connection.commit()
    clock[0] = NOW + timedelta(minutes=1)

    assert sink.recover_expired_claims() == 1
    assert sink.count("FAILED") == 1
    assert sink.count("PROCESSING") == 0


def test_incompatible_preexisting_discovery_schema_fails_closed(tmp_path) -> None:
    path = tmp_path / "discovery.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE discovery_jobs (job_id TEXT PRIMARY KEY, state TEXT NOT NULL)"
        )
        connection.commit()

    with pytest.raises(DiscoveryUnavailable, match=r"incompatible.*lease_token"):
        FileDiscoverySink(tmp_path)


@pytest.mark.parametrize("missing", ["last_error", "created_at", "updated_at"])
def test_discovery_rejects_any_incomplete_preexisting_schema(tmp_path, missing) -> None:
    columns = {
        "job_id": "TEXT PRIMARY KEY",
        "candidate_json": "TEXT NOT NULL",
        "state": "TEXT NOT NULL",
        "attempt_count": "INTEGER NOT NULL",
        "available_at": "TEXT NOT NULL",
        "lease_owner": "TEXT",
        "lease_expires_at": "TEXT",
        "lease_token": "TEXT",
        "last_error": "TEXT",
        "created_at": "TEXT NOT NULL",
        "updated_at": "TEXT NOT NULL",
    }
    columns.pop(missing)
    definition = ", ".join(f"{name} {spec}" for name, spec in columns.items())
    path = tmp_path / "discovery.db"
    with sqlite3.connect(path) as connection:
        connection.execute(f"CREATE TABLE discovery_jobs ({definition})")
        connection.commit()

    with pytest.raises(DiscoveryUnavailable, match=rf"incompatible.*{missing}"):
        FileDiscoverySink(tmp_path)


def test_discovery_rejects_constraintless_catalog(tmp_path) -> None:
    columns = (
        "job_id TEXT, candidate_json TEXT, state TEXT, attempt_count INTEGER, "
        "available_at TEXT, lease_owner TEXT, lease_expires_at TEXT, lease_token TEXT, "
        "last_error TEXT, created_at TEXT, updated_at TEXT"
    )
    with sqlite3.connect(tmp_path / "discovery.db") as connection:
        connection.execute(f"CREATE TABLE discovery_jobs ({columns})")
        connection.commit()

    with pytest.raises(DiscoveryUnavailable, match="incompatible"):
        FileDiscoverySink(tmp_path)


def test_discovery_catalog_has_ready_and_unique_lease_indexes(tmp_path) -> None:
    sink = FileDiscoverySink(tmp_path, now=lambda: NOW)
    with sqlite3.connect(sink.path) as connection:
        indexes = connection.execute("PRAGMA index_list(discovery_jobs)").fetchall()
        names = {row[1] for row in indexes}
    assert "discovery_jobs_ready_idx" in names
    assert "discovery_jobs_processing_lease_idx" in names
    assert any(row[2] == 1 for row in indexes if row[1] == "discovery_jobs_processing_lease_idx")


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("candidate_json", "not-json"),
        ("available_at", "not-a-time"),
        ("attempt_count", -1),
        ("lease_owner", "unexpected-owner"),
    ],
)
def test_corrupt_head_is_failed_and_valid_job_can_be_claimed(tmp_path, column, value) -> None:
    sink = FileDiscoverySink(tmp_path, now=lambda: NOW)
    corrupt = candidate(project="aaa")
    sink.discover(corrupt)
    sink.discover(candidate(project="valid"))
    with sqlite3.connect(sink.path) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            f"UPDATE discovery_jobs SET {column} = ? WHERE job_id = ?",
            (value, _job_id_for_test(corrupt)),
        )
        connection.execute(
            "UPDATE discovery_jobs SET created_at = ?, updated_at = ? WHERE job_id = ?",
            ("2026-08-23T01:02:03+00:00", "2026-08-23T01:02:03+00:00", _job_id_for_test(corrupt)),
        )
        connection.commit()

    claim = sink.claim_next("worker-1", NOW + timedelta(minutes=5))

    assert claim is not None
    assert claim.candidate.project == "valid"
    assert sink.count("FAILED") == 1


def test_claim_query_is_bounded_to_eligible_rows(tmp_path) -> None:
    sink = FileDiscoverySink(tmp_path, now=lambda: NOW)
    sink.discover(candidate())
    traces: list[str] = []
    original_connect = sink._connect

    def tracked_connect():
        connection = original_connect()
        connection.set_trace_callback(traces.append)
        return connection

    sink._connect = tracked_connect
    assert sink.claim_next("worker-1", NOW + timedelta(minutes=5)) is not None
    claim_sql = "\n".join(traces)
    assert "available_at <=" in claim_sql
    assert "LIMIT 64" in claim_sql


def _job_id_for_test(item: DiscoveryCandidate) -> str:
    payload = json.dumps(
        {
            "filename": item.filename,
            "link_href": item.link_href,
            "project": item.project,
            "sha256": item.sha256,
            "stage": item.stage,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    import hashlib

    return hashlib.sha256(payload.encode()).hexdigest()
