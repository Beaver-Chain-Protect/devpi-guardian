from datetime import UTC, datetime

import pytest

from devpi_guardian.verdicts.invariants import (
    PersistedStateCorruption,
    validate_persisted_state,
)

SHA256 = "a" * 64
NOW = datetime(2026, 8, 17, 0, 0, tzinfo=UTC)
CANONICAL_TIMESTAMP = NOW.isoformat()


def persisted_rows() -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    artifact: dict[str, object] = {
        "sha256": SHA256,
        "size_bytes": 1,
        "state": "REVIEW",
        "discovered_at": CANONICAL_TIMESTAMP,
        "updated_at": CANONICAL_TIMESTAMP,
        "lease_owner": None,
        "lease_expires_at": None,
        "lease_token": None,
        "last_error": None,
    }
    verdict: dict[str, object] = {
        "id": 1,
        "sha256": SHA256,
        "decision": "REVIEW",
        "score": 1.0,
        "policy_version": "policy-1",
        "analyzer_version": "analyzer-1",
        "baseline_sha256": None,
        "is_current": 1,
        "created_at": CANONICAL_TIMESTAMP,
    }
    override: dict[str, object] = {
        "id": 1,
        "sha256": SHA256,
        "decision": "ALLOW",
        "actor": "admin@example.test",
        "reason": "reviewed",
        "created_at": CANONICAL_TIMESTAMP,
        "expires_at": "2026-08-17T01:00:00+00:00",
        "is_current": 1,
    }
    return artifact, verdict, override


@pytest.mark.parametrize(
    ("row_name", "field_name", "timestamp"),
    [
        ("artifact", "discovered_at", "20260817T000000+00:00"),
        ("artifact", "updated_at", "2026-W33-1T00:00:00+00:00"),
        ("artifact", "lease_expires_at", "2026-08-17 01:00:00+00:00"),
        ("verdict", "created_at", "2026-08-17t00:00:00+00:00"),
        ("override", "created_at", "2026-08-17T09:00:00+09:00"),
        ("override", "expires_at", "2026-08-17T01:00:00"),
        ("override", "expires_at", "2026-08-17T01:00:00Z"),
    ],
)
def test_persisted_timestamp_must_use_writer_canonical_utc_form(
    row_name: str,
    field_name: str,
    timestamp: str,
) -> None:
    artifact, verdict, override = persisted_rows()
    rows = {
        "artifact": artifact,
        "verdict": verdict,
        "override": override,
    }
    if field_name == "lease_expires_at":
        artifact.update(
            state="SCANNING",
            lease_owner="worker",
            lease_expires_at="2026-08-17T01:00:00+00:00",
            lease_token="f" * 64,
        )
        override = None
    rows[row_name][field_name] = timestamp

    with pytest.raises(PersistedStateCorruption):
        validate_persisted_state(artifact, verdict, override, NOW)


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-08-17T00:00:00+00:00",
        "2026-08-17T00:00:00.123456+00:00",
    ],
)
def test_writer_canonical_utc_timestamps_are_valid(timestamp: str) -> None:
    artifact, verdict, override = persisted_rows()
    artifact["discovered_at"] = timestamp
    artifact["updated_at"] = timestamp
    verdict["created_at"] = timestamp
    override["created_at"] = timestamp

    context = validate_persisted_state(artifact, verdict, override, NOW)

    assert context.current_override_id == 1
