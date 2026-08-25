from __future__ import annotations

import json
import math
import sqlite3
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from devpi_guardian.admin.views import _response
from devpi_guardian.verdicts.db import ConnectionFactory, migrate
from devpi_guardian.verdicts.errors import (
    ArtifactNotFound,
    InvalidSha256,
    StoreUnavailable,
    TransitionConflict,
)
from devpi_guardian.verdicts.models import (
    ArtifactState,
    ClaimedArtifact,
    Decision,
    EvidenceInput,
    VerdictInput,
)
from devpi_guardian.verdicts.store import SQLiteArtifactStore
from tests.verdicts.test_store_claims import SHA as SHA256
from tests.verdicts.test_store_claims import (
    WrappingFactory,
    artifact,
    fetchall,
    make_store,
    release,
)

NOW = datetime(2026, 8, 17, 0, 0, tzinfo=UTC)
BASELINE_SHA256 = "b" * 64
MISSING_SHA256 = "c" * 64


class DerivedTier(str):
    pass


def verdict(**changes: Any) -> VerdictInput:
    values = {
        "sha256": SHA256,
        "decision": Decision.REVIEW,
        "score": 40.0,
        "policy_version": "policy-1",
        "analyzer_version": "analyzer-1",
        "baseline_sha256": None,
        "baseline_tier": None,
        "created_at": NOW,
    }
    values.update(changes)
    return VerdictInput(**values)


def evidence(**changes: Any) -> EvidenceInput:
    values = {
        "rule_id": "new-network-call",
        "action": Decision.REVIEW,
        "file_path": "demo/client.py",
        "line": 12,
        "message": "new outbound request",
        "details": {"callee": "requests.post"},
    }
    values.update(changes)
    return EvidenceInput(**values)


def unchecked_verdict(**changes: Any) -> VerdictInput:
    valid = verdict()
    values = {
        "sha256": valid.sha256,
        "decision": valid.decision,
        "score": valid.score,
        "policy_version": valid.policy_version,
        "analyzer_version": valid.analyzer_version,
        "baseline_sha256": valid.baseline_sha256,
        "baseline_tier": valid.baseline_tier,
        "created_at": valid.created_at,
        "cooldown_until": valid.cooldown_until,
    }
    values.update(changes)
    value = object.__new__(VerdictInput)
    for field_name, field_value in values.items():
        object.__setattr__(value, field_name, field_value)
    return value


def unchecked_verdict_without_cooldown_slot() -> VerdictInput:
    valid = verdict()
    value = object.__new__(VerdictInput)
    for field_name in (
        "sha256",
        "decision",
        "score",
        "policy_version",
        "analyzer_version",
        "baseline_sha256",
        "baseline_tier",
        "created_at",
    ):
        object.__setattr__(value, field_name, getattr(valid, field_name))
    return value


def unchecked_evidence(**changes: Any) -> EvidenceInput:
    valid = evidence()
    values = {
        "rule_id": valid.rule_id,
        "action": valid.action,
        "file_path": valid.file_path,
        "line": valid.line,
        "message": valid.message,
        "details": valid.details,
    }
    values.update(changes)
    value = object.__new__(EvidenceInput)
    for field_name, field_value in values.items():
        object.__setattr__(value, field_name, field_value)
    return value


def claim_input(**changes: Any) -> ClaimedArtifact:
    values = {
        "sha256": SHA256,
        "size_bytes": 123,
        "worker_id": "worker",
        "lease_expires_at": NOW + timedelta(minutes=5),
        "lease_token": "d" * 64,
    }
    values.update(changes)
    return ClaimedArtifact(**values)


def unchecked_claim(**changes: Any) -> ClaimedArtifact:
    valid = claim_input()
    values = {
        "sha256": valid.sha256,
        "size_bytes": valid.size_bytes,
        "worker_id": valid.worker_id,
        "lease_expires_at": valid.lease_expires_at,
        "lease_token": valid.lease_token,
    }
    values.update(changes)
    value = object.__new__(ClaimedArtifact)
    for field_name, field_value in values.items():
        object.__setattr__(value, field_name, field_value)
    return value


def prepare_scanning(
    tmp_path,
    audit_writer,
) -> tuple[SQLiteArtifactStore, ClaimedArtifact]:
    store = make_store(tmp_path, audit_writer, now=lambda: NOW)
    store.discover_artifact(artifact(), release())
    claimed = store.claim_next("worker", NOW + timedelta(minutes=5))
    assert claimed is not None
    audit_writer.events.clear()
    return store, claimed


def install_trigger(store: SQLiteArtifactStore, sql: str) -> None:
    with closing(store.connection_factory.connect()) as connection, connection:
        connection.execute(sql)


def assert_scanning_without_verdict(
    store: SQLiteArtifactStore,
    claim: ClaimedArtifact,
) -> None:
    row = fetchall(
        store,
        """
        SELECT state, lease_owner, lease_expires_at, lease_token, last_error
        FROM artifacts WHERE sha256 = ?
        """,
        (SHA256,),
    )[0]
    assert tuple(row) == (
        ArtifactState.SCANNING.value,
        "worker",
        (NOW + timedelta(minutes=5)).isoformat(),
        claim.lease_token,
        None,
    )
    assert fetchall(store, "SELECT COUNT(*) FROM verdicts")[0][0] == 0
    assert fetchall(store, "SELECT COUNT(*) FROM evidence")[0][0] == 0


class NeverConnectFactory:
    def __init__(self, path: Path) -> None:
        self.path = path

    def connect(self):
        raise AssertionError("invalid input opened SQLite")


def test_record_verdict_persists_current_verdict_evidence_and_terminal_state(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    created_at = datetime(
        2026,
        8,
        17,
        9,
        30,
        tzinfo=timezone(timedelta(hours=9)),
    )

    store.record_verdict(
        claim,
        verdict(created_at=created_at),
        [
            evidence(
                details={
                    "z": [2, 1],
                    "a": {"enabled": True},
                    "sha256": {"value": "https://user:secret@example.invalid/a.whl"},
                    "baseline_sha256": ["https://user:secret@example.invalid/a.whl"],
                }
            )
        ],
    )

    artifact_row = fetchall(
        store,
        """
        SELECT state, lease_owner, lease_expires_at, lease_token, last_error,
               updated_at
        FROM artifacts WHERE sha256 = ?
        """,
        (SHA256,),
    )[0]
    assert tuple(artifact_row) == (
        ArtifactState.REVIEW.value,
        None,
        None,
        None,
        None,
        NOW.isoformat(),
    )
    verdict_row = fetchall(
        store,
        """
        SELECT sha256, decision, score, policy_version, analyzer_version,
               baseline_sha256, is_current, created_at
        FROM verdicts
        """,
    )[0]
    assert tuple(verdict_row) == (
        SHA256,
        Decision.REVIEW.value,
        40.0,
        "policy-1",
        "analyzer-1",
        None,
        1,
        NOW.replace(hour=0, minute=30).isoformat(),
    )
    evidence_row = fetchall(
        store,
        """
        SELECT rule_id, action, file_path, line, message, details_json
        FROM evidence
        """,
    )[0]
    assert tuple(evidence_row) == (
        "new-network-call",
        Decision.REVIEW.value,
        "demo/client.py",
        12,
        "new outbound request",
        '{"a":{"enabled":true},"baseline_sha256":["[URL]"],"sha256":{"value":"[URL]"},"z":[2,1]}',
    )


def test_record_allow_verdict_persists_cooldown_window(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    cooldown_until = NOW + timedelta(hours=24)

    store.record_verdict(
        claim,
        verdict(decision=Decision.ALLOW, cooldown_until=cooldown_until),
        (),
    )

    row = fetchall(
        store,
        "SELECT state, cooldown_started_at, cooldown_until FROM artifacts",
    )[0]
    assert tuple(row) == (
        ArtifactState.ALLOW.value,
        NOW.isoformat(),
        cooldown_until.isoformat(),
    )


@pytest.mark.parametrize(
    ("decision", "effective"),
    [
        (Decision.ALLOW, Decision.ALLOW),
        (Decision.REVIEW, Decision.DENY),
        (Decision.DENY, Decision.DENY),
    ],
)
def test_record_verdict_audits_effective_transition_and_versions(
    tmp_path,
    audit_writer,
    decision,
    effective,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)

    store.record_verdict(claim, verdict(decision=decision), ())

    assert len(audit_writer.events) == 1
    event = audit_writer.events[0]
    assert (
        event.actor,
        event.action,
        event.sha256,
        event.previous_decision,
        event.new_decision,
        event.reason,
        event.policy_version,
        event.analyzer_version,
        event.occurred_at,
    ) == (
        "guardian-policy",
        "artifact.verdict_recorded",
        SHA256,
        Decision.DENY,
        effective,
        "automated policy decision",
        "policy-1",
        "analyzer-1",
        NOW,
    )


def test_record_verdict_requires_existing_scanning_artifact(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer, now=lambda: NOW)
    store.discover_artifact(artifact(), release())
    audit_writer.events.clear()

    with pytest.raises(TransitionConflict):
        store.record_verdict(claim_input(), verdict(), ())
    with pytest.raises(TransitionConflict):
        missing_claim = claim_input(sha256=MISSING_SHA256)
        store.record_verdict(
            missing_claim,
            verdict(sha256=MISSING_SHA256),
            (),
        )

    assert fetchall(store, "SELECT COUNT(*) FROM verdicts")[0][0] == 0
    row = fetchall(
        store,
        "SELECT state FROM artifacts WHERE sha256 = ?",
        (SHA256,),
    )[0]
    assert row[0] == ArtifactState.DISCOVERED.value
    assert audit_writer.events == []


def test_duplicate_verdict_submission_rolls_back_cleanly(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    store.record_verdict(claim, verdict(decision=Decision.ALLOW), ())
    original_events = list(audit_writer.events)

    with pytest.raises(TransitionConflict):
        store.record_verdict(
            claim,
            verdict(decision=Decision.DENY),
            [evidence()],
        )

    row = fetchall(
        store,
        "SELECT decision, is_current FROM verdicts WHERE sha256 = ?",
        (SHA256,),
    )[0]
    assert tuple(row) == (Decision.ALLOW.value, 1)
    assert fetchall(store, "SELECT COUNT(*) FROM verdicts")[0][0] == 1
    assert fetchall(store, "SELECT COUNT(*) FROM evidence")[0][0] == 0
    assert audit_writer.events == original_events


def test_racing_verdict_submissions_have_one_winner(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)

    def submit(decision: Decision) -> Decision | None:
        try:
            store.record_verdict(claim, verdict(decision=decision), ())
        except TransitionConflict:
            return None
        return decision

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(submit, (Decision.ALLOW, Decision.DENY)))

    assert len([result for result in results if result is not None]) == 1
    assert fetchall(store, "SELECT COUNT(*) FROM verdicts")[0][0] == 1
    assert len(audit_writer.events) == 1


def test_recovered_claim_cannot_complete_a_later_claim(
    tmp_path,
    audit_writer,
) -> None:
    clock = [NOW]
    store = make_store(tmp_path, audit_writer, now=lambda: clock[0])
    store.discover_artifact(artifact(), release())
    claim_a = store.claim_next("worker-a", NOW + timedelta(minutes=1))
    assert claim_a is not None
    clock[0] = NOW + timedelta(minutes=2)
    assert store.recover_expired_claims(clock[0]) == 1
    claim_b = store.claim_next("worker-b", NOW + timedelta(minutes=5))
    assert claim_b is not None
    audit_writer.events.clear()

    with pytest.raises(TransitionConflict):
        store.record_verdict(claim_a, verdict(), ())

    row = fetchall(
        store,
        """
        SELECT state, lease_owner, lease_expires_at, lease_token
        FROM artifacts
        """,
    )[0]
    assert tuple(row) == (
        ArtifactState.SCANNING.value,
        claim_b.worker_id,
        claim_b.lease_expires_at.isoformat(),
        claim_b.lease_token,
    )
    assert fetchall(store, "SELECT COUNT(*) FROM verdicts")[0][0] == 0
    assert audit_writer.events == []

    store.record_verdict(claim_b, verdict(), ())

    completed = fetchall(
        store,
        """
        SELECT state, lease_owner, lease_expires_at, lease_token
        FROM artifacts
        """,
    )[0]
    assert tuple(completed) == (ArtifactState.REVIEW.value, None, None, None)
    assert fetchall(store, "SELECT COUNT(*) FROM verdicts")[0][0] == 1
    assert len(audit_writer.events) == 1


def test_recovered_claim_cannot_mark_a_later_claim_as_error(
    tmp_path,
    audit_writer,
) -> None:
    clock = [NOW]
    store = make_store(tmp_path, audit_writer, now=lambda: clock[0])
    store.discover_artifact(artifact(), release())
    claim_a = store.claim_next("worker-a", NOW + timedelta(minutes=1))
    assert claim_a is not None
    clock[0] = NOW + timedelta(minutes=2)
    assert store.recover_expired_claims(clock[0]) == 1
    claim_b = store.claim_next("worker-b", NOW + timedelta(minutes=5))
    assert claim_b is not None
    audit_writer.events.clear()

    with pytest.raises(TransitionConflict):
        store.mark_analysis_error(claim_a, "late analysis failure")

    row = fetchall(
        store,
        """
        SELECT state, size_bytes, lease_owner, lease_expires_at, lease_token,
               last_error
        FROM artifacts
        """,
    )[0]
    assert tuple(row) == (
        ArtifactState.SCANNING.value,
        claim_b.size_bytes,
        claim_b.worker_id,
        claim_b.lease_expires_at.isoformat(),
        claim_b.lease_token,
        None,
    )
    assert audit_writer.events == []


@pytest.mark.parametrize("operation", ["verdict", "error"])
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sha256", MISSING_SHA256),
        ("size_bytes", 124),
        ("worker_id", "forged-worker"),
        ("lease_expires_at", NOW + timedelta(minutes=4)),
        ("lease_token", "c" * 64),
    ],
)
def test_completion_rejects_forged_claim_fields_without_side_effects(
    tmp_path,
    audit_writer,
    operation,
    field,
    value,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    forged = replace(claim, **{field: value})

    with pytest.raises(TransitionConflict) as error:
        if operation == "verdict":
            store.record_verdict(
                forged,
                verdict(sha256=forged.sha256),
                (),
            )
        else:
            store.mark_analysis_error(forged, "failed")

    assert forged.lease_token not in str(error.value)
    assert_scanning_without_verdict(store, claim)
    assert audit_writer.events == []


@pytest.mark.parametrize("operation", ["verdict", "error"])
def test_completion_rejects_expired_current_claim_without_side_effects(
    tmp_path,
    audit_writer,
    operation,
) -> None:
    clock = [NOW]
    store = make_store(tmp_path, audit_writer, now=lambda: clock[0])
    store.discover_artifact(artifact(), release())
    claim = store.claim_next("worker", NOW + timedelta(minutes=1))
    assert claim is not None
    audit_writer.events.clear()
    clock[0] = claim.lease_expires_at

    with pytest.raises(TransitionConflict):
        if operation == "verdict":
            store.record_verdict(claim, verdict(), ())
        else:
            store.mark_analysis_error(claim, "failed")

    row = fetchall(
        store,
        """
        SELECT state, size_bytes, lease_owner, lease_expires_at, lease_token,
               last_error
        FROM artifacts
        """,
    )[0]
    assert tuple(row) == (
        ArtifactState.SCANNING.value,
        claim.size_bytes,
        claim.worker_id,
        claim.lease_expires_at.isoformat(),
        claim.lease_token,
        None,
    )
    assert fetchall(store, "SELECT COUNT(*) FROM verdicts")[0][0] == 0
    assert audit_writer.events == []


def test_record_verdict_preserves_history_and_replaces_only_current_marker(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    with closing(store.connection_factory.connect()) as connection, connection:
        old_cursor = connection.execute(
            """
            INSERT INTO verdicts(
                sha256, decision, score, policy_version, analyzer_version,
                baseline_sha256, is_current, created_at
            ) VALUES (?, 'DENY', 99, 'policy-old', 'analyzer-old', NULL, 1, ?)
            """,
            (SHA256, (NOW - timedelta(days=1)).isoformat()),
        )
        connection.execute(
            """
            INSERT INTO evidence(
                verdict_id, rule_id, action, file_path, line, message,
                details_json
            ) VALUES (?, 'old-rule', 'DENY', NULL, NULL, 'old evidence', '{}')
            """,
            (old_cursor.lastrowid,),
        )

    store.record_verdict(
        claim,
        verdict(decision=Decision.REVIEW),
        [evidence()],
    )

    verdict_rows = fetchall(
        store,
        """
        SELECT decision, score, policy_version, analyzer_version, is_current
        FROM verdicts ORDER BY id
        """,
    )
    assert [tuple(row) for row in verdict_rows] == [
        (Decision.DENY.value, 99.0, "policy-old", "analyzer-old", 0),
        (Decision.REVIEW.value, 40.0, "policy-1", "analyzer-1", 1),
    ]
    evidence_rows = fetchall(
        store,
        "SELECT rule_id, message FROM evidence ORDER BY id",
    )
    assert [tuple(row) for row in evidence_rows] == [
        ("old-rule", "old evidence"),
        ("new-network-call", "new outbound request"),
    ]


@pytest.mark.parametrize(
    "baseline_tier",
    ["same_tag", "universal_wheel", "sdist"],
)
def test_record_verdict_persists_existing_baseline_foreign_key(
    tmp_path,
    audit_writer,
    baseline_tier,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    store.discover_artifact(
        artifact(sha256=BASELINE_SHA256),
        release(
            sha256=BASELINE_SHA256,
            version="0.9.0",
            filename="demo_package-0.9.0.whl",
        ),
    )
    audit_writer.events.clear()

    store.record_verdict(
        claim,
        verdict(baseline_sha256=BASELINE_SHA256, baseline_tier=baseline_tier),
        (),
    )

    row = fetchall(
        store,
        "SELECT baseline_sha256, baseline_tier FROM verdicts",
    )[0]
    assert tuple(row) == (BASELINE_SHA256, baseline_tier)


def test_record_verdict_rejects_missing_baseline_without_changes(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)

    with pytest.raises(ArtifactNotFound):
        store.record_verdict(
            claim,
            verdict(baseline_sha256=BASELINE_SHA256, baseline_tier="same_tag"),
            (),
        )

    assert_scanning_without_verdict(store, claim)
    assert audit_writer.events == []


@pytest.mark.parametrize("operation", ["verdict", "error"])
def test_completion_requires_exact_claim_dto_before_connecting(
    tmp_path,
    audit_writer,
    operation,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(ValueError, match="ClaimedArtifact"):
        if operation == "verdict":
            store.record_verdict(object(), verdict(), ())
        else:
            store.mark_analysis_error(object(), "failed")

    assert audit_writer.events == []


@pytest.mark.parametrize("operation", ["verdict", "error"])
@pytest.mark.parametrize(
    ("changes", "error_type"),
    [
        ({"sha256": "A" * 64}, InvalidSha256),
        ({"size_bytes": True}, ValueError),
        ({"size_bytes": -1}, ValueError),
        ({"size_bytes": 2**63}, ValueError),
        ({"worker_id": None}, ValueError),
        ({"worker_id": " "}, ValueError),
        ({"worker_id": "worker\x00unsafe"}, ValueError),
        ({"worker_id": "w" * 4097}, ValueError),
        ({"lease_expires_at": NOW.replace(tzinfo=None)}, ValueError),
        ({"lease_expires_at": "2026-08-17"}, ValueError),
        ({"lease_token": None}, ValueError),
        ({"lease_token": "D" * 64}, ValueError),
        ({"lease_token": "d" * 63}, ValueError),
        ({"lease_token": "g" * 64}, ValueError),
    ],
)
def test_completion_validates_mutated_claim_before_connecting(
    tmp_path,
    audit_writer,
    operation,
    changes,
    error_type,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(error_type):
        if operation == "verdict":
            store.record_verdict(unchecked_claim(**changes), verdict(), ())
        else:
            store.mark_analysis_error(unchecked_claim(**changes), "failed")

    assert audit_writer.events == []


def test_record_verdict_rejects_claim_verdict_sha_mismatch_before_connecting(
    tmp_path,
    audit_writer,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(TransitionConflict):
        store.record_verdict(
            claim_input(sha256=MISSING_SHA256),
            verdict(),
            (),
        )

    assert audit_writer.events == []


@pytest.mark.parametrize(
    ("changes", "error_type"),
    [
        ({"sha256": "A" * 64}, InvalidSha256),
        ({"decision": "ALLOW"}, ValueError),
        ({"score": True}, ValueError),
        ({"score": math.nan}, ValueError),
        ({"score": "40"}, ValueError),
        ({"score": 2**2000}, ValueError),
        ({"policy_version": None}, ValueError),
        ({"policy_version": " "}, ValueError),
        ({"policy_version": "policy\x00unsafe"}, ValueError),
        ({"policy_version": "p" * 4097}, ValueError),
        ({"analyzer_version": None}, ValueError),
        ({"analyzer_version": "a" * 4097}, ValueError),
        ({"baseline_sha256": "invalid"}, InvalidSha256),
        ({"baseline_tier": "same_tag"}, ValueError),
        ({"baseline_sha256": BASELINE_SHA256}, ValueError),
        (
            {"baseline_sha256": BASELINE_SHA256, "baseline_tier": "unknown"},
            ValueError,
        ),
        (
            {"baseline_sha256": BASELINE_SHA256, "baseline_tier": 1},
            ValueError,
        ),
        (
            {
                "baseline_sha256": BASELINE_SHA256,
                "baseline_tier": DerivedTier("same_tag"),
            },
            ValueError,
        ),
        ({"created_at": NOW.replace(tzinfo=None)}, ValueError),
        ({"created_at": "2026-08-17"}, ValueError),
    ],
)
def test_record_verdict_validates_mutated_dto_before_connecting(
    tmp_path,
    audit_writer,
    changes,
    error_type,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(error_type):
        store.record_verdict(
            claim_input(),
            unchecked_verdict(**changes),
            (),
        )

    assert audit_writer.events == []


def test_record_verdict_requires_exact_verdict_dto_before_connecting(
    tmp_path,
    audit_writer,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(ValueError, match="VerdictInput"):
        store.record_verdict(claim_input(), object(), ())


def test_record_verdict_rejects_forged_dto_missing_cooldown_slot(
    tmp_path,
    audit_writer,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(ValueError, match="VerdictInput missing required fields"):
        store.record_verdict(
            claim_input(),
            unchecked_verdict_without_cooldown_slot(),
            (),
        )

    assert audit_writer.events == []


@pytest.mark.parametrize("bad_evidence", [None, "text", b"bytes", 123])
def test_record_verdict_rejects_non_sequence_evidence_before_connecting(
    tmp_path,
    audit_writer,
    bad_evidence,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(ValueError, match="sequence"):
        store.record_verdict(claim_input(), verdict(), bad_evidence)


def test_record_verdict_rejects_iterator_evidence_before_connecting(
    tmp_path,
    audit_writer,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )
    iterator: Iterator[EvidenceInput] = iter([evidence()])

    with pytest.raises(ValueError, match="sequence"):
        store.record_verdict(claim_input(), verdict(), iterator)


def test_record_verdict_requires_actual_evidence_dto_before_connecting(
    tmp_path,
    audit_writer,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(ValueError, match="EvidenceInput"):
        store.record_verdict(claim_input(), verdict(), [{}])


@pytest.mark.parametrize(
    "changes",
    [
        {"rule_id": None},
        {"rule_id": " "},
        {"rule_id": "rule\x00unsafe"},
        {"rule_id": "r" * 4097},
        {"action": "REVIEW"},
        {"file_path": 123},
        {"file_path": " "},
        {"file_path": "path\x00unsafe"},
        {"file_path": "p" * 4097},
        {"line": True},
        {"line": 0},
        {"line": 1.5},
        {"line": 2**63},
        {"message": None},
        {"message": " "},
        {"message": "message\x00unsafe"},
        {"message": "m" * 4097},
        {"details": {2: "non-string key"}},
        {"details": {"not_finite": math.inf}},
        {"details": {"unsupported": object()}},
    ],
)
def test_record_verdict_validates_mutated_evidence_before_connecting(
    tmp_path,
    audit_writer,
    changes,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(ValueError):
        store.record_verdict(
            claim_input(),
            verdict(),
            [unchecked_evidence(**changes)],
        )


def test_record_verdict_rejects_cyclic_evidence_details_before_connecting(
    tmp_path,
    audit_writer,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )
    details: dict[str, Any] = {}
    details["cycle"] = details

    with pytest.raises(ValueError, match="details"):
        store.record_verdict(
            claim_input(),
            verdict(),
            [unchecked_evidence(details=details)],
        )


def test_record_verdict_rejects_cycle_below_diagnostic_evidence_key_before_connecting(
    tmp_path,
    audit_writer,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )
    details: dict[str, Any] = {}
    cycle: dict[str, Any] = {}
    cycle["self"] = cycle
    details["message"] = cycle

    with pytest.raises(ValueError, match="details"):
        store.record_verdict(
            claim_input(),
            verdict(),
            [unchecked_evidence(details=details)],
        )


def test_record_verdict_redacts_nested_credential_fields_at_persistence_boundary(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    digest = "a" * 64

    store.record_verdict(
        claim,
        verdict(),
        [
            evidence(
                details={
                    "message": {
                        "client_secret": "nested-secret",
                        "sha256": digest,
                    }
                }
            )
        ],
    )

    details_json = fetchall(store, "SELECT details_json FROM evidence")[0][0]

    assert details_json == (f'{{"message":{{"client_secret":"[REDACTED]","sha256":"{digest}"}}}}')


def test_record_verdict_redacts_entire_evidence_details_at_persistence_boundary(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    digest = "a" * 64
    store.record_verdict(
        claim,
        verdict(),
        [
            evidence(
                details={
                    "path": "/Users/alice/My Secret/file.whl",
                    "url": "https://user:secret@example.invalid/a?token=query-secret",
                    "exception": "failed https://user:secret@example.invalid/a",
                    "sha256": digest,
                }
            )
        ],
    )

    details_json = fetchall(store, "SELECT details_json FROM evidence")[0][0]
    details = json.loads(details_json)

    assert details == {
        "exception": "failed [URL]",
        "path": "[PATH]",
        "sha256": digest,
        "url": "[URL]",
    }


@pytest.mark.parametrize(
    "trigger_sql",
    [
        """
        CREATE TRIGGER ignore_verdict_insert BEFORE INSERT ON verdicts
        BEGIN SELECT RAISE(IGNORE); END
        """,
        """
        CREATE TRIGGER ignore_evidence_insert BEFORE INSERT ON evidence
        BEGIN SELECT RAISE(IGNORE); END
        """,
        """
        CREATE TRIGGER ignore_terminal_update
        BEFORE UPDATE OF state ON artifacts
        WHEN OLD.state = 'SCANNING'
        BEGIN SELECT RAISE(IGNORE); END
        """,
    ],
)
def test_record_verdict_rejects_ignored_state_changing_writes(
    tmp_path,
    audit_writer,
    trigger_sql,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    install_trigger(store, trigger_sql)

    with pytest.raises(TransitionConflict):
        store.record_verdict(claim, verdict(), [evidence()])

    assert_scanning_without_verdict(store, claim)
    assert audit_writer.events == []


def test_record_verdict_rejects_ignored_current_verdict_update(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    with closing(store.connection_factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO verdicts(
                sha256, decision, score, policy_version, analyzer_version,
                baseline_sha256, is_current, created_at
            ) VALUES (?, 'DENY', 99, 'policy-old', 'analyzer-old', NULL, 1, ?)
            """,
            (SHA256, (NOW - timedelta(days=1)).isoformat()),
        )
        connection.execute(
            """
            CREATE TRIGGER ignore_current_verdict_update
            BEFORE UPDATE OF is_current ON verdicts
            WHEN OLD.is_current = 1
            BEGIN SELECT RAISE(IGNORE); END
            """
        )

    with pytest.raises(TransitionConflict):
        store.record_verdict(claim, verdict(), ())

    rows = fetchall(store, "SELECT decision, is_current FROM verdicts")
    assert [tuple(row) for row in rows] == [(Decision.DENY.value, 1)]
    artifact_row = fetchall(
        store,
        "SELECT state, lease_owner FROM artifacts WHERE sha256 = ?",
        (SHA256,),
    )[0]
    assert tuple(artifact_row) == (ArtifactState.SCANNING.value, "worker")
    assert audit_writer.events == []


def test_record_verdict_checks_final_artifact_state(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    install_trigger(
        store,
        """
        CREATE TRIGGER rewrite_terminal_state
        AFTER UPDATE OF state ON artifacts
        WHEN NEW.state = 'ALLOW'
        BEGIN
            UPDATE artifacts SET state = 'DENY' WHERE sha256 = NEW.sha256;
        END
        """,
    )

    with pytest.raises(TransitionConflict):
        store.record_verdict(
            claim,
            verdict(decision=Decision.ALLOW),
            [evidence()],
        )

    assert_scanning_without_verdict(store, claim)
    assert audit_writer.events == []


def test_audit_failure_rolls_back_verdict_evidence_and_state(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    audit_writer.fail = True

    with pytest.raises(RuntimeError, match="audit unavailable"):
        store.record_verdict(claim, verdict(), [evidence()])

    assert_scanning_without_verdict(store, claim)


def test_commit_failure_rolls_back_verdict_evidence_and_state(
    tmp_path,
    audit_writer,
) -> None:
    base_factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(base_factory)
    base_store = SQLiteArtifactStore(
        base_factory,
        audit_writer,
        now=lambda: NOW,
    )
    base_store.discover_artifact(artifact(), release())
    claim = base_store.claim_next("worker", NOW + timedelta(minutes=5))
    assert claim is not None
    audit_writer.events.clear()
    wrapping_factory = WrappingFactory(base_factory, fail_commit=True)
    store = SQLiteArtifactStore(
        wrapping_factory,
        audit_writer,
        now=lambda: NOW,
    )

    with pytest.raises(StoreUnavailable) as error:
        store.record_verdict(claim, verdict(), [evidence()])

    assert isinstance(error.value.__cause__, sqlite3.OperationalError)
    assert str(error.value.__cause__) == "commit failed"
    assert wrapping_factory.last_connection.rollback_called is True
    with closing(base_factory.connect()) as connection:
        artifact_row = connection.execute(
            "SELECT state, lease_owner FROM artifacts WHERE sha256 = ?",
            (SHA256,),
        ).fetchone()
        verdict_query = "SELECT COUNT(*) FROM verdicts"
        evidence_query = "SELECT COUNT(*) FROM evidence"
        verdict_count = connection.execute(verdict_query).fetchone()[0]
        evidence_count = connection.execute(evidence_query).fetchone()[0]
    assert tuple(artifact_row) == (ArtifactState.SCANNING.value, "worker")
    assert verdict_count == 0
    assert evidence_count == 0


def test_unexpected_sqlite_error_recording_verdict_maps_to_store_unavailable(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    install_trigger(
        store,
        """
        CREATE TRIGGER abort_verdict_insert BEFORE INSERT ON verdicts
        BEGIN SELECT RAISE(ABORT, 'verdict storage failed'); END
        """,
    )

    with pytest.raises(StoreUnavailable) as error:
        store.record_verdict(claim, verdict(), ())

    assert isinstance(error.value.__cause__, sqlite3.IntegrityError)
    assert_scanning_without_verdict(store, claim)
    assert audit_writer.events == []


def test_analysis_error_is_terminal_sanitized_and_audited(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    raw_error = (
        "RuntimeError: origin=https://user:secret@example.invalid/pkg?token=query-secret "
        "credential=/Users/alice/private/file.whl "
        "X-Devpi-Auth: dXNlcjpzZWNyZXQ= Authorization: Bearer bearer-secret "
        "Authorization: Basic dXNlcjpwYXNz auth_token=secret-token "
        "client_secret=client-secret C:/Users/alice/private/file.whl sha256="
        + "a" * 64
        + "\nline two\x00\t"
        + "x" * 5000
        + "TAIL-SECRET"
    )

    store.mark_analysis_error(claim, raw_error)

    row = fetchall(
        store,
        """
        SELECT state, lease_owner, lease_expires_at, lease_token, last_error,
               updated_at
        FROM artifacts WHERE sha256 = ?
        """,
        (SHA256,),
    )[0]
    assert row["state"] == ArtifactState.ERROR.value
    assert row["lease_owner"] is None
    assert row["lease_expires_at"] is None
    assert row["lease_token"] is None
    assert row["updated_at"] == NOW.isoformat()
    assert len(row["last_error"]) == 4096
    assert "\n" not in row["last_error"]
    assert "\x00" not in row["last_error"]
    assert "\t" not in row["last_error"]
    assert "TAIL-SECRET" not in row["last_error"]
    assert "secret@example.invalid" not in row["last_error"]
    assert "query-secret" not in row["last_error"]
    assert "/Users/alice/private/file.whl" not in row["last_error"]
    assert "dXNlcjpzZWNyZXQ=" not in row["last_error"]
    assert "bearer-secret" not in row["last_error"]
    assert "dXNlcjpwYXNz" not in row["last_error"]
    assert "secret-token" not in row["last_error"]
    assert "client-secret" not in row["last_error"]
    assert "C:/Users/alice/private/file.whl" not in row["last_error"]
    assert "a" * 64 not in row["last_error"]

    response = _response({"artifact": {"last_error": row["last_error"]}})
    serialized = response.json_body["artifact"]["last_error"]
    assert "dXNlcjpzZWNyZXQ=" not in serialized
    assert "bearer-secret" not in serialized
    assert "dXNlcjpwYXNz" not in serialized
    assert "secret-token" not in serialized
    assert "client-secret" not in serialized
    assert "C:/Users/alice/private/file.whl" not in serialized
    assert len(audit_writer.events) == 1
    event = audit_writer.events[0]
    assert (
        event.actor,
        event.action,
        event.sha256,
        event.previous_decision,
        event.new_decision,
        event.reason,
        event.policy_version,
        event.analyzer_version,
        event.occurred_at,
    ) == (
        "guardian-worker",
        "artifact.analysis_error",
        SHA256,
        Decision.DENY,
        Decision.DENY,
        "analysis failed",
        None,
        None,
        NOW,
    )


def test_analysis_error_requires_existing_scanning_artifact(
    tmp_path,
    audit_writer,
) -> None:
    store = make_store(tmp_path, audit_writer, now=lambda: NOW)
    store.discover_artifact(artifact(), release())
    audit_writer.events.clear()

    with pytest.raises(TransitionConflict):
        store.mark_analysis_error(claim_input(), "failed")
    with pytest.raises(TransitionConflict):
        store.mark_analysis_error(
            claim_input(sha256=MISSING_SHA256),
            "failed",
        )

    row = fetchall(
        store,
        "SELECT state, last_error FROM artifacts WHERE sha256 = ?",
        (SHA256,),
    )[0]
    assert tuple(row) == (ArtifactState.DISCOVERED.value, None)
    assert audit_writer.events == []


@pytest.mark.parametrize(
    ("claim", "error_value", "error_type"),
    [
        (unchecked_claim(sha256="A" * 64), "failed", InvalidSha256),
        (claim_input(), None, ValueError),
        (claim_input(), 123, ValueError),
        (claim_input(), b"failed", ValueError),
    ],
)
def test_analysis_error_validates_inputs_before_connecting(
    tmp_path,
    audit_writer,
    claim,
    error_value,
    error_type,
) -> None:
    store = SQLiteArtifactStore(
        NeverConnectFactory(tmp_path / "never.db"),
        audit_writer,
    )

    with pytest.raises(error_type):
        store.mark_analysis_error(claim, error_value)

    assert audit_writer.events == []


def test_analysis_error_replaces_unsafe_unicode_deterministically(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)

    store.mark_analysis_error(claim, "bad\ud800value\x7f")

    row = fetchall(
        store,
        "SELECT last_error FROM artifacts WHERE sha256 = ?",
        (SHA256,),
    )[0]
    assert row[0] == "bad value "


def test_ignored_analysis_error_update_fails_closed(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    install_trigger(
        store,
        """
        CREATE TRIGGER ignore_analysis_error
        BEFORE UPDATE OF state ON artifacts
        WHEN NEW.state = 'ERROR'
        BEGIN SELECT RAISE(IGNORE); END
        """,
    )

    with pytest.raises(TransitionConflict):
        store.mark_analysis_error(claim, "failed")

    assert_scanning_without_verdict(store, claim)
    assert audit_writer.events == []


def test_analysis_error_checks_final_artifact_state(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    install_trigger(
        store,
        """
        CREATE TRIGGER rewrite_error_state
        AFTER UPDATE OF state ON artifacts
        WHEN NEW.state = 'ERROR'
        BEGIN
            UPDATE artifacts
            SET state = 'DISCOVERED', lease_owner = NULL,
                lease_expires_at = NULL, lease_token = NULL
            WHERE sha256 = NEW.sha256;
        END
        """,
    )

    with pytest.raises(TransitionConflict):
        store.mark_analysis_error(claim, "failed")

    assert_scanning_without_verdict(store, claim)
    assert audit_writer.events == []


def test_audit_failure_rolls_back_analysis_error(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    audit_writer.fail = True

    with pytest.raises(RuntimeError, match="audit unavailable"):
        store.mark_analysis_error(claim, "failed")

    assert_scanning_without_verdict(store, claim)


def test_commit_failure_rolls_back_analysis_error(
    tmp_path,
    audit_writer,
) -> None:
    base_factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(base_factory)
    base_store = SQLiteArtifactStore(
        base_factory,
        audit_writer,
        now=lambda: NOW,
    )
    base_store.discover_artifact(artifact(), release())
    claim = base_store.claim_next("worker", NOW + timedelta(minutes=5))
    assert claim is not None
    audit_writer.events.clear()
    wrapping_factory = WrappingFactory(base_factory, fail_commit=True)
    store = SQLiteArtifactStore(
        wrapping_factory,
        audit_writer,
        now=lambda: NOW,
    )

    with pytest.raises(StoreUnavailable) as error:
        store.mark_analysis_error(claim, "failed")

    assert isinstance(error.value.__cause__, sqlite3.OperationalError)
    assert str(error.value.__cause__) == "commit failed"
    assert wrapping_factory.last_connection.rollback_called is True
    with closing(base_factory.connect()) as connection:
        row = connection.execute(
            """
            SELECT state, lease_owner, lease_expires_at, lease_token,
                   last_error
            FROM artifacts WHERE sha256 = ?
            """,
            (SHA256,),
        ).fetchone()
    assert tuple(row) == (
        ArtifactState.SCANNING.value,
        "worker",
        (NOW + timedelta(minutes=5)).isoformat(),
        claim.lease_token,
        None,
    )


def test_unexpected_sqlite_error_marking_analysis_error_maps_to_unavailable(
    tmp_path,
    audit_writer,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    install_trigger(
        store,
        """
        CREATE TRIGGER abort_analysis_error
        BEFORE UPDATE OF state ON artifacts
        WHEN NEW.state = 'ERROR'
        BEGIN SELECT RAISE(ABORT, 'analysis error storage failed'); END
        """,
    )

    with pytest.raises(StoreUnavailable) as error:
        store.mark_analysis_error(claim, "failed")

    assert isinstance(error.value.__cause__, sqlite3.IntegrityError)
    assert_scanning_without_verdict(store, claim)
    assert audit_writer.events == []
