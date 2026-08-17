from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest

from devpi_guardian.verdicts.db import ConnectionFactory, migrate
from devpi_guardian.verdicts.errors import InvalidSha256, StoreUnavailable
from devpi_guardian.verdicts.models import (
    ArtifactState,
    Decision,
    DecisionSource,
)
from devpi_guardian.verdicts.reader import SQLiteVerdictReader

SHA_ALLOW = "a" * 64
SHA_REVIEW = "b" * 64
SHA_MISSING = "c" * 64
NOW = datetime(2026, 8, 17, 0, 0, tzinfo=UTC)


def seed_artifact(
    factory: ConnectionFactory,
    sha256: str,
    state: ArtifactState,
    automated: tuple[Decision, str] | None = None,
    manual: Decision | None = None,
    expires: datetime | None = None,
    *,
    expires_text: str | None = None,
) -> None:
    timestamp = NOW.isoformat()
    lease_values = (
        ("worker", (NOW + timedelta(minutes=10)).isoformat())
        if state is ArtifactState.SCANNING
        else (None, None)
    )
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at,
                lease_owner, lease_expires_at
            ) VALUES (?, 1, ?, ?, ?, ?, ?)
            """,
            (sha256, state.value, timestamp, timestamp, *lease_values),
        )
        if automated is not None:
            decision, policy_version = automated
            connection.execute(
                """
                INSERT INTO verdicts(
                    sha256, decision, score, policy_version, analyzer_version,
                    baseline_sha256, is_current, created_at
                ) VALUES (?, ?, 1.0, ?, 'analyzer-1', NULL, 1, ?)
                """,
                (sha256, decision.value, policy_version, timestamp),
            )
        if manual is not None:
            expiry = (
                expires_text
                if expires_text is not None
                else expires.isoformat()
                if expires is not None
                else None
            )
            connection.execute(
                """
                INSERT INTO manual_overrides(
                    sha256, decision, actor, reason, created_at, expires_at,
                    is_current
                ) VALUES (?, ?, 'tester', 'test override', ?, ?, 1)
                """,
                (
                    sha256,
                    manual.value,
                    timestamp,
                    expiry,
                ),
            )


def test_reader_allows_only_automated_allow(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        automated=(Decision.ALLOW, "policy-1"),
    )
    seed_artifact(
        factory,
        SHA_REVIEW,
        ArtifactState.REVIEW,
        automated=(Decision.REVIEW, "policy-1"),
    )

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)

    allowed = reader.get_effective_decision(SHA_ALLOW)
    blocked = reader.get_effective_decision(SHA_REVIEW)

    assert allowed.allowed is True
    assert allowed.effective_decision is Decision.ALLOW
    assert allowed.source is DecisionSource.AUTOMATED
    assert allowed.artifact_state is ArtifactState.ALLOW
    assert allowed.policy_version == "policy-1"
    assert blocked.allowed is False
    assert blocked.effective_decision is Decision.DENY
    assert blocked.source is DecisionSource.AUTOMATED
    assert blocked.artifact_state is ArtifactState.REVIEW


def test_current_manual_decision_overrides_automated_decision(
    tmp_path,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        automated=(Decision.ALLOW, "policy-1"),
        manual=Decision.DENY,
    )

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    result = reader.get_effective_decision(SHA_ALLOW)

    assert result.allowed is False
    assert result.effective_decision is Decision.DENY
    assert result.source is DecisionSource.MANUAL_OVERRIDE
    assert result.artifact_state is ArtifactState.ALLOW
    assert result.policy_version == "policy-1"


def test_manual_allow_over_review_is_effective(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_REVIEW,
        ArtifactState.REVIEW,
        automated=(Decision.REVIEW, "policy-1"),
        manual=Decision.ALLOW,
    )

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    result = reader.get_effective_decision(SHA_REVIEW)

    assert result.allowed is True
    assert result.effective_decision is Decision.ALLOW
    assert result.source is DecisionSource.MANUAL_OVERRIDE
    assert result.artifact_state is ArtifactState.REVIEW


def test_expired_manual_allow_falls_back_to_automated_review(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_REVIEW,
        ArtifactState.REVIEW,
        automated=(Decision.REVIEW, "policy-1"),
        manual=Decision.ALLOW,
        expires=NOW,
    )

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    result = reader.get_effective_decision(SHA_REVIEW)

    assert result.allowed is False
    assert result.effective_decision is Decision.DENY
    assert result.source is DecisionSource.AUTOMATED
    assert result.artifact_state is ArtifactState.REVIEW


def test_missing_and_batch_results_are_fail_closed(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        automated=(Decision.ALLOW, "policy-1"),
    )

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    results = reader.get_effective_decisions([SHA_ALLOW, SHA_MISSING])

    assert results[SHA_ALLOW].allowed is True
    assert results[SHA_MISSING].allowed is False
    assert results[SHA_MISSING].effective_decision is Decision.DENY
    assert results[SHA_MISSING].source is DecisionSource.MISSING
    assert results[SHA_MISSING].artifact_state is ArtifactState.MISSING
    assert results[SHA_MISSING].policy_version is None


@pytest.mark.parametrize(
    "state",
    [
        ArtifactState.DISCOVERED,
        ArtifactState.SCANNING,
        ArtifactState.REVIEW,
        ArtifactState.DENY,
        ArtifactState.ERROR,
    ],
)
def test_nonallow_lifecycle_states_block(
    tmp_path,
    state: ArtifactState,
) -> None:
    factory = ConnectionFactory(tmp_path / f"{state.value}.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        state,
        automated=(Decision.ALLOW, "policy-1"),
    )

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    result = reader.get_effective_decision(SHA_ALLOW)

    assert result.allowed is False
    assert result.effective_decision is Decision.DENY
    assert result.source is DecisionSource.AUTOMATED
    assert result.artifact_state is state


def test_mismatched_automated_allow_blocks_allow_artifact(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        automated=(Decision.REVIEW, "policy-1"),
    )

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    result = reader.get_effective_decision(SHA_ALLOW)

    assert result.allowed is False
    assert result.effective_decision is Decision.DENY
    assert result.policy_version == "policy-1"


def test_duplicate_inputs_return_one_result_per_distinct_sha(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        automated=(Decision.ALLOW, "policy-1"),
    )

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    results = reader.get_effective_decisions(
        [SHA_MISSING, SHA_ALLOW, SHA_MISSING, SHA_ALLOW],
    )

    assert list(results) == [SHA_MISSING, SHA_ALLOW]
    assert len(results) == 2


def test_batch_chunks_large_input_and_preserves_missing_results(
    tmp_path,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    shas = [f"{number:064x}" for number in range(401)]
    reader = SQLiteVerdictReader(factory, now=lambda: NOW)

    results = reader.get_effective_decisions(shas)

    assert list(results) == shas
    assert len(results) == 401
    assert all(not result.allowed for result in results.values())
    sources = (result.source for result in results.values())
    assert all(source is DecisionSource.MISSING for source in sources)


def test_invalid_caller_sha_raises_invalid_sha256(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    reader = SQLiteVerdictReader(factory, now=lambda: NOW)

    with pytest.raises(InvalidSha256):
        reader.get_effective_decisions([SHA_ALLOW, "NOT-A-SHA"])


def test_corrupt_artifact_state_maps_to_store_unavailable(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(factory, SHA_ALLOW, ArtifactState.ALLOW)
    with closing(factory.connect()) as connection, connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            "UPDATE artifacts SET state = 'CORRUPT' WHERE sha256 = ?",
            (SHA_ALLOW,),
        )

    with pytest.raises(StoreUnavailable):
        SQLiteVerdictReader(factory, now=lambda: NOW).get_effective_decision(
            SHA_ALLOW,
        )


def test_corrupt_expiry_maps_to_store_unavailable(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        manual=Decision.ALLOW,
        expires_text="not-a-timestamp",
    )

    with pytest.raises(StoreUnavailable):
        SQLiteVerdictReader(factory, now=lambda: NOW).get_effective_decision(
            SHA_ALLOW,
        )


def test_single_delegates_to_batch(monkeypatch, tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    expected = reader._missing(SHA_ALLOW)
    calls: list[list[str]] = []

    def fake_batch(sha256s):
        calls.append(list(sha256s))
        return {SHA_ALLOW: expected}

    monkeypatch.setattr(reader, "get_effective_decisions", fake_batch)

    assert reader.get_effective_decision(SHA_ALLOW) == expected
    assert calls == [[SHA_ALLOW]]


def test_now_is_read_once_for_each_batch_call(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    calls = 0

    def clock() -> datetime:
        nonlocal calls
        calls += 1
        return NOW

    SQLiteVerdictReader(factory, now=clock).get_effective_decisions(
        [SHA_ALLOW, SHA_MISSING] * 500,
    )

    assert calls == 1
