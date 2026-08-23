from __future__ import annotations

from contextlib import closing
from datetime import UTC, datetime, timedelta

from devpi_guardian.verdicts.db import ConnectionFactory, migrate
from devpi_guardian.verdicts.models import Decision
from devpi_guardian.verdicts.reader import SQLiteVerdictReader

SHA256 = "a" * 64
NOW = datetime(2026, 8, 23, 0, 0, tzinfo=UTC)


def _seed_allow(factory: ConnectionFactory, cooldown_until: datetime) -> None:
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at,
                cooldown_started_at, cooldown_until
            ) VALUES (?, 1, 'ALLOW', ?, ?, ?, ?)
            """,
            (
                SHA256,
                NOW.isoformat(),
                NOW.isoformat(),
                NOW.isoformat(),
                cooldown_until.isoformat(),
            ),
        )
        connection.execute(
            """
            INSERT INTO verdicts(
                sha256, decision, score, policy_version, analyzer_version,
                baseline_sha256, is_current, created_at, baseline_tier
            ) VALUES (?, 'ALLOW', 0.0, 'policy-1', 'analyzer-1', NULL, 1, ?, NULL)
            """,
            (SHA256, NOW.isoformat()),
        )


def test_allow_is_hidden_until_artifact_cooldown_finishes(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    cooldown_until = NOW + timedelta(hours=24)
    _seed_allow(factory, cooldown_until)

    during = SQLiteVerdictReader(factory, now=lambda: cooldown_until - timedelta(seconds=1))
    after = SQLiteVerdictReader(factory, now=lambda: cooldown_until)

    blocked = during.get_effective_decision(SHA256)
    assert blocked.effective_decision is Decision.ALLOW
    assert blocked.allowed is False
    assert blocked.cooldown_until == cooldown_until
    assert blocked.cooldown_finished is False

    exposed = after.get_effective_decision(SHA256)
    assert exposed.allowed is True
    assert exposed.cooldown_finished is True
