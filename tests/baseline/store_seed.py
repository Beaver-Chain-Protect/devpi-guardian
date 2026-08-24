"""Seed a real F4 verdict store, the way tests/verdicts/test_reader.py does.

These are not test doubles: they build an actual SQLite database with F4's own
`ConnectionFactory` and `migrate`, so the tests above them exercise the real
`list_allowed_releases` query.
"""

from __future__ import annotations

from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from devpi_guardian.verdicts.db import ConnectionFactory, migrate
from devpi_guardian.verdicts.models import ArtifactState, Decision

NOW = datetime(2026, 8, 18, 0, 0, tzinfo=UTC)


def build_store(path: Path) -> ConnectionFactory:
    factory = ConnectionFactory(Path(path) / "guardian.db")
    migrate(factory)
    return factory


def seed_artifact(
    factory: ConnectionFactory,
    sha256: str,
    state: ArtifactState,
    automated: tuple[Decision, str] | None = None,
) -> None:
    timestamp = NOW.isoformat()
    lease = (
        ("worker", (NOW + timedelta(minutes=10)).isoformat(), "f" * 64)
        if state is ArtifactState.SCANNING
        else (None, None, None)
    )
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at,
                lease_owner, lease_expires_at, lease_token, last_error
            ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (sha256, state.value, timestamp, timestamp, *lease),
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


def seed_release(
    factory: ConnectionFactory,
    sha256: str,
    *,
    stage: str = "root/dev",
    project: str = "demo-package",
    version: str = "1.0.0",
    filename: str = "demo_package-1.0.0-py3-none-any.whl",
    origin_url: str | None = None,
) -> None:
    default_origin = f"https://devpi.example/{stage}/+f/{sha256[:2]}/{filename}"
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO release_mappings(
                stage, project, version, filename, sha256,
                origin_url, discovered_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stage,
                project,
                version,
                filename,
                sha256,
                origin_url or default_origin,
                NOW.isoformat(),
            ),
        )


def seed_allowed(factory: ConnectionFactory, sha256: str, **release_kwargs) -> None:
    """Seed one artifact whose current automated verdict is ALLOW."""

    seed_artifact(factory, sha256, ArtifactState.ALLOW, automated=(Decision.ALLOW, "policy-1"))
    seed_release(factory, sha256, **release_kwargs)
