from __future__ import annotations

from contextlib import closing
from datetime import UTC, datetime

import pytest

from devpi_guardian.verdicts.db import ConnectionFactory, migrate
from devpi_guardian.verdicts.errors import ArtifactNotFound
from devpi_guardian.verdicts.models import ArtifactState, Decision
from devpi_guardian.verdicts.reader import SQLiteVerdictReader

SHA256 = "a" * 64
NOW = datetime(2026, 8, 24, tzinfo=UTC)


def reader_with_review(tmp_path) -> SQLiteVerdictReader:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    timestamp = NOW.isoformat()
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at
            ) VALUES (?, 42, 'REVIEW', ?, ?)
            """,
            (SHA256, timestamp, timestamp),
        )
        cursor = connection.execute(
            """
            INSERT INTO verdicts(
                sha256, decision, score, policy_version, analyzer_version,
                baseline_sha256, is_current, created_at, baseline_tier
            ) VALUES (?, 'REVIEW', 20, 'policy-1', 'analyzer-1', NULL, 1, ?, NULL)
            """,
            (SHA256, timestamp),
        )
        connection.execute(
            """
            INSERT INTO evidence(
                verdict_id, rule_id, action, file_path, line, message, details_json
            ) VALUES (?, 'new_network', 'REVIEW', 'pkg/client.py', 7,
                      'new network call', '{"host":"example.test"}')
            """,
            (cursor.lastrowid,),
        )
        connection.execute(
            """
            INSERT INTO release_mappings(
                stage, project, version, filename, sha256, origin_url, discovered_at
            ) VALUES ('company/guardian', 'demo', '1.0', 'demo-1.0.whl', ?,
                      'https://example.test/demo.whl', ?)
            """,
            (SHA256, timestamp),
        )
    return SQLiteVerdictReader(factory, now=lambda: NOW)


def test_reader_lists_quarantine_and_reports_total(tmp_path) -> None:
    reader = reader_with_review(tmp_path)

    page = reader.list_quarantine(states=(ArtifactState.REVIEW,), limit=20, offset=0)

    assert page.total == 1
    assert page.items[0].sha256 == SHA256
    assert page.items[0].state is ArtifactState.REVIEW


def test_reader_returns_details_release_and_evidence(tmp_path) -> None:
    reader = reader_with_review(tmp_path)

    details = reader.get_artifact_details(SHA256)

    assert details.allowed is False
    assert details.effective_decision is Decision.DENY
    assert details.analyzer_version == "analyzer-1"
    assert details.releases[0].project == "demo"
    assert details.evidence[0].rule_id == "new_network"
    assert details.evidence[0].details == {"host": "example.test"}
    assert reader.health() == {"database": "ok", "schema_version": 6}


def test_reader_detail_raises_for_missing_artifact(tmp_path) -> None:
    reader = reader_with_review(tmp_path)

    with pytest.raises(ArtifactNotFound):
        reader.get_artifact_details("b" * 64)
