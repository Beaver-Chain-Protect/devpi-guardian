from __future__ import annotations

import sqlite3
from collections.abc import Callable, Collection, Mapping
from contextlib import closing
from datetime import UTC, datetime

from .db import ConnectionFactory
from .errors import StoreUnavailable
from .invariants import PersistedStateContext, validate_persisted_state
from .models import (
    ArtifactState,
    Decision,
    DecisionSource,
    EnforcementDecision,
    require_utc,
    validate_sha256,
)

_CHUNK_SIZE = 400


class SQLiteVerdictReader:
    def __init__(
        self,
        factory: ConnectionFactory,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = factory
        self._now = now if now is not None else lambda: datetime.now(UTC)

    def get_effective_decision(self, sha256: str) -> EnforcementDecision:
        return self.get_effective_decisions([sha256])[sha256]

    def get_effective_decisions(
        self,
        sha256s: Collection[str],
    ) -> Mapping[str, EnforcementDecision]:
        requested: list[str] = []
        seen: set[str] = set()
        for sha256 in sha256s:
            canonical = validate_sha256(sha256)
            if canonical not in seen:
                requested.append(canonical)
                seen.add(canonical)

        as_of = require_utc(self._now(), "now")
        results = {sha256: self._missing(sha256) for sha256 in requested}
        if not requested:
            return results

        try:
            with closing(self._factory.connect()) as connection:
                try:
                    connection.execute("BEGIN")
                    for offset in range(0, len(requested), _CHUNK_SIZE):
                        chunk = requested[slice(offset, offset + _CHUNK_SIZE)]
                        placeholders = ", ".join("?" for _ in chunk)
                        rows = connection.execute(
                            f"""
                            SELECT
                                a.sha256 AS artifact_sha256,
                                a.size_bytes AS artifact_size_bytes,
                                a.state AS artifact_state,
                                a.discovered_at AS artifact_discovered_at,
                                a.updated_at AS artifact_updated_at,
                                a.lease_owner AS artifact_lease_owner,
                                a.lease_expires_at
                                    AS artifact_lease_expires_at,
                                a.lease_token AS artifact_lease_token,
                                a.last_error AS artifact_last_error,
                                v.id AS verdict_id,
                                v.sha256 AS verdict_sha256,
                                v.decision AS verdict_decision,
                                v.score AS verdict_score,
                                v.policy_version AS verdict_policy_version,
                                v.analyzer_version AS verdict_analyzer_version,
                                v.baseline_sha256 AS verdict_baseline_sha256,
                                v.is_current AS verdict_is_current,
                                v.created_at AS verdict_created_at,
                                m.id AS override_id,
                                m.sha256 AS override_sha256,
                                m.decision AS override_decision,
                                m.actor AS override_actor,
                                m.reason AS override_reason,
                                m.created_at AS override_created_at,
                                m.expires_at AS override_expires_at,
                                m.is_current AS override_is_current
                            FROM artifacts AS a
                            LEFT JOIN verdicts AS v
                                ON v.sha256 = a.sha256 AND v.is_current = 1
                            LEFT JOIN manual_overrides AS m
                                ON m.sha256 = a.sha256 AND m.is_current = 1
                            WHERE a.sha256 IN ({placeholders})
                            """,
                            chunk,
                        ).fetchall()
                        returned: set[str] = set()
                        for row in rows:
                            sha256 = row["artifact_sha256"]
                            if sha256 in returned:
                                message = "duplicate current joined rows"
                                raise ValueError(message)
                            returned.add(sha256)
                            context = self._context_from_row(row, as_of)
                            results[sha256] = self._from_context(
                                sha256,
                                context,
                            )
                    connection.commit()
                except (sqlite3.Error, TypeError, ValueError, OverflowError):
                    if connection.in_transaction:
                        connection.rollback()
                    raise
        except (sqlite3.Error, TypeError, ValueError, OverflowError) as exc:
            raise StoreUnavailable(str(self._factory.path)) from exc

        return results

    @staticmethod
    def _missing(sha256: str) -> EnforcementDecision:
        return EnforcementDecision(
            sha256=sha256,
            allowed=False,
            effective_decision=Decision.DENY,
            source=DecisionSource.MISSING,
            artifact_state=ArtifactState.MISSING,
            policy_version=None,
        )

    @staticmethod
    def _context_from_row(
        row: sqlite3.Row,
        as_of: datetime,
    ) -> PersistedStateContext:
        artifact = {
            name: row[f"artifact_{name}"]
            for name in (
                "sha256",
                "size_bytes",
                "state",
                "discovered_at",
                "updated_at",
                "lease_owner",
                "lease_expires_at",
                "lease_token",
                "last_error",
            )
        }
        verdict = None
        if row["verdict_id"] is not None:
            verdict = {
                name: row[f"verdict_{name}"]
                for name in (
                    "id",
                    "sha256",
                    "decision",
                    "score",
                    "policy_version",
                    "analyzer_version",
                    "baseline_sha256",
                    "is_current",
                    "created_at",
                )
            }
        override = None
        if row["override_id"] is not None:
            override = {
                name: row[f"override_{name}"]
                for name in (
                    "id",
                    "sha256",
                    "decision",
                    "actor",
                    "reason",
                    "created_at",
                    "expires_at",
                    "is_current",
                )
            }
        return validate_persisted_state(artifact, verdict, override, as_of)

    @staticmethod
    def _from_context(
        sha256: str,
        context: PersistedStateContext,
    ) -> EnforcementDecision:
        allowed = context.effective_decision is Decision.ALLOW
        return EnforcementDecision(
            sha256=sha256,
            allowed=allowed,
            effective_decision=context.effective_decision,
            source=context.source,
            artifact_state=context.artifact_state,
            policy_version=context.policy_version,
        )
