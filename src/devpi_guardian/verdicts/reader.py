from __future__ import annotations

import sqlite3
from collections.abc import Callable, Collection, Mapping
from contextlib import closing
from datetime import UTC, datetime

from .db import ConnectionFactory
from .errors import StoreUnavailable
from .invariants import (
    PersistedStateContext,
    PersistedStateCorruption,
    validate_persisted_state,
)
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
                        artifact_rows = connection.execute(
                            f"""
                            SELECT * FROM artifacts
                            WHERE sha256 IN ({placeholders})
                            """,
                            chunk,
                        ).fetchall()
                        verdict_rows = connection.execute(
                            f"""
                            SELECT id, sha256, decision, score,
                                   policy_version, analyzer_version,
                                   baseline_sha256, is_current, created_at
                            FROM (
                                SELECT v.*,
                                    ROW_NUMBER() OVER (
                                        PARTITION BY sha256 ORDER BY id
                                    ) AS current_rank
                                FROM verdicts AS v
                                WHERE is_current = 1
                                  AND sha256 IN ({placeholders})
                            )
                            WHERE current_rank <= 2
                            ORDER BY sha256, id
                            """,
                            chunk,
                        ).fetchall()
                        override_rows = connection.execute(
                            f"""
                            SELECT id, sha256, decision, actor, reason,
                                   created_at, expires_at, is_current
                            FROM (
                                SELECT m.*,
                                    ROW_NUMBER() OVER (
                                        PARTITION BY sha256 ORDER BY id
                                    ) AS current_rank
                                FROM manual_overrides AS m
                                WHERE is_current = 1
                                  AND sha256 IN ({placeholders})
                            )
                            WHERE current_rank <= 2
                            ORDER BY sha256, id
                            """,
                            chunk,
                        ).fetchall()
                        verdicts = self._one_current_per_artifact(
                            verdict_rows,
                            "verdict",
                        )
                        overrides = self._one_current_per_artifact(
                            override_rows,
                            "override",
                        )
                        returned: set[str] = set()
                        for artifact in artifact_rows:
                            sha256 = artifact["sha256"]
                            if sha256 in returned:
                                raise PersistedStateCorruption(
                                    "multiple artifact rows",
                                )
                            returned.add(sha256)
                            context = validate_persisted_state(
                                artifact,
                                verdicts.get(sha256),
                                overrides.get(sha256),
                                as_of,
                            )
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
    def _one_current_per_artifact(
        rows: list[sqlite3.Row],
        history_name: str,
    ) -> dict[str, sqlite3.Row]:
        current: dict[str, sqlite3.Row] = {}
        for row in rows:
            sha256 = row["sha256"]
            if sha256 in current:
                raise PersistedStateCorruption(
                    f"multiple current {history_name}s",
                )
            current[sha256] = row
        return current

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
