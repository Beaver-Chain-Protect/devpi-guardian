from __future__ import annotations

import sqlite3
from collections.abc import Callable, Collection, Mapping
from contextlib import closing
from datetime import UTC, datetime

from .db import ConnectionFactory
from .errors import StoreUnavailable
from .models import (
    ArtifactState,
    Decision,
    DecisionSource,
    EnforcementDecision,
    require_utc,
    validate_sha256,
)

_CHUNK_SIZE = 400
_TERMINAL_STATES = {
    ArtifactState.ALLOW,
    ArtifactState.REVIEW,
    ArtifactState.DENY,
    ArtifactState.ERROR,
}


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
                                a.sha256,
                                a.state,
                                v.decision AS automated_decision,
                                v.policy_version,
                                m.decision AS manual_decision,
                                m.expires_at
                            FROM artifacts AS a
                            LEFT JOIN verdicts AS v
                                ON v.sha256 = a.sha256 AND v.is_current = 1
                            LEFT JOIN manual_overrides AS m
                                ON m.sha256 = a.sha256 AND m.is_current = 1
                            WHERE a.sha256 IN ({placeholders})
                            """,
                            chunk,
                        ).fetchall()
                        for row in rows:
                            results[row["sha256"]] = self._from_row(row, as_of)
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
    def _from_row(row: sqlite3.Row, as_of: datetime) -> EnforcementDecision:
        sha256 = row["sha256"]
        state = ArtifactState(row["state"])
        automated_raw = row["automated_decision"]
        automated = None if automated_raw is None else Decision(automated_raw)
        manual_raw = row["manual_decision"]
        manual = Decision(manual_raw) if manual_raw is not None else None
        if manual is not None and manual not in (
            Decision.ALLOW,
            Decision.DENY,
        ):
            raise ValueError("stored manual decision is invalid")
        expires_raw = row["expires_at"]
        expires = (
            require_utc(datetime.fromisoformat(expires_raw), "expires_at")
            if expires_raw is not None
            else None
        )

        if (
            manual is not None
            and state in _TERMINAL_STATES
            and (expires is None or expires > as_of)
        ):
            return EnforcementDecision(
                sha256=sha256,
                allowed=manual is Decision.ALLOW,
                effective_decision=manual,
                source=DecisionSource.MANUAL_OVERRIDE,
                artifact_state=state,
                policy_version=row["policy_version"],
            )

        allowed = state is ArtifactState.ALLOW and automated is Decision.ALLOW
        return EnforcementDecision(
            sha256=sha256,
            allowed=allowed,
            effective_decision=Decision.ALLOW if allowed else Decision.DENY,
            source=DecisionSource.AUTOMATED,
            artifact_state=state,
            policy_version=row["policy_version"],
        )
