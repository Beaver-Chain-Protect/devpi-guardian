from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Collection, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime

from .db import ConnectionFactory
from .errors import ArtifactNotFound, StoreUnavailable
from .invariants import (
    PersistedStateContext,
    PersistedStateCorruption,
    validate_persisted_release_mapping,
    validate_persisted_state,
)
from .models import (
    AllowedRelease,
    ArtifactAdminDetails,
    ArtifactAdminSummary,
    ArtifactState,
    Decision,
    DecisionSource,
    EnforcementDecision,
    EvidenceRecord,
    QuarantinePage,
    ReleaseArtifact,
    require_utc,
    validate_sha256,
)
from .releases import normalize_requested_project

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
            with self._read_transaction() as connection:
                results = self._read_effective_decisions(
                    connection,
                    requested,
                    as_of,
                )
        except (sqlite3.Error, TypeError, ValueError, OverflowError) as exc:
            raise StoreUnavailable(str(self._factory.path)) from exc

        return results

    def list_quarantine(
        self,
        *,
        states: tuple[ArtifactState, ...],
        limit: int,
        offset: int,
    ) -> QuarantinePage:
        if not states or any(
            type(state) is not ArtifactState
            or state in (ArtifactState.ALLOW, ArtifactState.MISSING)
            for state in states
        ):
            raise ValueError("invalid quarantine states")
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        if type(offset) is not int or offset < 0:
            raise ValueError("offset must be non-negative")
        values = tuple(dict.fromkeys(state.value for state in states))
        placeholders = ", ".join("?" for _ in values)
        as_of = require_utc(self._now(), "now")
        try:
            with self._read_transaction() as connection:
                total = connection.execute(
                    f"SELECT COUNT(*) FROM artifacts WHERE state IN ({placeholders})",
                    values,
                ).fetchone()[0]
                if type(total) is not int or total < 0:
                    raise PersistedStateCorruption("invalid quarantine total")
                rows = connection.execute(
                    f"""
                    SELECT sha256, size_bytes, state, discovered_at, updated_at,
                           cooldown_until, last_error
                    FROM artifacts
                    WHERE state IN ({placeholders})
                    ORDER BY discovered_at DESC, sha256
                    LIMIT ? OFFSET ?
                    """,
                    (*values, limit, offset),
                ).fetchall()
                requested = [row["sha256"] for row in rows]
                self._read_effective_decisions(connection, requested, as_of)
                items = tuple(self._admin_summary(row) for row in rows)
        except (sqlite3.Error, TypeError, ValueError, OverflowError) as exc:
            raise StoreUnavailable(str(self._factory.path)) from exc
        return QuarantinePage(items=items, total=total, limit=limit, offset=offset)

    def get_artifact_details(self, sha256: str) -> ArtifactAdminDetails:
        canonical = validate_sha256(sha256)
        as_of = require_utc(self._now(), "now")
        try:
            with self._read_transaction() as connection:
                artifact = connection.execute(
                    "SELECT * FROM artifacts WHERE sha256 = ?",
                    (canonical,),
                ).fetchone()
                if artifact is None:
                    raise ArtifactNotFound(canonical)
                verdict_rows = connection.execute(
                    "SELECT * FROM verdicts WHERE sha256 = ? AND is_current = 1",
                    (canonical,),
                ).fetchall()
                override_rows = connection.execute(
                    "SELECT * FROM manual_overrides WHERE sha256 = ? AND is_current = 1",
                    (canonical,),
                ).fetchall()
                verdict = self._one_current_per_artifact(verdict_rows, "verdict").get(canonical)
                override = self._one_current_per_artifact(override_rows, "override").get(canonical)
                context = validate_persisted_state(artifact, verdict, override, as_of)
                effective = self._from_context(canonical, context)
                release_rows = connection.execute(
                    """
                    SELECT r.id, r.stage, r.project, r.version, r.filename,
                           r.sha256, r.origin_url, r.discovered_at, a.size_bytes
                    FROM release_mappings AS r
                    JOIN artifacts AS a ON a.sha256 = r.sha256
                    WHERE r.sha256 = ?
                    ORDER BY r.stage, r.project, r.version, r.filename, r.origin_url
                    """,
                    (canonical,),
                ).fetchall()
                releases = tuple(self._release_from_row(row) for row in release_rows)
                evidence = () if verdict is None else self._read_evidence(connection, verdict["id"])
                return ArtifactAdminDetails(
                    summary=self._admin_summary(artifact),
                    allowed=effective.allowed,
                    effective_decision=effective.effective_decision,
                    decision_source=effective.source,
                    policy_version=effective.policy_version,
                    analyzer_version=None if verdict is None else verdict["analyzer_version"],
                    baseline_sha256=None if verdict is None else verdict["baseline_sha256"],
                    baseline_tier=None if verdict is None else verdict["baseline_tier"],
                    releases=releases,
                    evidence=evidence,
                )
        except ArtifactNotFound:
            raise
        except (sqlite3.Error, TypeError, ValueError, OverflowError) as exc:
            raise StoreUnavailable(str(self._factory.path)) from exc

    def health(self) -> dict[str, object]:
        try:
            with self._read_transaction() as connection:
                version = connection.execute(
                    "SELECT MAX(version) FROM schema_migrations"
                ).fetchone()[0]
                connection.execute("SELECT 1 FROM artifacts LIMIT 1").fetchone()
        except (sqlite3.Error, TypeError, ValueError, OverflowError) as exc:
            raise StoreUnavailable(str(self._factory.path)) from exc
        return {"database": "ok", "schema_version": version}

    @staticmethod
    def _timestamp(value: object, field_name: str) -> datetime:
        if type(value) is not str:
            raise ValueError(f"invalid {field_name}")
        return require_utc(datetime.fromisoformat(value), field_name)

    @classmethod
    def _admin_summary(cls, row: sqlite3.Row) -> ArtifactAdminSummary:
        size_bytes = row["size_bytes"]
        if type(size_bytes) is not int or not 0 <= size_bytes <= 2**63 - 1:
            raise PersistedStateCorruption("invalid persisted artifact size")
        state = ArtifactState(row["state"])
        last_error = row["last_error"]
        if state is ArtifactState.ERROR:
            if type(last_error) is not str or len(last_error) > 4096 or "\x00" in last_error:
                raise PersistedStateCorruption("invalid persisted last_error")
        elif last_error is not None:
            raise PersistedStateCorruption("invalid persisted last_error")
        cooldown = row["cooldown_until"]
        return ArtifactAdminSummary(
            sha256=validate_sha256(row["sha256"]),
            size_bytes=size_bytes,
            state=state,
            discovered_at=cls._timestamp(row["discovered_at"], "discovered_at"),
            updated_at=cls._timestamp(row["updated_at"], "updated_at"),
            cooldown_until=None if cooldown is None else cls._timestamp(cooldown, "cooldown_until"),
            last_error=row["last_error"],
        )

    @staticmethod
    def _release_from_row(row: sqlite3.Row) -> ReleaseArtifact:
        release = validate_persisted_release_mapping(row)
        return ReleaseArtifact(
            stage=release.stage,
            project=release.project,
            version=release.version,
            filename=release.filename,
            sha256=release.sha256,
            origin_url=release.origin_url,
            size_bytes=row["size_bytes"],
        )

    @staticmethod
    def _read_evidence(
        connection: sqlite3.Connection,
        verdict_id: int,
    ) -> tuple[EvidenceRecord, ...]:
        rows = connection.execute(
            """
            SELECT rule_id, action, file_path, line, message, details_json
            FROM evidence WHERE verdict_id = ? ORDER BY id
            """,
            (verdict_id,),
        ).fetchall()
        return tuple(
            EvidenceRecord(
                rule_id=row["rule_id"],
                action=Decision(row["action"]),
                file_path=row["file_path"],
                line=row["line"],
                message=row["message"],
                details=json.loads(row["details_json"]),
            )
            for row in rows
        )

    def _read_effective_decisions(
        self,
        connection: sqlite3.Connection,
        requested: list[str],
        as_of: datetime,
    ) -> dict[str, EnforcementDecision]:
        results = {sha256: self._missing(sha256) for sha256 in requested}
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
                       baseline_sha256, is_current, created_at, baseline_tier
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
        return results

    def list_allowed_releases(
        self,
        project: str,
    ) -> tuple[AllowedRelease, ...]:
        canonical_project = normalize_requested_project(project)
        as_of = require_utc(self._now(), "now")
        results: list[AllowedRelease] = []
        try:
            with self._read_transaction() as connection:
                mapping_cursor = connection.execute(
                    """
                    SELECT id, stage, project, version, filename, sha256,
                           origin_url, discovered_at
                    FROM release_mappings
                    WHERE project = ?
                    ORDER BY id
                    """,
                    (canonical_project,),
                )
                while rows := mapping_cursor.fetchmany(_CHUNK_SIZE):
                    validate_mapping = validate_persisted_release_mapping
                    mappings = tuple(validate_mapping(row) for row in rows)
                    requested = []
                    requested_shas = set()
                    for mapping in mappings:
                        if mapping.sha256 not in requested_shas:
                            requested.append(mapping.sha256)
                            requested_shas.add(mapping.sha256)
                    decisions = self._read_effective_decisions(
                        connection,
                        requested,
                        as_of,
                    )
                    placeholders = ", ".join("?" for _ in requested)
                    baseline_rows = connection.execute(
                        f"""
                        SELECT sha256, enabled FROM baseline_overrides
                        WHERE is_current = 1 AND sha256 IN ({placeholders})
                        ORDER BY id
                        """,
                        requested,
                    ).fetchall()
                    baseline_enabled: dict[str, bool] = {}
                    for row in baseline_rows:
                        digest = validate_sha256(row["sha256"])
                        if digest in baseline_enabled or row["enabled"] not in (0, 1):
                            raise PersistedStateCorruption(
                                "invalid current baseline override",
                            )
                        baseline_enabled[digest] = bool(row["enabled"])
                    missing_state = ArtifactState.MISSING
                    for mapping in mappings:
                        decision = decisions[mapping.sha256]
                        if decision.artifact_state is missing_state:
                            message = "release mapping artifact is missing"
                            raise PersistedStateCorruption(
                                message,
                            )
                        if decision.allowed and baseline_enabled.get(mapping.sha256, True):
                            results.append(mapping)
        except (sqlite3.Error, TypeError, ValueError, OverflowError) as exc:
            raise StoreUnavailable(str(self._factory.path)) from exc

        results.sort(
            key=lambda release: (
                release.stage,
                release.version,
                release.filename,
                release.sha256,
                release.origin_url,
            ),
        )
        return tuple(results)

    def get_artifact_releases(self, sha256: str) -> tuple[ReleaseArtifact, ...]:
        canonical_sha256 = validate_sha256(sha256)
        return self._release_artifacts("WHERE r.sha256 = ?", (canonical_sha256,))

    def list_release_artifacts(
        self,
        project: str,
        version: str,
    ) -> tuple[ReleaseArtifact, ...]:
        canonical_project = normalize_requested_project(project)
        if not isinstance(version, str) or not version.strip():
            raise ValueError("version must not be blank")
        return self._release_artifacts(
            "WHERE r.project = ? AND r.version = ?",
            (canonical_project, version),
        )

    def _release_artifacts(
        self,
        where_clause: str,
        parameters: tuple[str, ...],
    ) -> tuple[ReleaseArtifact, ...]:
        try:
            with self._read_transaction() as connection:
                rows = connection.execute(
                    f"""
                    SELECT r.id, r.stage, r.project, r.version, r.filename,
                           r.sha256, r.origin_url, r.discovered_at,
                           a.size_bytes
                    FROM release_mappings AS r
                    JOIN artifacts AS a ON a.sha256 = r.sha256
                    {where_clause}
                    ORDER BY r.stage, r.project, r.version, r.filename,
                             r.sha256, r.origin_url
                    """,
                    parameters,
                ).fetchall()
                results = []
                for row in rows:
                    release = validate_persisted_release_mapping(row)
                    size_bytes = row["size_bytes"]
                    if type(size_bytes) is not int or size_bytes < 0:
                        raise PersistedStateCorruption("invalid persisted artifact size")
                    results.append(
                        ReleaseArtifact(
                            stage=release.stage,
                            project=release.project,
                            version=release.version,
                            filename=release.filename,
                            sha256=release.sha256,
                            origin_url=release.origin_url,
                            size_bytes=size_bytes,
                        )
                    )
                return tuple(results)
        except (sqlite3.Error, TypeError, ValueError, OverflowError) as exc:
            raise StoreUnavailable(str(self._factory.path)) from exc

    @contextmanager
    def _read_transaction(self) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        primary: BaseException | None = None
        try:
            connection = self._factory.connect()
            connection.execute("BEGIN")
            yield connection
            connection.commit()
        except BaseException as exc:
            primary = exc
            if connection is not None:
                try:
                    if connection.in_transaction:
                        connection.rollback()
                except BaseException:
                    pass
            raise
        finally:
            if connection is not None:
                try:
                    connection.close()
                except BaseException:
                    if primary is None:
                        raise

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
        allowed = context.effective_decision is Decision.ALLOW and context.cooldown_finished
        return EnforcementDecision(
            sha256=sha256,
            allowed=allowed,
            effective_decision=context.effective_decision,
            source=context.source,
            artifact_state=context.artifact_state,
            policy_version=context.policy_version,
            cooldown_until=context.cooldown_until,
            cooldown_finished=context.cooldown_finished,
        )
