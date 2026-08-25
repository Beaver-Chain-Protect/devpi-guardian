from __future__ import annotations

import json
import math
import secrets
import sqlite3
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime

from devpi_common.metadata import normalize_name

from devpi_guardian.privacy import sanitize_diagnostic, sanitize_diagnostic_graph

from .db import ConnectionFactory
from .errors import ArtifactNotFound, StoreUnavailable, TransitionConflict
from .interfaces import AuditWriter
from .invariants import (
    PersistedStateContext,
    PersistedStateCorruption,
    validate_persisted_state,
)
from .models import (
    ArtifactInput,
    AuditEventInput,
    ClaimedArtifact,
    Decision,
    EvidenceInput,
    ManualOverrideInput,
    ReleaseInput,
    VerdictInput,
    require_utc,
    validate_baseline_tier,
    validate_sha256,
)
from .releases import sanitize_origin_url

_MAX_SQLITE_INTEGER = 2**63 - 1
_MAX_STORED_TEXT_LENGTH = 4096
_MAX_DETAILS_JSON_LENGTH = 1024 * 1024
_TERMINAL_STATES = {"ALLOW", "REVIEW", "DENY", "ERROR"}


def _require_datetime(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise ValueError(f"{field_name} must be a datetime")
    return value


def _require_nonblank_string(value: object, field_name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{field_name} must be a nonblank string")
    return value


def _require_stored_string(value: object, field_name: str) -> str:
    text = _require_nonblank_string(value, field_name)
    if len(text) > _MAX_STORED_TEXT_LENGTH or "\x00" in text:
        raise ValueError(f"{field_name} is not safe to store")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{field_name} is not safe to store") from None
    return text


def _iso(value: datetime, field_name: str) -> str:
    timestamp = _require_datetime(value, field_name)
    return require_utc(timestamp, field_name).isoformat()


def _normalize_score(value: object) -> float:
    if type(value) not in (int, float):
        raise ValueError("score must be a finite number")
    try:
        score = float(value)
    except (OverflowError, TypeError, ValueError):
        raise ValueError("score must be a finite number") from None
    if not math.isfinite(score):
        raise ValueError("score must be a finite number")
    return score


def _validate_json_value(value: object) -> None:
    if value is None or type(value) in (bool, int, str):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("details must contain finite JSON numbers")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("details object keys must be strings")
            _validate_json_value(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_json_value(item)
        return
    raise ValueError("details must be JSON-serializable")


def _serialize_details(value: object) -> str:
    if not isinstance(value, dict):
        raise ValueError("details must be a dictionary")
    try:
        _validate_json_value(value)
        serialized = json.dumps(
            value,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
        RuntimeError,
    ) as exc:
        raise ValueError("details must be JSON-serializable") from exc
    if len(serialized.encode("utf-8")) > _MAX_DETAILS_JSON_LENGTH:
        raise ValueError("details JSON is too large")
    return serialized


def _sanitize_analysis_error(value: object) -> str:
    if type(value) is not str:
        raise ValueError("error must be a string")
    return sanitize_diagnostic(value)


def _require_lease_token(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("lease_token must be a canonical token")
    return value


def _prepare_claim(
    claim: object,
) -> tuple[str, int, str, datetime, str, str]:
    if type(claim) is not ClaimedArtifact:
        raise ValueError("claim must be a ClaimedArtifact")
    try:
        sha256 = validate_sha256(claim.sha256)
        size_bytes = claim.size_bytes
        worker_id = _require_stored_string(claim.worker_id, "worker_id")
        lease_expires_at = require_utc(
            _require_datetime(claim.lease_expires_at, "lease_expires_at"),
            "lease_expires_at",
        )
        lease_token = _require_lease_token(claim.lease_token)
    except AttributeError:
        raise ValueError("ClaimedArtifact missing required fields") from None
    size_is_integer = type(size_bytes) is int
    size_in_range = size_is_integer and 0 <= size_bytes <= _MAX_SQLITE_INTEGER
    if not size_in_range:
        raise ValueError("size_bytes must be a SQLite integer")
    return (
        sha256,
        size_bytes,
        worker_id,
        lease_expires_at,
        lease_expires_at.isoformat(),
        lease_token,
    )


def _prepare_evidence(
    evidence: object,
) -> tuple[tuple[str, str, str | None, int | None, str, str], ...]:
    if isinstance(evidence, (str, bytes, bytearray)) or not isinstance(
        evidence,
        Sequence,
    ):
        raise ValueError("evidence must be a stable sequence")
    try:
        items = tuple(evidence)
    except (IndexError, KeyError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError("evidence must be a stable sequence") from exc

    prepared: list[tuple[str, str, str | None, int | None, str, str]] = []
    for item in items:
        if type(item) is not EvidenceInput:
            raise ValueError("evidence items must be EvidenceInput instances")
        try:
            rule_id = _require_stored_string(item.rule_id, "rule_id")
            action = item.action
            file_path_value = item.file_path
            line = item.line
            raw_message = _require_stored_string(item.message, "message")
            message = sanitize_diagnostic(raw_message)
            try:
                details_json = _serialize_details(sanitize_diagnostic_graph(item.details))
            except (
                TypeError,
                ValueError,
                OverflowError,
                RecursionError,
                RuntimeError,
            ) as exc:
                raise ValueError("details must be JSON-serializable") from exc
        except AttributeError:
            message = "EvidenceInput missing required fields"
            raise ValueError(message) from None
        if type(action) is not Decision:
            raise ValueError("action must be a Decision")
        file_path = (
            None
            if file_path_value is None
            else sanitize_diagnostic(_require_stored_string(file_path_value, "file_path"))
        )
        line_is_integer = type(line) is int
        line_in_range = line_is_integer and 0 < line <= _MAX_SQLITE_INTEGER
        if line is not None and not line_in_range:
            raise ValueError("line must be a SQLite positive integer or None")
        prepared.append(
            (
                rule_id,
                action.value,
                file_path,
                line,
                message,
                details_json,
            )
        )
    return tuple(prepared)


def _prepare_manual_override(
    override: object,
) -> tuple[str, Decision, str, str, str, datetime | None, str | None]:
    if type(override) is not ManualOverrideInput:
        raise ValueError("override must be a ManualOverrideInput")
    try:
        sha256 = validate_sha256(override.sha256)
        decision = override.decision
        actor = _require_stored_string(override.actor, "actor")
        reason = _require_stored_string(override.reason, "reason")
        created_at = _iso(override.created_at, "created_at")
        expires_value = override.expires_at
    except AttributeError:
        message = "ManualOverrideInput missing required fields"
        raise ValueError(message) from None
    if type(decision) is not Decision or decision not in (
        Decision.ALLOW,
        Decision.DENY,
    ):
        raise ValueError("manual decision must be ALLOW or DENY")
    expires_at = None
    expires_text = None
    if expires_value is not None:
        expires_at = require_utc(
            _require_datetime(expires_value, "expires_at"),
            "expires_at",
        )
        expires_text = expires_at.isoformat()
        created = require_utc(
            _require_datetime(override.created_at, "created_at"),
            "created_at",
        )
        if expires_at <= created:
            raise ValueError("expires_at must be later than created_at")
    return (
        sha256,
        decision,
        actor,
        reason,
        created_at,
        expires_at,
        expires_text,
    )


def _prepare_admin_command(
    sha256: object,
    actor: object,
    reason: object,
) -> tuple[str, str, str]:
    return (
        validate_sha256(sha256),
        _require_stored_string(actor, "actor"),
        _require_stored_string(reason, "reason"),
    )


class SQLiteArtifactStore:
    def __init__(
        self,
        factory: ConnectionFactory,
        audit_writer: AuditWriter,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.connection_factory = factory
        self._audit_writer = audit_writer
        self._now = now if now is not None else lambda: datetime.now(UTC)

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        primary: BaseException | None = None
        committed = False
        try:
            connection = self.connection_factory.connect()
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
            committed = True
        except BaseException as exc:
            primary = exc
            if connection is not None:
                try:
                    if connection.in_transaction:
                        connection.rollback()
                except BaseException:
                    pass
        finally:
            if connection is not None:
                try:
                    connection.close()
                except BaseException as exc:
                    # A completed commit cannot be reversed by close failing.
                    if primary is None and not committed:
                        primary = exc

        if primary is not None:
            if isinstance(primary, sqlite3.Error):
                path = str(self.connection_factory.path)
                raise StoreUnavailable(path) from primary
            raise primary.with_traceback(primary.__traceback__)

    def _audit(
        self,
        connection: sqlite3.Connection,
        *,
        actor: str,
        action: str,
        sha256: str,
        reason: str,
        occurred_at: datetime,
        previous: Decision = Decision.DENY,
        new: Decision = Decision.DENY,
        policy_version: str | None = None,
        analyzer_version: str | None = None,
    ) -> None:
        self._audit_writer.append_in_transaction(
            connection,
            AuditEventInput(
                actor=actor,
                action=action,
                sha256=sha256,
                previous_decision=previous,
                new_decision=new,
                reason=reason,
                policy_version=policy_version,
                analyzer_version=analyzer_version,
                occurred_at=occurred_at,
            ),
        )

    def set_baseline_eligibility(
        self,
        sha256: str,
        *,
        enabled: bool,
        actor: str,
        reason: str,
    ) -> None:
        canonical = validate_sha256(sha256)
        if type(enabled) is not bool:
            raise ValueError("enabled must be a bool")
        actor = _require_stored_string(actor, "actor")
        reason = _require_stored_string(reason, "reason")

        with self._write() as connection:
            operation_at = require_utc(_require_datetime(self._now(), "now"), "now")
            _artifact, _override, context = self._administrator_context(
                connection,
                canonical,
                operation_at,
            )
            if enabled and not (
                context.effective_decision is Decision.ALLOW and context.cooldown_finished
            ):
                raise TransitionConflict("baseline must be an effective, cooldown-finished ALLOW")

            current_rows = connection.execute(
                """
                SELECT id, enabled FROM baseline_overrides
                WHERE sha256 = ? AND is_current = 1
                ORDER BY id LIMIT 2
                """,
                (canonical,),
            ).fetchall()
            if len(current_rows) > 1:
                raise TransitionConflict("multiple current baseline overrides")
            if current_rows and bool(current_rows[0]["enabled"]) is enabled:
                return
            if current_rows:
                cursor = connection.execute(
                    """
                    UPDATE baseline_overrides SET is_current = 0
                    WHERE id = ? AND is_current = 1
                    """,
                    (current_rows[0]["id"],),
                )
                if cursor.rowcount != 1:
                    raise TransitionConflict("baseline override update failed")

            created_at = operation_at.isoformat()
            inserted = connection.execute(
                """
                INSERT INTO baseline_overrides(
                    sha256, enabled, actor, reason, created_at, is_current
                ) VALUES (?, ?, ?, ?, ?, 1)
                """,
                (canonical, int(enabled), actor, reason, created_at),
            )
            if inserted.rowcount != 1:
                raise TransitionConflict("baseline override insert failed")

            expected_baseline_history = self._baseline_history(connection, canonical)
            expected_override = None if _override is None else tuple(_override)
            expected_administrator = {
                "sha256": canonical,
                "operation_at": operation_at,
                "expected_artifact": tuple(_artifact),
                "expected_counts": self._history_counts(connection, canonical),
                "expected_verdict_id": context.current_verdict_id,
                "expected_override": expected_override,
            }

            self._audit(
                connection,
                actor=actor,
                action="baseline.added" if enabled else "baseline.removed",
                sha256=canonical,
                reason=reason,
                previous=context.effective_decision,
                new=context.effective_decision,
                policy_version=context.policy_version,
                analyzer_version=context.analyzer_version,
                occurred_at=operation_at,
            )
            self._verify_administrator_result(connection, **expected_administrator)
            self._verify_baseline_history(
                connection,
                canonical,
                expected_baseline_history,
            )

    def discover_artifact(
        self,
        artifact: ArtifactInput,
        release: ReleaseInput,
    ) -> None:
        if type(artifact) is not ArtifactInput:
            raise ValueError("artifact must be an ArtifactInput")
        if type(release) is not ReleaseInput:
            raise ValueError("release must be a ReleaseInput")
        validate_sha256(artifact.sha256)
        validate_sha256(release.sha256)
        if artifact.sha256 != release.sha256:
            raise ValueError("artifact and release sha256 must match")
        if (
            type(artifact.size_bytes) is not int
            or not 0 <= artifact.size_bytes <= _MAX_SQLITE_INTEGER
        ):
            raise ValueError("size_bytes must be a SQLite integer")

        stage = _require_nonblank_string(release.stage, "stage")
        project_input = _require_nonblank_string(release.project, "project")
        version = _require_nonblank_string(release.version, "version")
        filename = _require_nonblank_string(release.filename, "filename")
        release_origin = release.origin_url
        origin_input = _require_nonblank_string(release_origin, "origin_url")

        project = normalize_name(project_input)
        origin_url = sanitize_origin_url(origin_input)
        artifact_discovered_at = _iso(artifact.discovered_at, "discovered_at")
        release_discovered_at = _iso(release.discovered_at, "discovered_at")
        operation_at = require_utc(
            _require_datetime(self._now(), "now"),
            "now",
        )

        with self._write() as connection:
            artifact_cursor = connection.execute(
                """
                INSERT INTO artifacts(
                    sha256, size_bytes, state, discovered_at, updated_at
                ) VALUES (?, ?, 'DISCOVERED', ?, ?)
                ON CONFLICT(sha256) DO NOTHING
                """,
                (
                    artifact.sha256,
                    artifact.size_bytes,
                    artifact_discovered_at,
                    artifact_discovered_at,
                ),
            )
            stored = connection.execute(
                "SELECT size_bytes FROM artifacts WHERE sha256 = ?",
                (artifact.sha256,),
            ).fetchone()
            if artifact_cursor.rowcount == 0 and stored is None:
                raise TransitionConflict("artifact insert ignored without row")
            if stored is None or stored["size_bytes"] != artifact.size_bytes:
                raise TransitionConflict("artifact size conflict")

            mapping_cursor = connection.execute(
                """
                INSERT INTO release_mappings(
                    stage, project, version, filename, sha256, origin_url,
                    discovered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(stage, project, version, filename, sha256)
                DO NOTHING
                """,
                (
                    stage,
                    project,
                    version,
                    filename,
                    artifact.sha256,
                    origin_url,
                    release_discovered_at,
                ),
            )
            if mapping_cursor.rowcount == 0:
                stored_mapping = connection.execute(
                    """
                    SELECT origin_url
                    FROM release_mappings
                    WHERE stage = ? AND project = ? AND version = ?
                      AND filename = ? AND sha256 = ?
                    """,
                    (
                        stage,
                        project,
                        version,
                        filename,
                        artifact.sha256,
                    ),
                ).fetchone()
                if stored_mapping is None:
                    raise TransitionConflict("release mapping row missing")
                if stored_mapping["origin_url"] != origin_url:
                    raise TransitionConflict("release mapping conflict")
            if artifact_cursor.rowcount == 1 or mapping_cursor.rowcount == 1:
                self._audit(
                    connection,
                    actor="guardian-discovery",
                    action="artifact.discovered",
                    sha256=artifact.sha256,
                    reason="release mapping discovered",
                    occurred_at=operation_at,
                )

    def _verify_claimed_state(
        self,
        connection: sqlite3.Connection,
        expected: tuple[object, ...],
        *,
        after_audit: bool,
    ) -> None:
        persisted = connection.execute(
            """
            SELECT sha256, size_bytes, discovered_at, state, lease_owner,
                   lease_expires_at, lease_token, last_error, updated_at
            FROM artifacts WHERE sha256 = ?
            """,
            (expected[0],),
        ).fetchone()
        persisted_tuple = None if persisted is None else tuple(persisted)
        if persisted_tuple == expected:
            return

        persisted_identity = None
        if persisted_tuple is not None:
            persisted_identity = persisted_tuple[:3]
        identity_changed = persisted_identity != expected[:3]
        if after_audit or identity_changed:
            corruption = PersistedStateCorruption(
                "claimed artifact state changed unexpectedly",
            )
            path = str(self.connection_factory.path)
            raise StoreUnavailable(path) from corruption
        raise TransitionConflict("artifact claim state mismatch")

    def claim_next(
        self,
        worker_id: str,
        lease_until: datetime,
    ) -> ClaimedArtifact | None:
        worker_id = _require_stored_string(worker_id, "worker_id")
        lease_timestamp = _require_datetime(lease_until, "lease_until")
        lease_expires_at = require_utc(lease_timestamp, "lease_until")
        lease_text = lease_expires_at.isoformat()

        with self._write() as connection:
            operation_at = require_utc(
                _require_datetime(self._now(), "now"),
                "now",
            )
            if lease_expires_at <= operation_at:
                raise ValueError("lease_until must be in the future")
            updated_at = operation_at.isoformat()
            row = connection.execute(
                """
                SELECT sha256, size_bytes, discovered_at
                FROM artifacts
                WHERE state = 'DISCOVERED'
                ORDER BY discovered_at, sha256
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                return None
            lease_token = _require_lease_token(secrets.token_hex(32))
            cursor = connection.execute(
                """
                UPDATE artifacts
                SET state = 'SCANNING', lease_owner = ?, lease_expires_at = ?,
                    lease_token = ?, updated_at = ?, last_error = NULL
                WHERE sha256 = ? AND state = 'DISCOVERED'
                """,
                (
                    worker_id,
                    lease_text,
                    lease_token,
                    updated_at,
                    row["sha256"],
                ),
            )
            if cursor.rowcount != 1:
                raise TransitionConflict("artifact could not be claimed")
            expected_artifact = (
                row["sha256"],
                row["size_bytes"],
                row["discovered_at"],
                "SCANNING",
                worker_id,
                lease_text,
                lease_token,
                None,
                updated_at,
            )
            self._verify_claimed_state(
                connection,
                expected_artifact,
                after_audit=False,
            )
            self._audit(
                connection,
                actor=worker_id,
                action="artifact.claimed",
                sha256=row["sha256"],
                reason="analysis lease acquired",
                occurred_at=operation_at,
            )
            self._verify_claimed_state(
                connection,
                expected_artifact,
                after_audit=True,
            )
            return ClaimedArtifact(
                sha256=row["sha256"],
                size_bytes=row["size_bytes"],
                worker_id=worker_id,
                lease_expires_at=lease_expires_at,
                lease_token=lease_token,
            )

    def recover_expired_claims(self, now: datetime) -> int:
        recovery_timestamp = _require_datetime(now, "now")
        recovered_at = require_utc(recovery_timestamp, "now")
        recovered_text = recovered_at.isoformat()
        recovered_count = 0

        with self._write() as connection:
            rows = connection.execute(
                """
                SELECT sha256, lease_owner, lease_expires_at, lease_token
                FROM artifacts
                WHERE state = 'SCANNING' AND lease_expires_at <= ?
                ORDER BY lease_expires_at, sha256
                """,
                (recovered_text,),
            ).fetchall()
            for row in rows:
                cursor = connection.execute(
                    """
                    UPDATE artifacts
                    SET state = 'DISCOVERED', lease_owner = NULL,
                        lease_expires_at = NULL, lease_token = NULL,
                        updated_at = ?
                    WHERE sha256 = ? AND state = 'SCANNING'
                      AND lease_owner = ? AND lease_expires_at = ?
                      AND lease_token = ?
                    """,
                    (
                        recovered_text,
                        row["sha256"],
                        row["lease_owner"],
                        row["lease_expires_at"],
                        row["lease_token"],
                    ),
                )
                if cursor.rowcount != 1:
                    continue
                recovered_count += 1
                self._audit(
                    connection,
                    actor=row["lease_owner"],
                    action="artifact.lease_expired",
                    sha256=row["sha256"],
                    reason="analysis lease expired",
                    occurred_at=recovered_at,
                )

        return recovered_count

    def record_verdict(
        self,
        claim: ClaimedArtifact,
        verdict: VerdictInput,
        evidence: Sequence[EvidenceInput],
    ) -> None:
        (
            claim_sha256,
            claim_size_bytes,
            claim_worker_id,
            claim_expires_at,
            claim_expires_text,
            claim_token,
        ) = _prepare_claim(claim)
        if type(verdict) is not VerdictInput:
            raise ValueError("verdict must be a VerdictInput")
        try:
            sha256 = validate_sha256(verdict.sha256)
            decision = verdict.decision
            score = _normalize_score(verdict.score)
            policy_version = _require_stored_string(
                verdict.policy_version,
                "policy_version",
            )
            analyzer_version = _require_stored_string(
                verdict.analyzer_version,
                "analyzer_version",
            )
            baseline_sha256 = verdict.baseline_sha256
            baseline_tier = verdict.baseline_tier
            created_at_value = require_utc(
                _require_datetime(verdict.created_at, "created_at"),
                "created_at",
            )
            created_at = created_at_value.isoformat()
            cooldown_until_value = verdict.cooldown_until
        except AttributeError:
            message = "VerdictInput missing required fields"
            raise ValueError(message) from None
        if type(decision) is not Decision:
            raise ValueError("decision must be a Decision")
        if baseline_sha256 is not None:
            baseline_sha256 = validate_sha256(baseline_sha256)
        if (baseline_sha256 is None) != (baseline_tier is None):
            message = "baseline_sha256 and baseline_tier must be paired"
            raise ValueError(message)
        if baseline_tier is not None:
            baseline_tier = validate_baseline_tier(baseline_tier)
        cooldown_until = None
        if cooldown_until_value is not None:
            cooldown_until_at = require_utc(
                _require_datetime(cooldown_until_value, "cooldown_until"),
                "cooldown_until",
            )
            if decision is not Decision.ALLOW:
                raise ValueError("cooldown requires an ALLOW verdict")
            if cooldown_until_at <= created_at_value:
                raise ValueError("cooldown_until must be later than created_at")
            cooldown_until = cooldown_until_at.isoformat()
        if sha256 != claim_sha256:
            raise TransitionConflict(sha256)

        prepared_evidence = _prepare_evidence(evidence)

        with self._write() as connection:
            operation_at = require_utc(
                _require_datetime(self._now(), "now"),
                "now",
            )
            if claim_expires_at <= operation_at:
                raise TransitionConflict(claim_sha256)
            updated_at = operation_at.isoformat()
            artifact_row = connection.execute(
                """
                SELECT sha256, size_bytes, state, lease_owner,
                       lease_expires_at, lease_token, cooldown_started_at,
                       cooldown_until
                FROM artifacts WHERE sha256 = ?
                """,
                (claim_sha256,),
            ).fetchone()
            if artifact_row is None or tuple(artifact_row)[:6] != (
                claim_sha256,
                claim_size_bytes,
                "SCANNING",
                claim_worker_id,
                claim_expires_text,
                claim_token,
            ):
                raise TransitionConflict(claim_sha256)
            stored_cooldown_started_at = artifact_row["cooldown_started_at"]
            stored_cooldown_until = artifact_row["cooldown_until"]
            expected_cooldown_started_at = (
                stored_cooldown_started_at
                if stored_cooldown_started_at is not None
                else created_at
                if cooldown_until is not None
                else None
            )
            expected_cooldown_until = (
                stored_cooldown_until if stored_cooldown_until is not None else cooldown_until
            )

            if baseline_sha256 is not None:
                baseline = connection.execute(
                    "SELECT 1 FROM artifacts WHERE sha256 = ?",
                    (baseline_sha256,),
                ).fetchone()
                if baseline is None:
                    raise ArtifactNotFound(baseline_sha256)

            current_rows = connection.execute(
                "SELECT id FROM verdicts WHERE sha256 = ? AND is_current = 1",
                (sha256,),
            ).fetchall()
            if len(current_rows) > 1:
                raise TransitionConflict("multiple current verdicts")
            if current_rows:
                current_id = current_rows[0]["id"]
                cleared = connection.execute(
                    """
                    UPDATE verdicts SET is_current = 0
                    WHERE id = ? AND is_current = 1
                    """,
                    (current_id,),
                )
                if cleared.rowcount != 1:
                    raise TransitionConflict("current verdict update failed")

            inserted = connection.execute(
                """
                INSERT INTO verdicts(
                    sha256, decision, score, policy_version, analyzer_version,
                    baseline_sha256, is_current, created_at, baseline_tier
                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    sha256,
                    decision.value,
                    score,
                    policy_version,
                    analyzer_version,
                    baseline_sha256,
                    created_at,
                    baseline_tier,
                ),
            )
            if inserted.rowcount != 1 or type(inserted.lastrowid) is not int:
                raise TransitionConflict("verdict insert was ignored")
            verdict_id = inserted.lastrowid

            for item in prepared_evidence:
                evidence_cursor = connection.execute(
                    """
                    INSERT INTO evidence(
                        verdict_id, rule_id, action, file_path, line, message,
                        details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (verdict_id, *item),
                )
                if evidence_cursor.rowcount != 1:
                    raise TransitionConflict("evidence insert was ignored")

            terminal = connection.execute(
                """
                UPDATE artifacts
                SET state = ?, lease_owner = NULL, lease_expires_at = NULL,
                    lease_token = NULL, last_error = NULL, updated_at = ?,
                    cooldown_started_at = COALESCE(cooldown_started_at, ?),
                    cooldown_until = COALESCE(cooldown_until, ?)
                WHERE sha256 = ? AND size_bytes = ?
                  AND state = 'SCANNING' AND lease_owner = ?
                  AND lease_expires_at = ? AND lease_token = ?
                  AND lease_expires_at > ?
                """,
                (
                    decision.value,
                    updated_at,
                    created_at if cooldown_until is not None else None,
                    cooldown_until,
                    claim_sha256,
                    claim_size_bytes,
                    claim_worker_id,
                    claim_expires_text,
                    claim_token,
                    updated_at,
                ),
            )
            if terminal.rowcount != 1:
                raise TransitionConflict(claim_sha256)

            final_artifact = connection.execute(
                """
                SELECT state, lease_owner, lease_expires_at, lease_token,
                       last_error, updated_at, cooldown_started_at,
                       cooldown_until
                FROM artifacts WHERE sha256 = ?
                """,
                (claim_sha256,),
            ).fetchone()
            if final_artifact is None or tuple(final_artifact) != (
                decision.value,
                None,
                None,
                None,
                None,
                updated_at,
                expected_cooldown_started_at,
                expected_cooldown_until,
            ):
                raise TransitionConflict("artifact terminal state mismatch")

            stored_verdict = connection.execute(
                """
                SELECT sha256, decision, score, policy_version,
                       analyzer_version,
                       baseline_sha256, is_current, created_at, baseline_tier
                FROM verdicts WHERE id = ?
                """,
                (verdict_id,),
            ).fetchone()
            if stored_verdict is None or tuple(stored_verdict) != (
                sha256,
                decision.value,
                score,
                policy_version,
                analyzer_version,
                baseline_sha256,
                1,
                created_at,
                baseline_tier,
            ):
                raise TransitionConflict("stored verdict mismatch")

            stored_evidence = connection.execute(
                """
                SELECT rule_id, action, file_path, line, message, details_json
                FROM evidence WHERE verdict_id = ? ORDER BY id
                """,
                (verdict_id,),
            ).fetchall()
            persisted_evidence = [tuple(row) for row in stored_evidence]
            if persisted_evidence != list(prepared_evidence):
                raise TransitionConflict("stored evidence mismatch")

            current = connection.execute(
                """
                SELECT id FROM verdicts
                WHERE sha256 = ? AND is_current = 1
                """,
                (sha256,),
            ).fetchall()
            if [row["id"] for row in current] != [verdict_id]:
                raise TransitionConflict("new verdict is not uniquely current")

            is_allow = decision is Decision.ALLOW
            effective_decision = Decision.ALLOW if is_allow else Decision.DENY
            self._audit(
                connection,
                actor="guardian-policy",
                action="artifact.verdict_recorded",
                sha256=sha256,
                previous=Decision.DENY,
                new=effective_decision,
                reason="automated policy decision",
                policy_version=policy_version,
                analyzer_version=analyzer_version,
                occurred_at=operation_at,
            )

    def mark_analysis_error(
        self,
        claim: ClaimedArtifact,
        error: str,
    ) -> None:
        (
            claim_sha256,
            claim_size_bytes,
            claim_worker_id,
            claim_expires_at,
            claim_expires_text,
            claim_token,
        ) = _prepare_claim(claim)
        message = _sanitize_analysis_error(error)

        with self._write() as connection:
            operation_at = require_utc(
                _require_datetime(self._now(), "now"),
                "now",
            )
            if claim_expires_at <= operation_at:
                raise TransitionConflict(claim_sha256)
            updated_at = operation_at.isoformat()
            artifact_row = connection.execute(
                """
                SELECT sha256, size_bytes, state, lease_owner,
                       lease_expires_at, lease_token
                FROM artifacts WHERE sha256 = ?
                """,
                (claim_sha256,),
            ).fetchone()
            if artifact_row is None or tuple(artifact_row) != (
                claim_sha256,
                claim_size_bytes,
                "SCANNING",
                claim_worker_id,
                claim_expires_text,
                claim_token,
            ):
                raise TransitionConflict(claim_sha256)

            updated = connection.execute(
                """
                UPDATE artifacts
                SET state = 'ERROR', lease_owner = NULL,
                    lease_expires_at = NULL, lease_token = NULL,
                    last_error = ?, updated_at = ?
                WHERE sha256 = ? AND size_bytes = ?
                  AND state = 'SCANNING' AND lease_owner = ?
                  AND lease_expires_at = ? AND lease_token = ?
                  AND lease_expires_at > ?
                """,
                (
                    message,
                    updated_at,
                    claim_sha256,
                    claim_size_bytes,
                    claim_worker_id,
                    claim_expires_text,
                    claim_token,
                    updated_at,
                ),
            )
            if updated.rowcount != 1:
                raise TransitionConflict(claim_sha256)

            final_artifact = connection.execute(
                """
                SELECT state, lease_owner, lease_expires_at, lease_token,
                       last_error, updated_at
                FROM artifacts WHERE sha256 = ?
                """,
                (claim_sha256,),
            ).fetchone()
            if final_artifact is None or tuple(final_artifact) != (
                "ERROR",
                None,
                None,
                None,
                message,
                updated_at,
            ):
                raise TransitionConflict("analysis error state mismatch")

            self._audit(
                connection,
                actor="guardian-worker",
                action="artifact.analysis_error",
                sha256=claim_sha256,
                reason="analysis failed",
                occurred_at=operation_at,
            )

    def _administrator_context(
        self,
        connection: sqlite3.Connection,
        sha256: str,
        operation_at: datetime,
    ) -> tuple[sqlite3.Row, sqlite3.Row | None, PersistedStateContext]:
        artifact_row = connection.execute(
            "SELECT * FROM artifacts WHERE sha256 = ?",
            (sha256,),
        ).fetchone()
        if artifact_row is None:
            raise ArtifactNotFound(sha256)

        verdict_rows = connection.execute(
            """
            SELECT *
            FROM verdicts
            WHERE sha256 = ? AND is_current = 1
            ORDER BY id LIMIT 2
            """,
            (sha256,),
        ).fetchall()

        override_rows = connection.execute(
            """
            SELECT id, sha256, decision, actor, reason, created_at,
                   expires_at, is_current
            FROM manual_overrides
            WHERE sha256 = ? AND is_current = 1
            ORDER BY id LIMIT 2
            """,
            (sha256,),
        ).fetchall()
        try:
            if len(verdict_rows) > 1:
                raise PersistedStateCorruption("multiple current verdicts")
            if len(override_rows) > 1:
                raise PersistedStateCorruption("multiple current overrides")
            current_verdict = verdict_rows[0] if verdict_rows else None
            current_override = override_rows[0] if override_rows else None
            context = validate_persisted_state(
                artifact_row,
                current_verdict,
                current_override,
                operation_at,
            )
        except PersistedStateCorruption as exc:
            path = str(self.connection_factory.path)
            raise StoreUnavailable(path) from exc
        return artifact_row, current_override, context

    @staticmethod
    def _history_counts(
        connection: sqlite3.Connection,
        sha256: str,
    ) -> tuple[int, int, int]:
        row = connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM verdicts WHERE sha256 = ?),
                (
                    SELECT COUNT(*) FROM evidence AS e
                    JOIN verdicts AS v ON v.id = e.verdict_id
                    WHERE v.sha256 = ?
                ),
                (SELECT COUNT(*) FROM manual_overrides WHERE sha256 = ?)
            """,
            (sha256, sha256, sha256),
        ).fetchone()
        if row is None or any(type(value) is not int for value in row):
            raise TransitionConflict("history count failed")
        return tuple(row)

    @staticmethod
    def _baseline_history(
        connection: sqlite3.Connection,
        sha256: str,
    ) -> tuple[tuple[object, ...], ...]:
        rows = connection.execute(
            """
            SELECT id, sha256, enabled, actor, reason, created_at, is_current
            FROM baseline_overrides
            WHERE sha256 = ? ORDER BY id
            """,
            (sha256,),
        ).fetchall()
        return tuple(tuple(row) for row in rows)

    def _verify_baseline_history(
        self,
        connection: sqlite3.Connection,
        sha256: str,
        expected: tuple[tuple[object, ...], ...],
    ) -> None:
        if self._baseline_history(connection, sha256) != expected:
            raise TransitionConflict("baseline override history changed")

    def _verify_administrator_result(
        self,
        connection: sqlite3.Connection,
        *,
        sha256: str,
        operation_at: datetime,
        expected_artifact: tuple[object, ...],
        expected_counts: tuple[int, int, int],
        expected_verdict_id: int | None,
        expected_override: tuple[object, ...] | None,
    ) -> None:
        artifact = connection.execute(
            "SELECT * FROM artifacts WHERE sha256 = ?",
            (sha256,),
        ).fetchone()
        if artifact is None or tuple(artifact) != expected_artifact:
            raise TransitionConflict("administrator artifact state changed")
        if self._history_counts(connection, sha256) != expected_counts:
            raise TransitionConflict("administrator history count changed")

        verdict_rows = connection.execute(
            """
            SELECT * FROM verdicts
            WHERE sha256 = ? AND is_current = 1
            ORDER BY id LIMIT 2
            """,
            (sha256,),
        ).fetchall()
        override_rows = connection.execute(
            """
            SELECT id, sha256, decision, actor, reason, created_at,
                   expires_at, is_current
            FROM manual_overrides
            WHERE sha256 = ? AND is_current = 1
            ORDER BY id LIMIT 2
            """,
            (sha256,),
        ).fetchall()
        verdict_ids = [row["id"] for row in verdict_rows]
        expected_verdict_ids = []
        if expected_verdict_id is not None:
            expected_verdict_ids = [expected_verdict_id]
        if verdict_ids != expected_verdict_ids:
            raise TransitionConflict("current verdict changed")
        expected_override_rows = []
        if expected_override is not None:
            expected_override_rows = [expected_override]
        if [tuple(row) for row in override_rows] != expected_override_rows:
            corruption = PersistedStateCorruption(
                "current override changed",
            )
            path = str(self.connection_factory.path)
            raise StoreUnavailable(path) from corruption
        try:
            validate_persisted_state(
                artifact,
                verdict_rows[0] if verdict_rows else None,
                override_rows[0] if override_rows else None,
                operation_at,
            )
        except PersistedStateCorruption as exc:
            path = str(self.connection_factory.path)
            raise StoreUnavailable(path) from exc

    @staticmethod
    def _deactivate_override(
        connection: sqlite3.Connection,
        current_override: sqlite3.Row,
    ) -> None:
        override_id = current_override["id"]
        cleared = connection.execute(
            """
            UPDATE manual_overrides SET is_current = 0
            WHERE id = ? AND is_current = 1
            """,
            (override_id,),
        )
        if cleared.rowcount != 1:
            raise TransitionConflict("current override update failed")
        persisted = connection.execute(
            """
            SELECT id, sha256, decision, actor, reason, created_at,
                   expires_at, is_current
            FROM manual_overrides WHERE id = ?
            """,
            (override_id,),
        ).fetchone()
        expected = (*tuple(current_override)[:-1], 0)
        if persisted is None or tuple(persisted) != expected:
            raise TransitionConflict("override history changed")

    def set_manual_override(self, override: ManualOverrideInput) -> None:
        (
            sha256,
            decision,
            actor,
            reason,
            created_at,
            expires_at,
            expires_text,
        ) = _prepare_manual_override(override)

        with self._write() as connection:
            operation_at = require_utc(
                _require_datetime(self._now(), "now"),
                "now",
            )
            if expires_at is not None and expires_at <= operation_at:
                raise ValueError("expires_at must be in the future")
            administrator = self._administrator_context(
                connection,
                sha256,
                operation_at,
            )
            artifact_row, current_override, state_context = administrator
            if state_context.artifact_state.value not in _TERMINAL_STATES:
                raise TransitionConflict(sha256)
            artifact_snapshot = tuple(artifact_row)
            history_counts = self._history_counts(connection, sha256)
            expected_counts = (
                history_counts[0],
                history_counts[1],
                history_counts[2] + 1,
            )
            if current_override is not None:
                self._deactivate_override(connection, current_override)

            inserted = connection.execute(
                """
                INSERT INTO manual_overrides(
                    sha256, decision, actor, reason, created_at, expires_at,
                    is_current
                ) VALUES (?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    sha256,
                    decision.value,
                    actor,
                    reason,
                    created_at,
                    expires_text,
                ),
            )
            if inserted.rowcount != 1 or type(inserted.lastrowid) is not int:
                raise TransitionConflict("override insert was ignored")
            override_id = inserted.lastrowid
            expected_override = (
                override_id,
                sha256,
                decision.value,
                actor,
                reason,
                created_at,
                expires_text,
                1,
            )
            stored = connection.execute(
                """
                SELECT id, sha256, decision, actor, reason, created_at,
                       expires_at, is_current
                FROM manual_overrides WHERE id = ?
                """,
                (override_id,),
            ).fetchone()
            if stored is None or tuple(stored) != expected_override:
                raise TransitionConflict("stored override mismatch")
            verification = {
                "sha256": sha256,
                "operation_at": operation_at,
                "expected_artifact": artifact_snapshot,
                "expected_counts": expected_counts,
                "expected_verdict_id": state_context.current_verdict_id,
                "expected_override": expected_override,
            }
            self._verify_administrator_result(connection, **verification)

            self._audit(
                connection,
                actor=actor,
                action="artifact.override_set",
                sha256=sha256,
                previous=state_context.effective_decision,
                new=decision,
                reason=reason,
                policy_version=state_context.policy_version,
                analyzer_version=state_context.analyzer_version,
                occurred_at=operation_at,
            )
            self._verify_administrator_result(connection, **verification)

    def revoke_manual_override(
        self,
        sha256: str,
        actor: str,
        reason: str,
    ) -> None:
        sha256, actor, reason = _prepare_admin_command(
            sha256,
            actor,
            reason,
        )

        with self._write() as connection:
            operation_at = require_utc(
                _require_datetime(self._now(), "now"),
                "now",
            )
            administrator = self._administrator_context(
                connection,
                sha256,
                operation_at,
            )
            artifact_row, current_override, state_context = administrator
            if state_context.artifact_state.value not in _TERMINAL_STATES:
                raise TransitionConflict(sha256)
            if current_override is None:
                raise TransitionConflict(sha256)
            artifact_snapshot = tuple(artifact_row)
            history_counts = self._history_counts(connection, sha256)
            self._deactivate_override(connection, current_override)
            verification = {
                "sha256": sha256,
                "operation_at": operation_at,
                "expected_artifact": artifact_snapshot,
                "expected_counts": history_counts,
                "expected_verdict_id": state_context.current_verdict_id,
                "expected_override": None,
            }
            self._verify_administrator_result(connection, **verification)
            self._audit(
                connection,
                actor=actor,
                action="artifact.override_revoked",
                sha256=sha256,
                previous=state_context.effective_decision,
                new=state_context.fallback_decision,
                reason=reason,
                policy_version=state_context.policy_version,
                analyzer_version=state_context.analyzer_version,
                occurred_at=operation_at,
            )
            self._verify_administrator_result(connection, **verification)

    def request_rescan(
        self,
        sha256: str,
        actor: str,
        reason: str,
    ) -> None:
        sha256, actor, reason = _prepare_admin_command(
            sha256,
            actor,
            reason,
        )

        with self._write() as connection:
            operation_at = require_utc(
                _require_datetime(self._now(), "now"),
                "now",
            )
            operation_text = operation_at.isoformat()
            administrator = self._administrator_context(
                connection,
                sha256,
                operation_at,
            )
            artifact_row, current_override, state_context = administrator
            state = state_context.artifact_state.value
            if state not in _TERMINAL_STATES:
                raise TransitionConflict(sha256)
            history_counts = self._history_counts(connection, sha256)

            updated = connection.execute(
                """
                UPDATE artifacts
                SET state = 'DISCOVERED', lease_owner = NULL,
                    lease_expires_at = NULL, lease_token = NULL,
                    last_error = NULL, updated_at = ?
                WHERE sha256 = ? AND state = ?
                """,
                (operation_text, sha256, state),
            )
            if updated.rowcount != 1:
                raise TransitionConflict(sha256)
            if current_override is not None:
                self._deactivate_override(connection, current_override)
            expected_artifact = (
                artifact_row["sha256"],
                artifact_row["size_bytes"],
                "DISCOVERED",
                artifact_row["discovered_at"],
                operation_text,
                None,
                None,
                None,
                None,
                artifact_row["cooldown_started_at"],
                artifact_row["cooldown_until"],
            )
            verification = {
                "sha256": sha256,
                "operation_at": operation_at,
                "expected_artifact": expected_artifact,
                "expected_counts": history_counts,
                "expected_verdict_id": state_context.current_verdict_id,
                "expected_override": None,
            }
            self._verify_administrator_result(connection, **verification)
            self._audit(
                connection,
                actor=actor,
                action="artifact.rescan_requested",
                sha256=sha256,
                previous=state_context.effective_decision,
                new=Decision.DENY,
                reason=reason,
                policy_version=state_context.policy_version,
                analyzer_version=state_context.analyzer_version,
                occurred_at=operation_at,
            )
            self._verify_administrator_result(connection, **verification)
