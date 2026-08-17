from __future__ import annotations

import json
import math
import secrets
import sqlite3
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from urllib.parse import SplitResult, urlsplit, urlunsplit

from devpi_common.metadata import normalize_name

from .db import ConnectionFactory
from .errors import ArtifactNotFound, StoreUnavailable, TransitionConflict
from .interfaces import AuditWriter
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
    validate_sha256,
)

_MAX_SQLITE_INTEGER = 2**63 - 1
_MAX_STORED_TEXT_LENGTH = 4096
_MAX_DETAILS_JSON_LENGTH = 1024 * 1024
_MAX_ANALYSIS_ERROR_LENGTH = 4096
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
    return "".join(
        " "
        if (
            ord(character) < 32
            or 127 <= ord(character) <= 159
            or 0xD800 <= ord(character) <= 0xDFFF
        )
        else character
        for character in value[:_MAX_ANALYSIS_ERROR_LENGTH]
    )


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
            message = _require_stored_string(item.message, "message")
            details_json = _serialize_details(item.details)
        except AttributeError:
            message = "EvidenceInput missing required fields"
            raise ValueError(message) from None
        if type(action) is not Decision:
            raise ValueError("action must be a Decision")
        file_path = (
            None
            if file_path_value is None
            else _require_stored_string(file_path_value, "file_path")
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


def _stored_expiry(value: object) -> datetime | None:
    if value is None:
        return None
    try:
        if type(value) is not str:
            raise ValueError("stored override expiry is invalid")
        parsed = datetime.fromisoformat(value)
        return require_utc(parsed, "stored override expiry")
    except (OverflowError, ValueError) as exc:
        raise ValueError("stored override expiry is invalid") from exc


def _effective_decision(
    state: str,
    automated_decision: object,
    current_override: sqlite3.Row | None,
    as_of: datetime,
) -> Decision:
    fallback = (
        Decision.ALLOW
        if state == "ALLOW" and automated_decision == Decision.ALLOW.value
        else Decision.DENY
    )
    if current_override is None or state not in _TERMINAL_STATES:
        return fallback
    manual_raw = current_override["decision"]
    try:
        manual = Decision(manual_raw)
    except (TypeError, ValueError):
        raise ValueError("stored override decision is invalid") from None
    if manual not in (Decision.ALLOW, Decision.DENY):
        raise ValueError("stored override decision is invalid")
    expires_at = _stored_expiry(current_override["expires_at"])
    return manual if expires_at is None or expires_at > as_of else fallback


def _deactivated_history(
    history: list[tuple[object, ...]],
    current_id: int | None,
) -> list[tuple[object, ...]]:
    return [(*row[:-1], 0) if row[0] == current_id else row for row in history]


def _sanitize_origin_url(value: str) -> str:
    origin_url = _require_nonblank_string(value, "origin_url")
    try:
        parsed = urlsplit(origin_url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError("origin_url must be a valid absolute URL") from None
    if (
        not parsed.scheme
        or not parsed.netloc
        or hostname is None
        or not hostname
        or any(character.isspace() for character in hostname)
    ):
        raise ValueError("origin_url must be a valid absolute URL")

    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host if port is None else f"{host}:{port}"
    sanitized = SplitResult(parsed.scheme, netloc, parsed.path, "", "")
    return urlunsplit(sanitized)


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
        origin_url = _sanitize_origin_url(origin_input)
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
                SELECT sha256, size_bytes
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
            persisted = connection.execute(
                """
                SELECT sha256, size_bytes, state, lease_owner,
                       lease_expires_at, lease_token, last_error, updated_at
                FROM artifacts WHERE sha256 = ?
                """,
                (row["sha256"],),
            ).fetchone()
            if persisted is None or tuple(persisted) != (
                row["sha256"],
                row["size_bytes"],
                "SCANNING",
                worker_id,
                lease_text,
                lease_token,
                None,
                updated_at,
            ):
                raise TransitionConflict("artifact claim state mismatch")
            self._audit(
                connection,
                actor=worker_id,
                action="artifact.claimed",
                sha256=row["sha256"],
                reason="analysis lease acquired",
                occurred_at=operation_at,
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
            created_at = _iso(verdict.created_at, "created_at")
        except AttributeError:
            message = "VerdictInput missing required fields"
            raise ValueError(message) from None
        if type(decision) is not Decision:
            raise ValueError("decision must be a Decision")
        if baseline_sha256 is not None:
            baseline_sha256 = validate_sha256(baseline_sha256)
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
                    baseline_sha256, is_current, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    sha256,
                    decision.value,
                    score,
                    policy_version,
                    analyzer_version,
                    baseline_sha256,
                    created_at,
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
                    lease_token = NULL, last_error = NULL, updated_at = ?
                WHERE sha256 = ? AND size_bytes = ?
                  AND state = 'SCANNING' AND lease_owner = ?
                  AND lease_expires_at = ? AND lease_token = ?
                  AND lease_expires_at > ?
                """,
                (
                    decision.value,
                    updated_at,
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
                       last_error, updated_at
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
            ):
                raise TransitionConflict("artifact terminal state mismatch")

            stored_verdict = connection.execute(
                """
                SELECT sha256, decision, score, policy_version,
                       analyzer_version,
                       baseline_sha256, is_current, created_at
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
    ) -> tuple[sqlite3.Row, sqlite3.Row | None, Decision, Decision]:
        artifact_row = connection.execute(
            "SELECT * FROM artifacts WHERE sha256 = ?",
            (sha256,),
        ).fetchone()
        if artifact_row is None:
            raise ArtifactNotFound(sha256)

        verdict_rows = connection.execute(
            """
            SELECT decision FROM verdicts
            WHERE sha256 = ? AND is_current = 1
            """,
            (sha256,),
        ).fetchall()
        if len(verdict_rows) > 1:
            raise TransitionConflict("multiple current verdicts")
        automated_decision = None
        if verdict_rows:
            automated_decision = verdict_rows[0]["decision"]

        override_rows = connection.execute(
            """
            SELECT id, sha256, decision, actor, reason, created_at,
                   expires_at, is_current
            FROM manual_overrides
            WHERE sha256 = ? AND is_current = 1
            """,
            (sha256,),
        ).fetchall()
        if len(override_rows) > 1:
            raise TransitionConflict("multiple current overrides")
        current_override = override_rows[0] if override_rows else None
        try:
            fallback = _effective_decision(
                artifact_row["state"],
                automated_decision,
                None,
                operation_at,
            )
            effective = _effective_decision(
                artifact_row["state"],
                automated_decision,
                current_override,
                operation_at,
            )
        except (OverflowError, TypeError, ValueError) as exc:
            path = str(self.connection_factory.path)
            raise StoreUnavailable(path) from exc
        return artifact_row, current_override, effective, fallback

    @staticmethod
    def _override_history(
        connection: sqlite3.Connection,
        sha256: str,
    ) -> list[tuple[object, ...]]:
        rows = connection.execute(
            """
            SELECT id, sha256, decision, actor, reason, created_at,
                   expires_at, is_current
            FROM manual_overrides WHERE sha256 = ? ORDER BY id
            """,
            (sha256,),
        ).fetchall()
        return [tuple(row) for row in rows]

    @staticmethod
    def _verdict_history(
        connection: sqlite3.Connection,
        sha256: str,
    ) -> list[tuple[object, ...]]:
        rows = connection.execute(
            "SELECT * FROM verdicts WHERE sha256 = ? ORDER BY id",
            (sha256,),
        ).fetchall()
        return [tuple(row) for row in rows]

    @staticmethod
    def _evidence_history(
        connection: sqlite3.Connection,
        sha256: str,
    ) -> list[tuple[object, ...]]:
        rows = connection.execute(
            """
            SELECT e.* FROM evidence AS e
            JOIN verdicts AS v ON v.id = e.verdict_id
            WHERE v.sha256 = ? ORDER BY e.id
            """,
            (sha256,),
        ).fetchall()
        return [tuple(row) for row in rows]

    @classmethod
    def _verify_unchanged_automated_state(
        cls,
        connection: sqlite3.Connection,
        sha256: str,
        artifact_snapshot: tuple[object, ...],
        verdict_snapshot: list[tuple[object, ...]],
        evidence_snapshot: list[tuple[object, ...]],
    ) -> None:
        artifact = connection.execute(
            "SELECT * FROM artifacts WHERE sha256 = ?",
            (sha256,),
        ).fetchone()
        if artifact is None or tuple(artifact) != artifact_snapshot:
            raise TransitionConflict("artifact changed during override")
        if cls._verdict_history(connection, sha256) != verdict_snapshot:
            raise TransitionConflict("verdict history changed")
        if cls._evidence_history(connection, sha256) != evidence_snapshot:
            raise TransitionConflict("evidence history changed")

    @classmethod
    def _verify_override_history(
        cls,
        connection: sqlite3.Connection,
        sha256: str,
        expected: list[tuple[object, ...]],
    ) -> None:
        if cls._override_history(connection, sha256) != expected:
            raise TransitionConflict("override history changed")

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
            context = self._administrator_context(
                connection,
                sha256,
                operation_at,
            )
            artifact_row, current_override, previous, _fallback = context
            if artifact_row["state"] not in _TERMINAL_STATES:
                raise TransitionConflict(sha256)
            artifact_snapshot = tuple(artifact_row)
            verdict_snapshot = self._verdict_history(connection, sha256)
            evidence_snapshot = self._evidence_history(connection, sha256)
            override_snapshot = self._override_history(connection, sha256)
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
            stored = connection.execute(
                """
                SELECT sha256, decision, actor, reason, created_at,
                       expires_at, is_current
                FROM manual_overrides WHERE id = ?
                """,
                (override_id,),
            ).fetchone()
            if stored is None or tuple(stored) != (
                sha256,
                decision.value,
                actor,
                reason,
                created_at,
                expires_text,
                1,
            ):
                raise TransitionConflict("stored override mismatch")
            current_rows = connection.execute(
                """
                SELECT id FROM manual_overrides
                WHERE sha256 = ? AND is_current = 1
                """,
                (sha256,),
            ).fetchall()
            if [row["id"] for row in current_rows] != [override_id]:
                message = "new override is not uniquely current"
                raise TransitionConflict(message)
            current_id = None
            if current_override is not None:
                current_id = current_override["id"]
            expected_history = _deactivated_history(
                override_snapshot,
                current_id,
            )
            expected_history.append(
                (
                    override_id,
                    sha256,
                    decision.value,
                    actor,
                    reason,
                    created_at,
                    expires_text,
                    1,
                ),
            )
            self._verify_override_history(
                connection,
                sha256,
                expected_history,
            )
            self._verify_unchanged_automated_state(
                connection,
                sha256,
                artifact_snapshot,
                verdict_snapshot,
                evidence_snapshot,
            )

            self._audit(
                connection,
                actor=actor,
                action="artifact.override_set",
                sha256=sha256,
                previous=previous,
                new=decision,
                reason=reason,
                occurred_at=operation_at,
            )

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
            context = self._administrator_context(
                connection,
                sha256,
                operation_at,
            )
            artifact_row, current_override, previous, fallback = context
            if artifact_row["state"] not in _TERMINAL_STATES:
                raise TransitionConflict(sha256)
            if current_override is None:
                raise TransitionConflict(sha256)
            artifact_snapshot = tuple(artifact_row)
            verdict_snapshot = self._verdict_history(connection, sha256)
            evidence_snapshot = self._evidence_history(connection, sha256)
            override_snapshot = self._override_history(connection, sha256)
            self._deactivate_override(connection, current_override)
            current_rows = connection.execute(
                """
                SELECT id FROM manual_overrides
                WHERE sha256 = ? AND is_current = 1
                """,
                (sha256,),
            ).fetchall()
            if current_rows:
                raise TransitionConflict("override remains current")
            expected_history = _deactivated_history(
                override_snapshot,
                current_override["id"],
            )
            self._verify_override_history(
                connection,
                sha256,
                expected_history,
            )
            self._verify_unchanged_automated_state(
                connection,
                sha256,
                artifact_snapshot,
                verdict_snapshot,
                evidence_snapshot,
            )
            self._audit(
                connection,
                actor=actor,
                action="artifact.override_revoked",
                sha256=sha256,
                previous=previous,
                new=fallback,
                reason=reason,
                occurred_at=operation_at,
            )

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
            context = self._administrator_context(
                connection,
                sha256,
                operation_at,
            )
            artifact_row, current_override, previous, _fallback = context
            state = artifact_row["state"]
            if state not in _TERMINAL_STATES:
                raise TransitionConflict(sha256)
            verdict_snapshot = self._verdict_history(connection, sha256)
            evidence_snapshot = self._evidence_history(connection, sha256)
            override_snapshot = self._override_history(connection, sha256)

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

            final_artifact = connection.execute(
                """
                SELECT state, lease_owner, lease_expires_at, lease_token,
                       last_error, updated_at
                FROM artifacts WHERE sha256 = ?
                """,
                (sha256,),
            ).fetchone()
            if final_artifact is None or tuple(final_artifact) != (
                "DISCOVERED",
                None,
                None,
                None,
                None,
                operation_text,
            ):
                raise TransitionConflict("artifact rescan state mismatch")
            current_rows = connection.execute(
                """
                SELECT id FROM manual_overrides
                WHERE sha256 = ? AND is_current = 1
                """,
                (sha256,),
            ).fetchall()
            if current_rows:
                raise TransitionConflict("override remains current")
            current_id = None
            if current_override is not None:
                current_id = current_override["id"]
            expected_history = _deactivated_history(
                override_snapshot,
                current_id,
            )
            self._verify_override_history(
                connection,
                sha256,
                expected_history,
            )
            if self._verdict_history(connection, sha256) != verdict_snapshot:
                raise TransitionConflict("verdict history changed")
            if self._evidence_history(connection, sha256) != evidence_snapshot:
                raise TransitionConflict("evidence history changed")

            self._audit(
                connection,
                actor=actor,
                action="artifact.rescan_requested",
                sha256=sha256,
                previous=previous,
                new=Decision.DENY,
                reason=reason,
                occurred_at=operation_at,
            )
