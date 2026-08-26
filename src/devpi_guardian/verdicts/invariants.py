from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from devpi_common.metadata import normalize_name

from .models import (
    AllowedRelease,
    ArtifactState,
    Decision,
    DecisionSource,
    validate_baseline_tier,
)
from .releases import sanitize_origin_url

_MAX_SQLITE_INTEGER = 2**63 - 1
_MAX_STORED_TEXT_LENGTH = 4096
_TERMINAL_STATES = {
    ArtifactState.ALLOW,
    ArtifactState.REVIEW,
    ArtifactState.DENY,
    ArtifactState.ERROR,
}
_VERDICT_STATES = {
    ArtifactState.ALLOW,
    ArtifactState.REVIEW,
    ArtifactState.DENY,
}


class PersistedStateCorruption(ValueError):
    """A persisted row violates the Guardian schema or state machine."""


@dataclass(frozen=True, slots=True)
class PersistedStateContext:
    artifact_state: ArtifactState
    effective_decision: Decision
    fallback_decision: Decision
    source: DecisionSource
    policy_version: str | None
    analyzer_version: str | None
    current_verdict_id: int | None
    current_override_id: int | None
    cooldown_until: datetime | None
    cooldown_finished: bool


def _optional_field(
    row: Mapping[str, object],
    name: str,
    default: object = None,
) -> object:
    try:
        return row[name]
    except (IndexError, KeyError, TypeError):
        return default


def _field(row: Mapping[str, object], name: str) -> object:
    try:
        return row[name]
    except (IndexError, KeyError, TypeError) as exc:
        raise PersistedStateCorruption(f"missing persisted {name}") from exc


def _sqlite_id(value: object, field_name: str) -> int:
    if type(value) is not int or not 0 < value <= _MAX_SQLITE_INTEGER:
        raise PersistedStateCorruption(f"invalid persisted {field_name}")
    return value


def _canonical_sha256(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PersistedStateCorruption(f"invalid persisted {field_name}")
    return value


def _stored_text(
    value: object,
    field_name: str,
    *,
    nonblank: bool = True,
) -> str:
    if type(value) is not str:
        raise PersistedStateCorruption(f"invalid persisted {field_name}")
    if nonblank and not value.strip():
        raise PersistedStateCorruption(f"invalid persisted {field_name}")
    if len(value) > _MAX_STORED_TEXT_LENGTH or "\x00" in value:
        raise PersistedStateCorruption(f"invalid persisted {field_name}")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise PersistedStateCorruption(
            f"invalid persisted {field_name}",
        ) from exc
    return value


def _stored_timestamp(value: object, field_name: str) -> datetime:
    text = _stored_text(value, field_name)
    try:
        parsed = datetime.fromisoformat(text)
        if (
            parsed.tzinfo is None
            or parsed.utcoffset() != timedelta(0)
            or parsed.isoformat() != text
        ):
            raise ValueError("timestamp is not canonical UTC")
        return parsed.astimezone(UTC)
    except (OverflowError, ValueError) as exc:
        raise PersistedStateCorruption(
            f"invalid persisted {field_name}",
        ) from exc


def _release_text(value: object, field_name: str) -> str:
    if type(value) is not str or not value.strip():
        message = f"invalid persisted release {field_name}"
        raise PersistedStateCorruption(message)
    return value


def validate_persisted_release_mapping(
    mapping: Mapping[str, object],
) -> AllowedRelease:
    _sqlite_id(_field(mapping, "id"), "release mapping id")
    stage = _release_text(_field(mapping, "stage"), "stage")
    project_raw = _field(mapping, "project")
    project = _release_text(project_raw, "project")
    try:
        canonical_project = normalize_name(project)
    except (TypeError, ValueError) as exc:
        raise PersistedStateCorruption(
            "invalid persisted release project",
        ) from exc
    if canonical_project != project:
        raise PersistedStateCorruption("invalid persisted release project")
    version = _release_text(_field(mapping, "version"), "version")
    filename = _release_text(_field(mapping, "filename"), "filename")
    sha256 = _canonical_sha256(
        _field(mapping, "sha256"),
        "release mapping sha256",
    )
    origin_raw = _field(mapping, "origin_url")
    origin_url = _release_text(origin_raw, "origin_url")
    try:
        canonical_origin = sanitize_origin_url(origin_url)
    except (TypeError, ValueError) as exc:
        raise PersistedStateCorruption(
            "invalid persisted release origin_url",
        ) from exc
    if canonical_origin != origin_url:
        raise PersistedStateCorruption(
            "noncanonical persisted release origin_url",
        )
    _stored_timestamp(
        _field(mapping, "discovered_at"),
        "release mapping discovered_at",
    )
    return AllowedRelease(
        stage=stage,
        project=project,
        version=version,
        filename=filename,
        sha256=sha256,
        origin_url=origin_url,
    )


def _artifact_context(
    artifact: Mapping[str, object],
) -> tuple[str, ArtifactState, datetime | None]:
    sha256 = _canonical_sha256(_field(artifact, "sha256"), "artifact sha256")
    size_bytes = _field(artifact, "size_bytes")
    size_is_integer = type(size_bytes) is int
    if not size_is_integer or not 0 <= size_bytes <= _MAX_SQLITE_INTEGER:
        raise PersistedStateCorruption("invalid persisted artifact size")

    state_raw = _field(artifact, "state")
    if type(state_raw) is not str:
        raise PersistedStateCorruption("invalid persisted artifact state")
    try:
        state = ArtifactState(state_raw)
    except ValueError as exc:
        raise PersistedStateCorruption(
            "invalid persisted artifact state",
        ) from exc
    if state is ArtifactState.MISSING:
        raise PersistedStateCorruption("invalid persisted artifact state")

    _stored_timestamp(_field(artifact, "discovered_at"), "discovered_at")
    updated_at = _stored_timestamp(
        _field(artifact, "updated_at"),
        "updated_at",
    )
    lease_owner = _field(artifact, "lease_owner")
    lease_expires_at = _field(artifact, "lease_expires_at")
    lease_token = _field(artifact, "lease_token")
    owner_is_clear = lease_owner is None
    expiry_is_clear = lease_expires_at is None
    token_is_clear = lease_token is None
    lease_is_clear = owner_is_clear and expiry_is_clear and token_is_clear
    if state is ArtifactState.SCANNING:
        _stored_text(lease_owner, "lease_owner")
        expires_at = _stored_timestamp(lease_expires_at, "lease_expires_at")
        if expires_at <= updated_at:
            raise PersistedStateCorruption("invalid persisted lease expiry")
        _canonical_sha256(lease_token, "lease_token")
    elif not lease_is_clear:
        raise PersistedStateCorruption("invalid persisted lease tuple")

    last_error = _field(artifact, "last_error")
    if state is ArtifactState.ERROR:
        _stored_text(last_error, "last_error", nonblank=False)
    elif last_error is not None:
        raise PersistedStateCorruption("invalid persisted last_error")
    cooldown_started_raw = _optional_field(artifact, "cooldown_started_at")
    cooldown_until_raw = _optional_field(artifact, "cooldown_until")
    if (cooldown_started_raw is None) != (cooldown_until_raw is None):
        raise PersistedStateCorruption("invalid persisted cooldown tuple")
    cooldown_until = None
    if cooldown_started_raw is not None:
        cooldown_started = _stored_timestamp(
            cooldown_started_raw,
            "cooldown_started_at",
        )
        cooldown_until = _stored_timestamp(cooldown_until_raw, "cooldown_until")
        if cooldown_until <= cooldown_started:
            raise PersistedStateCorruption("invalid persisted cooldown window")
    return sha256, state, cooldown_until


def _current_verdict(
    verdict: Mapping[str, object] | None,
    sha256: str,
    state: ArtifactState,
) -> tuple[int | None, Decision | None, str | None, str | None]:
    if verdict is None:
        if state in _VERDICT_STATES:
            raise PersistedStateCorruption(
                "terminal artifact has no current verdict",
            )
        return None, None, None, None

    verdict_id = _sqlite_id(_field(verdict, "id"), "verdict id")
    verdict_sha256 = _canonical_sha256(
        _field(verdict, "sha256"),
        "verdict sha256",
    )
    if verdict_sha256 != sha256:
        raise PersistedStateCorruption("current verdict artifact mismatch")
    decision_raw = _field(verdict, "decision")
    if type(decision_raw) is not str:
        raise PersistedStateCorruption("invalid persisted verdict decision")
    try:
        decision = Decision(decision_raw)
    except ValueError as exc:
        raise PersistedStateCorruption(
            "invalid persisted verdict decision",
        ) from exc
    score = _field(verdict, "score")
    if type(score) is not float or not math.isfinite(score):
        raise PersistedStateCorruption("invalid persisted verdict score")
    policy_version = _stored_text(
        _field(verdict, "policy_version"),
        "policy_version",
    )
    analyzer_version = _stored_text(
        _field(verdict, "analyzer_version"),
        "analyzer_version",
    )
    baseline_sha256 = _field(verdict, "baseline_sha256")
    if baseline_sha256 is not None:
        _canonical_sha256(baseline_sha256, "baseline sha256")
    baseline_tier = _field(verdict, "baseline_tier")
    if baseline_tier is not None:
        try:
            validate_baseline_tier(baseline_tier)
        except ValueError as exc:
            raise PersistedStateCorruption(
                "invalid persisted baseline tier",
            ) from exc
        if baseline_sha256 is None:
            raise PersistedStateCorruption(
                "persisted baseline tier has no baseline sha256",
            )
    current_marker = _field(verdict, "is_current")
    if type(current_marker) is not int or current_marker != 1:
        raise PersistedStateCorruption("invalid current verdict marker")
    _stored_timestamp(_field(verdict, "created_at"), "verdict created_at")
    if state in _VERDICT_STATES and decision.value != state.value:
        raise PersistedStateCorruption("artifact state and verdict mismatch")
    return verdict_id, decision, policy_version, analyzer_version


def _current_override(
    override: Mapping[str, object] | None,
    sha256: str,
    state: ArtifactState,
) -> tuple[int | None, Decision | None, datetime | None]:
    if override is None:
        return None, None, None
    if state not in _TERMINAL_STATES:
        raise PersistedStateCorruption("override on nonterminal artifact")

    override_id = _sqlite_id(_field(override, "id"), "override id")
    override_sha256 = _canonical_sha256(
        _field(override, "sha256"),
        "override sha256",
    )
    if override_sha256 != sha256:
        raise PersistedStateCorruption("current override artifact mismatch")
    decision_raw = _field(override, "decision")
    if type(decision_raw) is not str:
        raise PersistedStateCorruption("invalid persisted override decision")
    try:
        decision = Decision(decision_raw)
    except ValueError as exc:
        raise PersistedStateCorruption(
            "invalid persisted override decision",
        ) from exc
    if decision not in (Decision.ALLOW, Decision.DENY):
        raise PersistedStateCorruption("invalid persisted override decision")
    _stored_text(_field(override, "actor"), "override actor")
    _stored_text(_field(override, "reason"), "override reason")
    created_at = _stored_timestamp(
        _field(override, "created_at"),
        "override created_at",
    )
    expires_raw = _field(override, "expires_at")
    expires_at = None
    if expires_raw is not None:
        expires_at = _stored_timestamp(
            expires_raw,
            "override expires_at",
        )
    if expires_at is not None and expires_at <= created_at:
        raise PersistedStateCorruption("invalid persisted override expiry")
    current_marker = _field(override, "is_current")
    if type(current_marker) is not int or current_marker != 1:
        raise PersistedStateCorruption("invalid current override marker")
    return override_id, decision, expires_at


def validate_persisted_state(
    artifact: Mapping[str, object],
    current_verdict: Mapping[str, object] | None,
    current_override: Mapping[str, object] | None,
    as_of: datetime,
) -> PersistedStateContext:
    if type(as_of) is not datetime or as_of.tzinfo is None:
        raise PersistedStateCorruption("invalid evaluation timestamp")
    try:
        if as_of.utcoffset() is None:
            raise PersistedStateCorruption("invalid evaluation timestamp")
        evaluated_at = as_of.astimezone(UTC)
    except (OverflowError, ValueError) as exc:
        raise PersistedStateCorruption("invalid evaluation timestamp") from exc

    sha256, state, cooldown_until = _artifact_context(artifact)
    verdict_id, automated, policy_version, analyzer_version = _current_verdict(
        current_verdict,
        sha256,
        state,
    )
    override_id, manual, expires_at = _current_override(
        current_override,
        sha256,
        state,
    )
    fallback = (
        Decision.ALLOW
        if state is ArtifactState.ALLOW and automated is Decision.ALLOW
        else Decision.DENY
    )
    override_unexpired = expires_at is None or expires_at > evaluated_at
    manual_is_active = manual is not None and override_unexpired
    effective = manual if manual_is_active else fallback
    source = DecisionSource.AUTOMATED
    if manual_is_active:
        source = DecisionSource.MANUAL_OVERRIDE
    # Cooldown is an automated-verdict safety window.  A current manual
    # override is an explicit administrator decision and therefore bypasses
    # that automated window; an expired override falls back to the automated
    # decision and resumes cooldown enforcement.
    cooldown_finished = (
        source is not DecisionSource.AUTOMATED
        or cooldown_until is None
        or cooldown_until <= evaluated_at
    )
    return PersistedStateContext(
        artifact_state=state,
        effective_decision=effective,
        fallback_decision=fallback,
        source=source,
        policy_version=policy_version,
        analyzer_version=analyzer_version,
        current_verdict_id=verdict_id,
        current_override_id=override_id,
        cooldown_until=cooldown_until,
        cooldown_finished=cooldown_finished,
    )
