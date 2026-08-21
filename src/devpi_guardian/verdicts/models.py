from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .errors import InvalidSha256

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}", re.ASCII)


class _FrozenList(tuple[Any, ...]):
    def _raise_immutable(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("evidence details are immutable")

    __setitem__ = _raise_immutable
    __delitem__ = _raise_immutable
    __iadd__ = _raise_immutable
    __imul__ = _raise_immutable
    append = _raise_immutable
    clear = _raise_immutable
    extend = _raise_immutable
    insert = _raise_immutable
    pop = _raise_immutable
    remove = _raise_immutable
    reverse = _raise_immutable
    sort = _raise_immutable


class _FrozenDict(dict[Any, Any]):
    def _raise_immutable(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("evidence details are immutable")

    __setitem__ = _raise_immutable
    __delitem__ = _raise_immutable
    __ior__ = _raise_immutable
    clear = _raise_immutable
    pop = _raise_immutable
    popitem = _raise_immutable
    setdefault = _raise_immutable
    update = _raise_immutable


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("details object keys must be strings")
        return _FrozenDict(
            {key: _freeze_json(item) for key, item in value.items()},
        )
    if isinstance(value, (list, tuple)):
        return _FrozenList(_freeze_json(item) for item in value)
    return value


def _snapshot_details(details: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(details, dict):
        raise ValueError("details must be a dictionary")
    try:
        frozen = _freeze_json(details)
        json.dumps(
            frozen,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValueError("details must be JSON-serializable") from exc
    return frozen


def _require_decision(value: object, field_name: str) -> None:
    if not isinstance(value, Decision):
        raise ValueError(f"{field_name} must be a Decision")


def _invalid_line(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, int):
        return True
    return value <= 0


def _normalize_score(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("score must be a finite number")
    try:
        if not math.isfinite(value):
            raise ValueError("score must be a finite number")
        return float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError("score must be a finite number") from exc


class ArtifactState(StrEnum):
    DISCOVERED = "DISCOVERED"
    SCANNING = "SCANNING"
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    DENY = "DENY"
    ERROR = "ERROR"
    MISSING = "MISSING"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    DENY = "DENY"


class DecisionSource(StrEnum):
    AUTOMATED = "AUTOMATED"
    MANUAL_OVERRIDE = "MANUAL_OVERRIDE"
    MISSING = "MISSING"


def validate_sha256(value: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise InvalidSha256(value)
    return value


def require_utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class ArtifactInput:
    sha256: str
    size_bytes: int
    discovered_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        validate_sha256(self.sha256)
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be non-negative")
        require_utc(self.discovered_at, "discovered_at")


@dataclass(frozen=True, slots=True)
class ReleaseInput:
    stage: str
    project: str
    version: str
    filename: str
    sha256: str
    origin_url: str
    discovered_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        validate_sha256(self.sha256)
        for name in ("stage", "project", "version", "filename"):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"{name} must not be blank")
        require_utc(self.discovered_at, "discovered_at")


@dataclass(frozen=True, slots=True)
class AllowedRelease:
    stage: str
    project: str
    version: str
    filename: str
    sha256: str
    origin_url: str


@dataclass(frozen=True, slots=True)
class EvidenceInput:
    rule_id: str
    action: Decision
    file_path: str | None
    line: int | None
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not self.rule_id.strip():
            raise ValueError("rule_id must not be blank")
        _require_decision(self.action, "action")
        if self.line is not None and _invalid_line(self.line):
            raise ValueError("line must be None or a positive integer")
        if not isinstance(self.message, str) or not self.message.strip():
            raise ValueError("message must not be blank")
        object.__setattr__(self, "details", _snapshot_details(self.details))


@dataclass(frozen=True, slots=True)
class VerdictInput:
    sha256: str
    decision: Decision
    score: float
    policy_version: str
    analyzer_version: str
    baseline_sha256: str | None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        validate_sha256(self.sha256)
        _require_decision(self.decision, "decision")
        object.__setattr__(self, "score", _normalize_score(self.score))
        if self.baseline_sha256 is not None:
            validate_sha256(self.baseline_sha256)
        versions = self.policy_version.strip(), self.analyzer_version.strip()
        if not all(versions):
            message = "policy_version and analyzer_version"
            raise ValueError(f"{message} must not be blank")
        require_utc(self.created_at, "created_at")


@dataclass(frozen=True, slots=True)
class ManualOverrideInput:
    sha256: str
    decision: Decision
    actor: str
    reason: str
    created_at: datetime
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        validate_sha256(self.sha256)
        _require_decision(self.decision, "decision")
        if self.decision not in (Decision.ALLOW, Decision.DENY):
            raise ValueError("manual decision must be ALLOW or DENY")
        if not isinstance(self.actor, str) or not self.actor.strip():
            raise ValueError("actor must not be blank")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("reason must not be blank")
        if not isinstance(self.created_at, datetime):
            raise ValueError("created_at must be a datetime")
        created = require_utc(self.created_at, "created_at")
        if self.expires_at is not None:
            if not isinstance(self.expires_at, datetime):
                raise ValueError("expires_at must be a datetime")
            expires = require_utc(self.expires_at, "expires_at")
            if expires <= created:
                raise ValueError("expires_at must be later than created_at")


@dataclass(frozen=True, slots=True)
class ClaimedArtifact:
    sha256: str
    size_bytes: int
    worker_id: str
    lease_expires_at: datetime
    lease_token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class EnforcementDecision:
    sha256: str
    allowed: bool
    effective_decision: Decision
    source: DecisionSource
    artifact_state: ArtifactState
    policy_version: str | None


@dataclass(frozen=True, slots=True)
class AuditEventInput:
    actor: str
    action: str
    sha256: str
    previous_decision: Decision
    new_decision: Decision
    reason: str
    policy_version: str | None
    analyzer_version: str | None
    occurred_at: datetime
