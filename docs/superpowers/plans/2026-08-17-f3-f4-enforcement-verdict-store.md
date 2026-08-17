# F3·F4 Enforcement and Verdict Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Build a fail-closed devpi plugin that persists SHA-256 verdicts and serves direct Artifact URLs only when their effective decision is ALLOW.

**Architecture:** A standalone SQLite database owns Artifact state, immutable automated verdicts, evidence, and manual overrides. A read-only VerdictReader is shared by GuardianStage and a Pyramid tween; the tween resolves devpi releasefile entries to verified SHA-256 values before allowing +f or +e GET/HEAD requests.

**Tech Stack:** Python 3.11–3.14, devpi-server 6.20.3, Pyramid, stdlib sqlite3, setuptools, pytest, pytest-devpi-server 1.8.0, WebTest, Ruff, Flake8, uv

> **2026-08-18 claim-fencing correction:** Every `claim_next` call creates a
> unique 64-character `lease_token` and returns it in `ClaimedArtifact`.
> `record_verdict(claim, verdict, evidence)` and
> `mark_analysis_error(claim, error)` must compare `sha256`, owner, expiry,
> token, state, and non-expiry before completing work. This correction
> supersedes older snippets below that omit `lease_token` or accept only a
> SHA-256 for completion. A recovered claim's late result must fail with
> `TransitionConflict` after any later claim.

> **2026-08-18 administrator-audit correction:** Override set, revoke, and
> rescan audit events carry the current automated verdict's
> `policy_version` and `analyzer_version` when a current verdict exists.
> Stored artifact/verdict/override values that violate schema or state-machine
> semantics are database corruption and must raise `StoreUnavailable`; they
> are not ordinary `TransitionConflict` outcomes. This correction supersedes
> Task 7 snippets below that omit the version fields.

> **2026-08-18 persisted-invariant correction:** Reader and administrator
> paths use one shared persisted-state validator. Impossible lifecycle/current
> verdict/current override combinations and malformed persisted timestamps or
> metadata raise `StoreUnavailable`, so a corrupt manual `ALLOW` can never be
> served. Schema triggers enforce immutable Artifact identity fields and
> verdict/evidence history. Administrator commands use bounded row/count
> verification while holding `BEGIN IMMEDIATE`; they must not materialize all
> historical evidence payloads to prove immutability.

> **2026-08-18 replacement/duplicate-bound correction:** Every connection
> enables and verifies `PRAGMA recursive_triggers=ON`; immutable-history
> guards must also reject replacement of an existing row identity. Bounded
> post-audit checks compare the complete newly requested override row, not
> only its ID and count. Reader batches query current verdicts and overrides
> separately and retain at most two rows per SHA-256 so duplicate-current
> corruption cannot create a Cartesian result before `StoreUnavailable`.

> **2026-08-18 Pyramid pre-routing correction:** Pyramid tweens run before
> `Router.handle_request` populates `matched_route`, `matchdict`, and
> `context`. The resolver therefore classifies canonical `path_info` plus the
> raw request target, obtains XOM from the registry, and calls
> `xom.model.getstage(user, index)` inside the keyfs transaction. It must not
> return pass-through merely because routed request attributes are absent.
> The guardian tween remains registered under
> `devpi_server.views.tween_keyfs_transaction`.

> **2026-08-18 mirror/Unicode resolver correction:** Raw URI checks accept
> only the canonical UTF-8 percent encoding of decoded `SCRIPT_NAME` and
> `path_info`; alternate ASCII encodings remain ambiguous and fail closed.
> For a missing `+f` entry, the resolver may mirror devpi 6.20.3's
> metadata-only project refresh and retry the entry lookup once. It never
> reads or serves Artifact bytes before verdict enforcement, and `+e` retains
> its key-exists-first behavior.

---

## Source design

Implement against docs/superpowers/specs/2026-08-17-devpi-guardian-f3-f4-design.md. If this plan and that design disagree, stop and update the plan before changing code.

## Locked file structure

~~~text
devpi-guardian/
├── pyproject.toml
├── README.md
├── .gitignore
├── news/
│   └── 1.feature
├── src/devpi_guardian/
│   ├── __init__.py
│   ├── plugin.py
│   ├── enforcement/
│   │   ├── __init__.py
│   │   ├── resolve.py
│   │   └── tween.py
│   └── verdicts/
│       ├── __init__.py
│       ├── db.py
│       ├── errors.py
│       ├── invariants.py
│       ├── interfaces.py
│       ├── models.py
│       ├── reader.py
│       ├── store.py
│       └── sql/
│           ├── __init__.py
│           └── 001_initial.sql
├── tests/
│   ├── conftest.py
│   ├── __init__.py
│   ├── test_package.py
│   ├── enforcement/
│   │   ├── test_resolve.py
│   │   └── test_tween.py
│   ├── integration/
│   │   ├── conftest.py
│   │   └── test_direct_download.py
│   └── verdicts/
│       ├── __init__.py
│       ├── test_db.py
│       ├── test_models.py
│       ├── test_reader.py
│       ├── test_store_claims.py
│       ├── test_store_overrides.py
│       └── test_store_verdicts.py
└── docs/superpowers/
    ├── specs/2026-08-17-devpi-guardian-f3-f4-design.md
    └── plans/2026-08-17-f3-f4-enforcement-verdict-store.md
~~~

Each production module has one responsibility: models validate boundary data, db owns connection and migration behavior, reader computes effective decisions, store owns writes, resolve understands devpi file entries, tween maps decisions to HTTP, and plugin wires everything into devpi.

### Task 1: Bootstrap the installable devpi plugin package

**Files:**
- Create: pyproject.toml
- Create: README.md
- Create: .gitignore
- Create: news/1.feature
- Create: src/devpi_guardian/__init__.py
- Create: src/devpi_guardian/plugin.py
- Create: tests/__init__.py
- Create: tests/verdicts/__init__.py
- Create: tests/test_package.py

- [ ] **Step 1: Write the failing package metadata test**

Create tests/test_package.py:

~~~python
from importlib import metadata


def test_package_exposes_devpi_server_entry_point() -> None:
    matches = [
        entry_point
        for entry_point in metadata.entry_points(group="devpi_server")
        if entry_point.name == "guardian"
    ]

    assert len(matches) == 1
    assert matches[0].value == "devpi_guardian.plugin"
~~~

- [ ] **Step 2: Run the test to verify it fails**

Run: uv run --isolated --with pytest pytest tests/test_package.py -v

Expected: FAIL because the project and devpi_server entry point do not exist.

- [ ] **Step 3: Add package metadata and the minimal module**

Create pyproject.toml:

~~~toml
[build-system]
requires = ["setuptools>=80"]
build-backend = "setuptools.build_meta"

[project]
name = "devpi-guardian"
version = "0.1.0.dev0"
description = "Fail-closed Artifact enforcement for devpi-server"
readme = "README.md"
requires-python = ">=3.11"
dependencies = [
  "devpi-server==6.20.3",
]

[project.optional-dependencies]
test = [
  "flake8>=7,<9",
  "pytest>=8,<10",
  "pytest-devpi-server==1.8.0",
  "ruff>=0.12,<1",
  "webtest>=3,<4",
]

[project.entry-points.devpi_server]
guardian = "devpi_guardian.plugin"

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
"devpi_guardian.verdicts.sql" = ["*.sql"]

[tool.pytest.ini_options]
addopts = "-ra --strict-markers"
testpaths = ["tests"]
markers = [
  "integration: starts a real devpi-server process",
  "performance: verifies the verdict lookup latency budget",
]

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM", "RUF"]
~~~

Create src/devpi_guardian/__init__.py:

~~~python
"""devpi-guardian package."""

__version__ = "0.1.0.dev0"
~~~

Create src/devpi_guardian/plugin.py:

~~~python
"""devpi-server hook implementations.

The actual hooks are added after the storage and enforcement components exist.
"""
~~~

Create empty tests/__init__.py and tests/verdicts/__init__.py so shared test helpers have an unambiguous import path.

Create README.md:

~~~markdown
# devpi-guardian

devpi-guardian is a devpi-server plugin that exposes only Artifact SHA-256 values
whose current effective verdict is ALLOW. All missing, pending, denied, errored,
or unavailable verdicts fail closed.

The approved F3/F4 design is in
docs/superpowers/specs/2026-08-17-devpi-guardian-f3-f4-design.md.
~~~

Create .gitignore:

~~~gitignore
.DS_Store
.pytest_cache/
.ruff_cache/
.venv/
__pycache__/
*.py[cod]
*.db
*.db-shm
*.db-wal
dist/
build/
*.egg-info/
~~~

Create news/1.feature:

~~~text
Add SHA-256 verdict persistence and fail-closed direct Artifact download enforcement.
~~~

- [ ] **Step 4: Install the editable project and verify the test passes**

Run: uv sync --extra test

Expected: exit 0 and uv.lock is created with devpi-server 6.20.3.

Run: uv run pytest tests/test_package.py -v

Expected: PASS.

- [ ] **Step 5: Run formatting and lint checks**

Run: uv run ruff format --check .

Expected: exit 0.

Run: uv run ruff check .

Expected: exit 0.

Run: uv run flake8 src tests

Expected: exit 0.

- [ ] **Step 6: Commit the package bootstrap**

~~~bash
git add .gitignore README.md news pyproject.toml src tests uv.lock
git commit -m "chore: bootstrap devpi guardian plugin"
~~~

### Task 2: Define validated domain models and public protocols

**Files:**
- Create: src/devpi_guardian/verdicts/__init__.py
- Create: src/devpi_guardian/verdicts/errors.py
- Create: src/devpi_guardian/verdicts/interfaces.py
- Create: src/devpi_guardian/verdicts/models.py
- Create: tests/verdicts/test_models.py

- [ ] **Step 1: Write failing validation and effective-decision model tests**

Create tests/verdicts/test_models.py:

~~~python
from datetime import UTC, datetime, timedelta

import pytest

from devpi_guardian.verdicts.errors import InvalidSha256
from devpi_guardian.verdicts.models import (
    ArtifactInput,
    ArtifactState,
    Decision,
    DecisionSource,
    ManualOverrideInput,
    validate_sha256,
)

SHA256 = "a" * 64


@pytest.mark.parametrize("value", ["", "A" * 64, "g" * 64, "a" * 63, "a" * 65])
def test_validate_sha256_rejects_noncanonical_values(value: str) -> None:
    with pytest.raises(InvalidSha256):
        validate_sha256(value)


def test_artifact_input_rejects_negative_size() -> None:
    with pytest.raises(ValueError, match="size_bytes"):
        ArtifactInput(sha256=SHA256, size_bytes=-1)


def test_manual_override_requires_nonblank_actor_and_reason() -> None:
    now = datetime.now(UTC)

    with pytest.raises(ValueError, match="actor"):
        ManualOverrideInput(
            sha256=SHA256,
            decision=Decision.ALLOW,
            actor=" ",
            reason="reviewed",
            created_at=now,
        )


def test_manual_override_requires_future_expiry() -> None:
    now = datetime.now(UTC)

    with pytest.raises(ValueError, match="expires_at"):
        ManualOverrideInput(
            sha256=SHA256,
            decision=Decision.ALLOW,
            actor="admin",
            reason="temporary exception",
            created_at=now,
            expires_at=now - timedelta(seconds=1),
        )


def test_public_enums_have_locked_wire_values() -> None:
    assert ArtifactState.DISCOVERED.value == "DISCOVERED"
    assert Decision.REVIEW.value == "REVIEW"
    assert DecisionSource.MANUAL_OVERRIDE.value == "MANUAL_OVERRIDE"
~~~

- [ ] **Step 2: Run the tests to verify they fail**

Run: uv run pytest tests/verdicts/test_models.py -v

Expected: FAIL with ModuleNotFoundError for devpi_guardian.verdicts.

- [ ] **Step 3: Implement errors, enums, DTOs, and protocols**

Create src/devpi_guardian/verdicts/errors.py:

~~~python
class GuardianStoreError(Exception):
    """Base class for verdict store failures."""


class InvalidSha256(ValueError, GuardianStoreError):
    """The digest is not a canonical lowercase SHA-256."""


class ArtifactNotFound(GuardianStoreError):
    """The requested Artifact does not exist."""


class TransitionConflict(GuardianStoreError):
    """The current Artifact state does not permit the requested transition."""


class StoreUnavailable(GuardianStoreError):
    """SQLite could not safely answer the request."""


class MigrationError(GuardianStoreError):
    """The schema could not be migrated to the required version."""
~~~

Create src/devpi_guardian/verdicts/models.py:

~~~python
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .errors import InvalidSha256


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
    if len(value) != 64 or value.lower() != value:
        raise InvalidSha256(value)
    try:
        int(value, 16)
    except ValueError as exc:
        raise InvalidSha256(value) from exc
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
class EvidenceInput:
    rule_id: str
    action: Decision
    file_path: str | None
    line: int | None
    message: str
    details: dict[str, Any] = field(default_factory=dict)


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
        if self.baseline_sha256 is not None:
            validate_sha256(self.baseline_sha256)
        if not self.policy_version.strip() or not self.analyzer_version.strip():
            raise ValueError("policy_version and analyzer_version must not be blank")
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
        if self.decision not in (Decision.ALLOW, Decision.DENY):
            raise ValueError("manual decision must be ALLOW or DENY")
        if not self.actor.strip():
            raise ValueError("actor must not be blank")
        if not self.reason.strip():
            raise ValueError("reason must not be blank")
        created = require_utc(self.created_at, "created_at")
        if self.expires_at is not None:
            expires = require_utc(self.expires_at, "expires_at")
            if expires <= created:
                raise ValueError("expires_at must be later than created_at")


@dataclass(frozen=True, slots=True)
class ClaimedArtifact:
    sha256: str
    size_bytes: int
    worker_id: str
    lease_expires_at: datetime
    lease_token: str


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
~~~

Create src/devpi_guardian/verdicts/interfaces.py:

~~~python
from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from datetime import datetime
from sqlite3 import Connection
from typing import Protocol

from .models import (
    ArtifactInput,
    AuditEventInput,
    ClaimedArtifact,
    EnforcementDecision,
    EvidenceInput,
    ManualOverrideInput,
    ReleaseInput,
    VerdictInput,
)


class VerdictReader(Protocol):
    def get_effective_decision(self, sha256: str) -> EnforcementDecision: ...

    def get_effective_decisions(
        self, sha256s: Collection[str]
    ) -> Mapping[str, EnforcementDecision]: ...


class AuditWriter(Protocol):
    def append_in_transaction(
        self, connection: Connection, event: AuditEventInput
    ) -> None: ...


class ArtifactStore(Protocol):
    def discover_artifact(self, artifact: ArtifactInput, release: ReleaseInput) -> None: ...

    def claim_next(
        self, worker_id: str, lease_until: datetime
    ) -> ClaimedArtifact | None: ...

    def recover_expired_claims(self, now: datetime) -> int: ...

    def record_verdict(
        self,
        claim: ClaimedArtifact,
        verdict: VerdictInput,
        evidence: Sequence[EvidenceInput],
    ) -> None: ...

    def mark_analysis_error(self, claim: ClaimedArtifact, error: str) -> None: ...

    def request_rescan(self, sha256: str, actor: str, reason: str) -> None: ...

    def set_manual_override(self, override: ManualOverrideInput) -> None: ...

    def revoke_manual_override(self, sha256: str, actor: str, reason: str) -> None: ...
~~~

Create src/devpi_guardian/verdicts/__init__.py:

~~~python
from .interfaces import ArtifactStore, AuditWriter, VerdictReader
from .models import ArtifactState, Decision, EnforcementDecision

__all__ = [
    "ArtifactState",
    "ArtifactStore",
    "AuditWriter",
    "Decision",
    "EnforcementDecision",
    "VerdictReader",
]
~~~

- [ ] **Step 4: Run the model tests**

Run: uv run pytest tests/verdicts/test_models.py -v

Expected: PASS.

- [ ] **Step 5: Run lint checks**

Run: uv run ruff check src/devpi_guardian/verdicts tests/verdicts/test_models.py

Expected: exit 0.

- [ ] **Step 6: Commit the domain contracts**

~~~bash
git add src/devpi_guardian/verdicts tests/verdicts/test_models.py
git commit -m "feat: define guardian verdict contracts"
~~~

### Task 3: Add SQLite connection policy and idempotent migration

**Files:**
- Create: src/devpi_guardian/verdicts/db.py
- Create: src/devpi_guardian/verdicts/sql/__init__.py
- Create: src/devpi_guardian/verdicts/sql/001_initial.sql
- Create: tests/verdicts/test_db.py

- [ ] **Step 1: Write failing migration tests**

Create tests/verdicts/test_db.py:

~~~python
import sqlite3

from devpi_guardian.verdicts.db import ConnectionFactory, migrate


def test_migrate_creates_schema_and_is_idempotent(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")

    migrate(factory)
    migrate(factory)

    with factory.connect() as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        version = connection.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()[0]

    assert {
        "artifacts",
        "release_mappings",
        "verdicts",
        "evidence",
        "manual_overrides",
    } <= tables
    assert version == 1


def test_connection_enables_required_pragmas(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db", busy_timeout_ms=4321)
    migrate(factory)

    with factory.connect() as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 4321


def test_schema_rejects_invalid_sha256(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)

    with factory.connect() as connection, connection:
        try:
            connection.execute(
                """
                INSERT INTO artifacts(
                    sha256, size_bytes, state, discovered_at, updated_at
                ) VALUES (?, 1, 'DISCOVERED', ?, ?)
                """,
                ("NOT-A-SHA", "2026-08-17T00:00:00Z", "2026-08-17T00:00:00Z"),
            )
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("invalid SHA-256 was accepted")
~~~

- [ ] **Step 2: Run the migration tests to verify they fail**

Run: uv run pytest tests/verdicts/test_db.py -v

Expected: FAIL because db.py and the schema do not exist.

- [ ] **Step 3: Create the complete initial schema**

Create src/devpi_guardian/verdicts/sql/__init__.py:

~~~python
"""Packaged guardian SQLite migrations."""
~~~

Create src/devpi_guardian/verdicts/sql/001_initial.sql:

~~~sql
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE artifacts (
    sha256 TEXT PRIMARY KEY
        CHECK(length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    state TEXT NOT NULL
        CHECK(state IN ('DISCOVERED', 'SCANNING', 'ALLOW', 'REVIEW', 'DENY', 'ERROR')),
    discovered_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    last_error TEXT,
    CHECK(
        (state = 'SCANNING' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR
        (state != 'SCANNING' AND lease_owner IS NULL AND lease_expires_at IS NULL)
    )
);

CREATE TABLE release_mappings (
    id INTEGER PRIMARY KEY,
    stage TEXT NOT NULL,
    project TEXT NOT NULL,
    version TEXT NOT NULL,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL REFERENCES artifacts(sha256),
    origin_url TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    UNIQUE(stage, project, version, filename, sha256)
);

CREATE INDEX release_mappings_sha256_idx ON release_mappings(sha256);
CREATE INDEX release_mappings_project_idx
    ON release_mappings(project, version, filename);

CREATE TABLE verdicts (
    id INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL REFERENCES artifacts(sha256),
    decision TEXT NOT NULL CHECK(decision IN ('ALLOW', 'REVIEW', 'DENY')),
    score REAL NOT NULL,
    policy_version TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    baseline_sha256 TEXT REFERENCES artifacts(sha256),
    is_current INTEGER NOT NULL CHECK(is_current IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX verdicts_one_current_idx
    ON verdicts(sha256) WHERE is_current = 1;
CREATE INDEX verdicts_sha256_idx ON verdicts(sha256, created_at);

CREATE TABLE evidence (
    id INTEGER PRIMARY KEY,
    verdict_id INTEGER NOT NULL REFERENCES verdicts(id),
    rule_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('ALLOW', 'REVIEW', 'DENY')),
    file_path TEXT,
    line INTEGER CHECK(line IS NULL OR line > 0),
    message TEXT NOT NULL,
    details_json TEXT NOT NULL CHECK(json_valid(details_json))
);

CREATE INDEX evidence_verdict_id_idx ON evidence(verdict_id);

CREATE TABLE manual_overrides (
    id INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL REFERENCES artifacts(sha256),
    decision TEXT NOT NULL CHECK(decision IN ('ALLOW', 'DENY')),
    actor TEXT NOT NULL CHECK(length(trim(actor)) > 0),
    reason TEXT NOT NULL CHECK(length(trim(reason)) > 0),
    created_at TEXT NOT NULL,
    expires_at TEXT,
    is_current INTEGER NOT NULL CHECK(is_current IN (0, 1))
);

CREATE UNIQUE INDEX manual_overrides_one_current_idx
    ON manual_overrides(sha256) WHERE is_current = 1;
CREATE INDEX manual_overrides_sha256_idx
    ON manual_overrides(sha256, created_at);
~~~

- [ ] **Step 4: Implement connection and migration behavior**

Create src/devpi_guardian/verdicts/db.py:

~~~python
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path

from .errors import MigrationError, StoreUnavailable


@dataclass(frozen=True, slots=True)
class ConnectionFactory:
    path: Path
    busy_timeout_ms: int = 5_000

    def connect(self) -> sqlite3.Connection:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(
                self.path,
                isolation_level=None,
                timeout=self.busy_timeout_ms / 1000,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            return connection
        except sqlite3.Error as exc:
            raise StoreUnavailable(str(self.path)) from exc


def migrate(factory: ConnectionFactory) -> None:
    try:
        with factory.connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            has_migrations = connection.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'schema_migrations'
                """
            ).fetchone()
            current = 0
            if has_migrations:
                current = connection.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
                ).fetchone()[0]
            if current >= 1:
                return

            sql = (
                resources.files("devpi_guardian.verdicts.sql")
                .joinpath("001_initial.sql")
                .read_text(encoding="utf-8")
            )
            connection.executescript("BEGIN IMMEDIATE;\n" + sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (1, datetime.now(UTC).isoformat()),
            )
            connection.commit()
    except (OSError, sqlite3.Error) as exc:
        raise MigrationError(str(factory.path)) from exc
~~~

- [ ] **Step 5: Run migration tests**

Run: uv run pytest tests/verdicts/test_db.py -v

Expected: PASS with two consecutive migrate calls and all required PRAGMA assertions.

- [ ] **Step 6: Commit the database foundation**

~~~bash
git add src/devpi_guardian/verdicts/db.py src/devpi_guardian/verdicts/sql tests/verdicts/test_db.py
git commit -m "feat: add guardian sqlite schema"
~~~

### Task 4: Implement single and batch effective-decision reads

**Files:**
- Create: src/devpi_guardian/verdicts/reader.py
- Create: tests/verdicts/test_reader.py

- [ ] **Step 1: Write failing reader precedence tests**

Create tests/verdicts/test_reader.py with a seed helper and the locked precedence cases:

~~~python
from datetime import UTC, datetime, timedelta

from devpi_guardian.verdicts.db import ConnectionFactory, migrate
from devpi_guardian.verdicts.models import ArtifactState, Decision, DecisionSource
from devpi_guardian.verdicts.reader import SQLiteVerdictReader

SHA_ALLOW = "a" * 64
SHA_REVIEW = "b" * 64
SHA_MISSING = "c" * 64
NOW = datetime(2026, 8, 17, 0, 0, tzinfo=UTC)


def seed_artifact(factory, sha256, state, automated=None, manual=None, expires=None):
    with factory.connect() as connection, connection:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at
            ) VALUES (?, 1, ?, ?, ?)
            """,
            (sha256, state, NOW.isoformat(), NOW.isoformat()),
        )
        if automated is not None:
            connection.execute(
                """
                INSERT INTO verdicts(
                    sha256, decision, score, policy_version, analyzer_version,
                    baseline_sha256, is_current, created_at
                ) VALUES (?, ?, 0, 'policy-1', 'analyzer-1', NULL, 1, ?)
                """,
                (sha256, automated, NOW.isoformat()),
            )
        if manual is not None:
            connection.execute(
                """
                INSERT INTO manual_overrides(
                    sha256, decision, actor, reason, created_at, expires_at, is_current
                ) VALUES (?, ?, 'admin', 'reviewed', ?, ?, 1)
                """,
                (sha256, manual, NOW.isoformat(), expires.isoformat() if expires else None),
            )


def test_reader_allows_only_automated_allow(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(factory, SHA_ALLOW, "ALLOW", automated="ALLOW")
    seed_artifact(factory, SHA_REVIEW, "REVIEW", automated="REVIEW")
    reader = SQLiteVerdictReader(factory, now=lambda: NOW)

    assert reader.get_effective_decision(SHA_ALLOW).allowed is True
    assert reader.get_effective_decision(SHA_REVIEW).allowed is False


def test_current_manual_decision_overrides_automated_decision(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(factory, SHA_ALLOW, "ALLOW", automated="ALLOW", manual="DENY")
    reader = SQLiteVerdictReader(factory, now=lambda: NOW)

    result = reader.get_effective_decision(SHA_ALLOW)

    assert result.allowed is False
    assert result.source is DecisionSource.MANUAL_OVERRIDE


def test_expired_manual_allow_falls_back_to_automated_review(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_REVIEW,
        "REVIEW",
        automated="REVIEW",
        manual="ALLOW",
        expires=NOW - timedelta(seconds=1),
    )
    reader = SQLiteVerdictReader(factory, now=lambda: NOW)

    result = reader.get_effective_decision(SHA_REVIEW)

    assert result.allowed is False
    assert result.artifact_state is ArtifactState.REVIEW


def test_missing_and_batch_results_are_fail_closed(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(factory, SHA_ALLOW, "ALLOW", automated="ALLOW")
    reader = SQLiteVerdictReader(factory, now=lambda: NOW)

    results = reader.get_effective_decisions([SHA_ALLOW, SHA_MISSING])

    assert results[SHA_ALLOW].allowed is True
    assert results[SHA_MISSING].allowed is False
    assert results[SHA_MISSING].source is DecisionSource.MISSING
    assert results[SHA_MISSING].effective_decision is Decision.DENY
~~~

- [ ] **Step 2: Run the reader tests to verify they fail**

Run: uv run pytest tests/verdicts/test_reader.py -v

Expected: FAIL because reader.py does not exist.

- [ ] **Step 3: Implement the complete reader**

Create src/devpi_guardian/verdicts/reader.py:

~~~python
from __future__ import annotations

import sqlite3
from collections.abc import Callable, Collection, Mapping
from datetime import UTC, datetime

from .db import ConnectionFactory
from .errors import StoreUnavailable
from .models import (
    ArtifactState,
    Decision,
    DecisionSource,
    EnforcementDecision,
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
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = factory
        self._now = now or (lambda: datetime.now(UTC))

    def get_effective_decision(self, sha256: str) -> EnforcementDecision:
        return self.get_effective_decisions([sha256])[sha256]

    def get_effective_decisions(
        self, sha256s: Collection[str]
    ) -> Mapping[str, EnforcementDecision]:
        ordered = list(dict.fromkeys(validate_sha256(value) for value in sha256s))
        results = {value: self._missing(value) for value in ordered}
        try:
            with self._factory.connect() as connection:
                for offset in range(0, len(ordered), _CHUNK_SIZE):
                    chunk = ordered[offset : offset + _CHUNK_SIZE]
                    if not chunk:
                        continue
                    placeholders = ",".join("?" for _ in chunk)
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
                    )
                    for row in rows:
                        results[row["sha256"]] = self._from_row(row)
        except sqlite3.Error as exc:
            raise StoreUnavailable(str(self._factory.path)) from exc
        return results

    def _from_row(self, row: sqlite3.Row) -> EnforcementDecision:
        sha256 = row["sha256"]
        state = ArtifactState(row["state"])
        manual = row["manual_decision"]
        expires_at = row["expires_at"]
        manual_is_valid = (
            manual is not None
            and state in _TERMINAL_STATES
            and (
                expires_at is None
                or datetime.fromisoformat(expires_at).astimezone(UTC) > self._now()
            )
        )
        if manual_is_valid:
            decision = Decision(manual)
            return EnforcementDecision(
                sha256=sha256,
                allowed=decision is Decision.ALLOW,
                effective_decision=decision,
                source=DecisionSource.MANUAL_OVERRIDE,
                artifact_state=state,
                policy_version=row["policy_version"],
            )

        automated = row["automated_decision"]
        allowed = state is ArtifactState.ALLOW and automated == Decision.ALLOW.value
        return EnforcementDecision(
            sha256=sha256,
            allowed=allowed,
            effective_decision=Decision.ALLOW if allowed else Decision.DENY,
            source=DecisionSource.AUTOMATED,
            artifact_state=state,
            policy_version=row["policy_version"],
        )

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
~~~

- [ ] **Step 4: Run reader tests**

Run: uv run pytest tests/verdicts/test_reader.py -v

Expected: PASS.

- [ ] **Step 5: Run all F4 tests accumulated so far**

Run: uv run pytest tests/verdicts -v

Expected: PASS.

- [ ] **Step 6: Commit effective-decision reads**

~~~bash
git add src/devpi_guardian/verdicts/reader.py tests/verdicts/test_reader.py
git commit -m "feat: read effective artifact decisions"
~~~

### Task 5: Implement idempotent discovery and exclusive worker claims

**Files:**
- Create: src/devpi_guardian/verdicts/store.py
- Create: tests/conftest.py
- Create: tests/verdicts/test_store_claims.py

- [ ] **Step 1: Add a transaction-aware audit recording fixture**

Create tests/conftest.py:

~~~python
from dataclasses import dataclass, field

import pytest

from devpi_guardian.verdicts.models import AuditEventInput


@dataclass
class RecordingAuditWriter:
    events: list[AuditEventInput] = field(default_factory=list)
    fail: bool = False

    def append_in_transaction(self, connection, event: AuditEventInput) -> None:
        if self.fail:
            raise RuntimeError("audit unavailable")
        self.events.append(event)


@pytest.fixture
def audit_writer() -> RecordingAuditWriter:
    return RecordingAuditWriter()
~~~

- [ ] **Step 2: Write failing discovery, claim, and lease recovery tests**

Create tests/verdicts/test_store_claims.py:

~~~python
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from devpi_guardian.verdicts.db import ConnectionFactory, migrate
from devpi_guardian.verdicts.models import ArtifactInput, ReleaseInput
from devpi_guardian.verdicts.store import SQLiteArtifactStore

SHA256 = "a" * 64
NOW = datetime(2026, 8, 17, 0, 0, tzinfo=UTC)


def make_store(tmp_path, audit_writer):
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    return SQLiteArtifactStore(factory, audit_writer, now=lambda: NOW)


def discover(store):
    store.discover_artifact(
        ArtifactInput(SHA256, 123, NOW),
        ReleaseInput(
            stage="root/pypi",
            project="demo-package",
            version="1.0.0",
            filename="demo_package-1.0.0-py3-none-any.whl",
            sha256=SHA256,
            origin_url="https://files.pythonhosted.org/demo.whl",
            discovered_at=NOW,
        ),
    )


def test_discovery_is_idempotent(tmp_path, audit_writer) -> None:
    store = make_store(tmp_path, audit_writer)

    discover(store)
    discover(store)

    with store.connection_factory.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM release_mappings").fetchone()[0] == 1


def test_concurrent_claim_has_one_winner(tmp_path, audit_writer) -> None:
    store = make_store(tmp_path, audit_writer)
    discover(store)
    lease = NOW + timedelta(minutes=5)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda worker: store.claim_next(worker, lease), ["a", "b"]))

    assert sum(result is not None for result in results) == 1


def test_expired_claim_returns_to_discovered(tmp_path, audit_writer) -> None:
    store = make_store(tmp_path, audit_writer)
    discover(store)
    store.claim_next("worker-a", NOW - timedelta(seconds=1))

    recovered = store.recover_expired_claims(NOW)

    assert recovered == 1
    assert store.claim_next("worker-b", NOW + timedelta(minutes=5)) is not None
~~~

- [ ] **Step 3: Run claim tests to verify they fail**

Run: uv run pytest tests/verdicts/test_store_claims.py -v

Expected: FAIL because store.py does not exist.

- [ ] **Step 4: Implement transaction, discovery, and claim methods**

Create src/devpi_guardian/verdicts/store.py with the following complete first slice:

~~~python
from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

from devpi_common.validation import normalize_name

from .db import ConnectionFactory
from .errors import StoreUnavailable, TransitionConflict
from .interfaces import AuditWriter
from .models import (
    ArtifactInput,
    AuditEventInput,
    ClaimedArtifact,
    Decision,
    ReleaseInput,
    require_utc,
)


def _iso(value: datetime) -> str:
    return require_utc(value, "timestamp").isoformat()


def _sanitize_origin_url(value: str) -> str:
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


class SQLiteArtifactStore:
    def __init__(
        self,
        connection_factory: ConnectionFactory,
        audit_writer: AuditWriter,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.connection_factory = connection_factory
        self._audit_writer = audit_writer
        self._now = now or (lambda: datetime.now(UTC))

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        connection = self.connection_factory.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.Error as exc:
            connection.rollback()
            raise StoreUnavailable(str(self.connection_factory.path)) from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _audit(
        self,
        connection: sqlite3.Connection,
        *,
        actor: str,
        action: str,
        sha256: str,
        previous: Decision,
        new: Decision,
        reason: str,
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
                occurred_at=self._now(),
            ),
        )

    def discover_artifact(self, artifact: ArtifactInput, release: ReleaseInput) -> None:
        if artifact.sha256 != release.sha256:
            raise ValueError("artifact and release SHA-256 must match")
        with self._write() as connection:
            existing = connection.execute(
                "SELECT size_bytes FROM artifacts WHERE sha256 = ?",
                (artifact.sha256,),
            ).fetchone()
            if existing is not None and existing["size_bytes"] != artifact.size_bytes:
                raise TransitionConflict("same SHA-256 has a different size")
            connection.execute(
                """
                INSERT OR IGNORE INTO artifacts(
                    sha256, size_bytes, state, discovered_at, updated_at
                ) VALUES (?, ?, 'DISCOVERED', ?, ?)
                """,
                (
                    artifact.sha256,
                    artifact.size_bytes,
                    _iso(artifact.discovered_at),
                    _iso(artifact.discovered_at),
                ),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO release_mappings(
                    stage, project, version, filename, sha256, origin_url, discovered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    release.stage,
                    normalize_name(release.project),
                    release.version,
                    release.filename,
                    release.sha256,
                    _sanitize_origin_url(release.origin_url),
                    _iso(release.discovered_at),
                ),
            )
            self._audit(
                connection,
                actor="guardian-discovery",
                action="artifact.discovered",
                sha256=artifact.sha256,
                previous=Decision.DENY,
                new=Decision.DENY,
                reason="release mapping discovered",
            )

    def claim_next(
        self, worker_id: str, lease_until: datetime
    ) -> ClaimedArtifact | None:
        if not worker_id.strip():
            raise ValueError("worker_id must not be blank")
        with self._write() as connection:
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
            updated = connection.execute(
                """
                UPDATE artifacts
                SET state = 'SCANNING', lease_owner = ?, lease_expires_at = ?, updated_at = ?
                WHERE sha256 = ? AND state = 'DISCOVERED'
                """,
                (worker_id, _iso(lease_until), _iso(self._now()), row["sha256"]),
            )
            if updated.rowcount != 1:
                raise TransitionConflict(row["sha256"])
            self._audit(
                connection,
                actor=worker_id,
                action="artifact.claimed",
                sha256=row["sha256"],
                previous=Decision.DENY,
                new=Decision.DENY,
                reason="analysis lease acquired",
            )
            return ClaimedArtifact(
                sha256=row["sha256"],
                size_bytes=row["size_bytes"],
                worker_id=worker_id,
                lease_expires_at=require_utc(lease_until, "lease_until"),
            )

    def recover_expired_claims(self, now: datetime) -> int:
        timestamp = _iso(now)
        with self._write() as connection:
            rows = connection.execute(
                """
                SELECT sha256, lease_owner
                FROM artifacts
                WHERE state = 'SCANNING' AND lease_expires_at <= ?
                """,
                (timestamp,),
            ).fetchall()
            for row in rows:
                connection.execute(
                    """
                    UPDATE artifacts
                    SET state = 'DISCOVERED', lease_owner = NULL,
                        lease_expires_at = NULL, updated_at = ?
                    WHERE sha256 = ? AND state = 'SCANNING'
                    """,
                    (timestamp, row["sha256"]),
                )
                self._audit(
                    connection,
                    actor=row["lease_owner"],
                    action="artifact.lease_expired",
                    sha256=row["sha256"],
                    previous=Decision.DENY,
                    new=Decision.DENY,
                    reason="analysis lease expired",
                )
            return len(rows)
~~~

- [ ] **Step 5: Run claim tests**

Run: uv run pytest tests/verdicts/test_store_claims.py -v

Expected: PASS with exactly one concurrent claim winner.

- [ ] **Step 6: Commit discovery and worker claims**

~~~bash
git add src/devpi_guardian/verdicts/store.py tests/conftest.py tests/verdicts/test_store_claims.py
git commit -m "feat: add artifact discovery and worker claims"
~~~

### Task 6: Persist immutable verdicts, evidence, and analysis errors

**Files:**
- Modify: src/devpi_guardian/verdicts/store.py
- Create: tests/verdicts/test_store_verdicts.py

- [ ] **Step 1: Write failing verdict and error transition tests**

Create tests/verdicts/test_store_verdicts.py:

~~~python
from datetime import UTC, datetime, timedelta

import pytest

from devpi_guardian.verdicts.errors import TransitionConflict
from devpi_guardian.verdicts.models import (
    Decision,
    EvidenceInput,
    VerdictInput,
)
from tests.verdicts.test_store_claims import SHA256, discover, make_store

NOW = datetime(2026, 8, 17, 0, 0, tzinfo=UTC)


def test_record_verdict_persists_current_verdict_and_evidence(tmp_path, audit_writer) -> None:
    store = make_store(tmp_path, audit_writer)
    discover(store)
    store.claim_next("worker", NOW + timedelta(minutes=5))

    store.record_verdict(
        VerdictInput(
            sha256=SHA256,
            decision=Decision.REVIEW,
            score=40,
            policy_version="policy-1",
            analyzer_version="analyzer-1",
            baseline_sha256=None,
            created_at=NOW,
        ),
        [
            EvidenceInput(
                rule_id="new-network-call",
                action=Decision.REVIEW,
                file_path="demo/client.py",
                line=12,
                message="new outbound request",
                details={"callee": "requests.post"},
            )
        ],
    )

    with store.connection_factory.connect() as connection:
        assert connection.execute(
            "SELECT state FROM artifacts WHERE sha256 = ?", (SHA256,)
        ).fetchone()[0] == "REVIEW"
        assert connection.execute(
            "SELECT COUNT(*) FROM verdicts WHERE sha256 = ? AND is_current = 1",
            (SHA256,),
        ).fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1


def test_record_verdict_requires_scanning_state(tmp_path, audit_writer) -> None:
    store = make_store(tmp_path, audit_writer)
    discover(store)

    with pytest.raises(TransitionConflict):
        store.record_verdict(
            VerdictInput(
                SHA256, Decision.ALLOW, 0, "policy-1", "analyzer-1", None, NOW
            ),
            [],
        )


def test_analysis_error_is_terminal_and_sanitized(tmp_path, audit_writer) -> None:
    store = make_store(tmp_path, audit_writer)
    discover(store)
    store.claim_next("worker", NOW + timedelta(minutes=5))

    store.mark_analysis_error(SHA256, "x" * 5_000)

    with store.connection_factory.connect() as connection:
        row = connection.execute(
            "SELECT state, length(last_error) FROM artifacts WHERE sha256 = ?",
            (SHA256,),
        ).fetchone()
    assert tuple(row) == ("ERROR", 4096)
~~~

- [ ] **Step 2: Run verdict tests to verify they fail**

Run: uv run pytest tests/verdicts/test_store_verdicts.py -v

Expected: FAIL because record_verdict and mark_analysis_error do not exist.

- [ ] **Step 3: Add record_verdict and mark_analysis_error**

Append these methods to SQLiteArtifactStore in src/devpi_guardian/verdicts/store.py and add json plus Sequence imports:

~~~python
    def record_verdict(
        self, verdict: VerdictInput, evidence: Sequence[EvidenceInput]
    ) -> None:
        with self._write() as connection:
            state = connection.execute(
                "SELECT state FROM artifacts WHERE sha256 = ?",
                (verdict.sha256,),
            ).fetchone()
            if state is None or state["state"] != "SCANNING":
                raise TransitionConflict(verdict.sha256)
            connection.execute(
                "UPDATE verdicts SET is_current = 0 WHERE sha256 = ? AND is_current = 1",
                (verdict.sha256,),
            )
            cursor = connection.execute(
                """
                INSERT INTO verdicts(
                    sha256, decision, score, policy_version, analyzer_version,
                    baseline_sha256, is_current, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    verdict.sha256,
                    verdict.decision.value,
                    verdict.score,
                    verdict.policy_version,
                    verdict.analyzer_version,
                    verdict.baseline_sha256,
                    _iso(verdict.created_at),
                ),
            )
            for item in evidence:
                connection.execute(
                    """
                    INSERT INTO evidence(
                        verdict_id, rule_id, action, file_path, line, message, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cursor.lastrowid,
                        item.rule_id,
                        item.action.value,
                        item.file_path,
                        item.line,
                        item.message,
                        json.dumps(item.details, sort_keys=True, separators=(",", ":")),
                    ),
                )
            connection.execute(
                """
                UPDATE artifacts
                SET state = ?, lease_owner = NULL, lease_expires_at = NULL,
                    last_error = NULL, updated_at = ?
                WHERE sha256 = ? AND state = 'SCANNING'
                """,
                (verdict.decision.value, _iso(self._now()), verdict.sha256),
            )
            self._audit(
                connection,
                actor="guardian-policy",
                action="artifact.verdict_recorded",
                sha256=verdict.sha256,
                previous=Decision.DENY,
                new=Decision.ALLOW if verdict.decision is Decision.ALLOW else Decision.DENY,
                reason="automated policy decision",
                policy_version=verdict.policy_version,
                analyzer_version=verdict.analyzer_version,
            )

    def mark_analysis_error(self, sha256: str, error: str) -> None:
        message = error[:4096]
        with self._write() as connection:
            updated = connection.execute(
                """
                UPDATE artifacts
                SET state = 'ERROR', lease_owner = NULL, lease_expires_at = NULL,
                    last_error = ?, updated_at = ?
                WHERE sha256 = ? AND state = 'SCANNING'
                """,
                (message, _iso(self._now()), sha256),
            )
            if updated.rowcount != 1:
                raise TransitionConflict(sha256)
            self._audit(
                connection,
                actor="guardian-worker",
                action="artifact.analysis_error",
                sha256=sha256,
                previous=Decision.DENY,
                new=Decision.DENY,
                reason="analysis failed",
            )
~~~

Add these imports at the top of store.py:

~~~python
import json
from collections.abc import Sequence

from .models import EvidenceInput, VerdictInput
~~~

- [ ] **Step 4: Run verdict tests**

Run: uv run pytest tests/verdicts/test_store_verdicts.py -v

Expected: PASS.

- [ ] **Step 5: Run all verdict tests**

Run: uv run pytest tests/verdicts -v

Expected: PASS.

- [ ] **Step 6: Commit verdict persistence**

~~~bash
git add src/devpi_guardian/verdicts/store.py tests/verdicts/test_store_verdicts.py
git commit -m "feat: persist verdicts and evidence"
~~~

### Task 7: Add manual overrides, revocation, rescan, and audit rollback

**Files:**
- Modify: src/devpi_guardian/verdicts/store.py
- Create: tests/verdicts/test_store_overrides.py

- [ ] **Step 1: Write failing override and rollback tests**

Create tests/verdicts/test_store_overrides.py:

~~~python
from datetime import UTC, datetime, timedelta

import pytest

from devpi_guardian.verdicts.models import (
    Decision,
    ManualOverrideInput,
    VerdictInput,
)
from devpi_guardian.verdicts.reader import SQLiteVerdictReader
from tests.verdicts.test_store_claims import SHA256, discover, make_store

NOW = datetime(2026, 8, 17, 0, 0, tzinfo=UTC)


def terminal_store(tmp_path, audit_writer, decision=Decision.REVIEW):
    store = make_store(tmp_path, audit_writer)
    discover(store)
    store.claim_next("worker", NOW + timedelta(minutes=5))
    store.record_verdict(
        VerdictInput(
            SHA256, decision, 1, "policy-1", "analyzer-1", None, NOW
        ),
        [],
    )
    return store


def test_allow_override_and_revoke_change_effective_decision(tmp_path, audit_writer) -> None:
    store = terminal_store(tmp_path, audit_writer)
    reader = SQLiteVerdictReader(store.connection_factory, now=lambda: NOW)
    store.set_manual_override(
        ManualOverrideInput(
            SHA256, Decision.ALLOW, "admin", "reviewed", NOW, None
        )
    )
    assert reader.get_effective_decision(SHA256).allowed is True

    store.revoke_manual_override(SHA256, "admin", "approval withdrawn")

    assert reader.get_effective_decision(SHA256).allowed is False


def test_rescan_deactivates_override_and_blocks_during_scan(tmp_path, audit_writer) -> None:
    store = terminal_store(tmp_path, audit_writer)
    store.set_manual_override(
        ManualOverrideInput(
            SHA256, Decision.ALLOW, "admin", "reviewed", NOW, None
        )
    )
    reader = SQLiteVerdictReader(store.connection_factory, now=lambda: NOW)

    store.request_rescan(SHA256, "admin", "policy changed")

    assert reader.get_effective_decision(SHA256).allowed is False
    assert store.claim_next("worker", NOW + timedelta(minutes=5)) is not None


def test_audit_failure_rolls_back_override(tmp_path, audit_writer) -> None:
    store = terminal_store(tmp_path, audit_writer)
    audit_writer.fail = True

    with pytest.raises(RuntimeError, match="audit unavailable"):
        store.set_manual_override(
            ManualOverrideInput(
                SHA256, Decision.ALLOW, "admin", "reviewed", NOW, None
            )
        )

    with store.connection_factory.connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM manual_overrides WHERE is_current = 1"
        ).fetchone()[0] == 0
~~~

- [ ] **Step 2: Run override tests to verify they fail**

Run: uv run pytest tests/verdicts/test_store_overrides.py -v

Expected: FAIL because override, revoke, and rescan methods do not exist.

- [ ] **Step 3: Implement the three administrator commands**

Append to SQLiteArtifactStore:

~~~python
    def set_manual_override(self, override: ManualOverrideInput) -> None:
        with self._write() as connection:
            row = connection.execute(
                "SELECT state FROM artifacts WHERE sha256 = ?",
                (override.sha256,),
            ).fetchone()
            if row is None or row["state"] not in {"ALLOW", "REVIEW", "DENY", "ERROR"}:
                raise TransitionConflict(override.sha256)
            connection.execute(
                """
                UPDATE manual_overrides
                SET is_current = 0
                WHERE sha256 = ? AND is_current = 1
                """,
                (override.sha256,),
            )
            connection.execute(
                """
                INSERT INTO manual_overrides(
                    sha256, decision, actor, reason, created_at, expires_at, is_current
                ) VALUES (?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    override.sha256,
                    override.decision.value,
                    override.actor,
                    override.reason,
                    _iso(override.created_at),
                    _iso(override.expires_at) if override.expires_at else None,
                ),
            )
            previous = Decision.ALLOW if row["state"] == "ALLOW" else Decision.DENY
            self._audit(
                connection,
                actor=override.actor,
                action="artifact.override_set",
                sha256=override.sha256,
                previous=previous,
                new=override.decision,
                reason=override.reason,
            )

    def revoke_manual_override(self, sha256: str, actor: str, reason: str) -> None:
        if not actor.strip() or not reason.strip():
            raise ValueError("actor and reason must not be blank")
        with self._write() as connection:
            current = connection.execute(
                """
                SELECT decision FROM manual_overrides
                WHERE sha256 = ? AND is_current = 1
                """,
                (sha256,),
            ).fetchone()
            if current is None:
                raise TransitionConflict(sha256)
            connection.execute(
                "UPDATE manual_overrides SET is_current = 0 WHERE sha256 = ? AND is_current = 1",
                (sha256,),
            )
            state = connection.execute(
                "SELECT state FROM artifacts WHERE sha256 = ?", (sha256,)
            ).fetchone()["state"]
            fallback = Decision.ALLOW if state == "ALLOW" else Decision.DENY
            self._audit(
                connection,
                actor=actor,
                action="artifact.override_revoked",
                sha256=sha256,
                previous=Decision(current["decision"]),
                new=fallback,
                reason=reason,
            )

    def request_rescan(self, sha256: str, actor: str, reason: str) -> None:
        if not actor.strip() or not reason.strip():
            raise ValueError("actor and reason must not be blank")
        with self._write() as connection:
            updated = connection.execute(
                """
                UPDATE artifacts
                SET state = 'DISCOVERED', lease_owner = NULL, lease_expires_at = NULL,
                    last_error = NULL, updated_at = ?
                WHERE sha256 = ? AND state IN ('ALLOW', 'REVIEW', 'DENY', 'ERROR')
                """,
                (_iso(self._now()), sha256),
            )
            if updated.rowcount != 1:
                raise TransitionConflict(sha256)
            connection.execute(
                "UPDATE manual_overrides SET is_current = 0 WHERE sha256 = ? AND is_current = 1",
                (sha256,),
            )
            self._audit(
                connection,
                actor=actor,
                action="artifact.rescan_requested",
                sha256=sha256,
                previous=Decision.DENY,
                new=Decision.DENY,
                reason=reason,
            )
~~~

- [ ] **Step 4: Run override tests**

Run: uv run pytest tests/verdicts/test_store_overrides.py -v

Expected: PASS.

- [ ] **Step 5: Run the full F4 suite and lints**

Run: uv run pytest tests/verdicts -v

Expected: PASS.

Run: uv run ruff check src/devpi_guardian/verdicts tests/verdicts

Expected: exit 0.

- [ ] **Step 6: Commit administrator state transitions**

~~~bash
git add src/devpi_guardian/verdicts/store.py tests/verdicts/test_store_overrides.py
git commit -m "feat: add artifact verdict overrides"
~~~

### Task 8: Resolve protected devpi requests to verified release SHA-256 values

**Files:**
- Create: src/devpi_guardian/enforcement/__init__.py
- Create: src/devpi_guardian/enforcement/resolve.py
- Create: tests/enforcement/test_resolve.py

- [ ] **Step 1: Write failing resolver tests with devpi-shaped fakes**

Create tests/enforcement/test_resolve.py:

~~~python
from types import SimpleNamespace

import pytest

from devpi_guardian.enforcement.resolve import (
    ArtifactIdentityUnavailable,
    resolve_release_sha256,
)

SHA256 = "a" * 64
F_ROUTE = "/{user}/{index}/+f/{relpath:.*}"
E_ROUTE = "/{user}/{index}/+e/{relpath:.*}"


class FakeStage:
    def __init__(self, relation="releasefile"):
        self.relation = relation

    def get_link_from_entrypath(self, relpath):
        return SimpleNamespace(rel=self.relation)


class FakeFileStore:
    def __init__(self, entry):
        self.entry = entry

    def get_file_entry(self, relpath):
        return self.entry

    def get_key_from_relpath(self, relpath):
        return None


def request(method="GET", route=F_ROUTE, sha256=SHA256, relation="releasefile"):
    entry = SimpleNamespace(hashes={"sha256": sha256})
    xom = SimpleNamespace(filestore=FakeFileStore(entry))
    return SimpleNamespace(
        method=method,
        matched_route=SimpleNamespace(name=route),
        path_info="/root/pypi/+f/abc/demo-1.0.0.whl",
        registry={"xom": xom},
        context=SimpleNamespace(stage=FakeStage(relation)),
    )


@pytest.mark.parametrize("route", [F_ROUTE, E_ROUTE])
@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_release_routes_resolve_verified_sha256(route, method) -> None:
    assert resolve_release_sha256(request(method=method, route=route)) == SHA256


def test_metadata_suffix_resolves_original_artifact() -> None:
    candidate = request()
    candidate.path_info += ".metadata"

    assert resolve_release_sha256(candidate) == SHA256


def test_non_release_and_management_requests_pass_through() -> None:
    assert resolve_release_sha256(request(relation="toxresult")) is None
    assert resolve_release_sha256(request(method="POST")) is None


@pytest.mark.parametrize("sha256", [None, "", "A" * 64, "g" * 64])
def test_release_without_canonical_sha256_fails_closed(sha256) -> None:
    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(request(sha256=sha256))
~~~

- [ ] **Step 2: Run resolver tests to verify they fail**

Run: uv run pytest tests/enforcement/test_resolve.py -v

Expected: FAIL because enforcement.resolve does not exist.

- [ ] **Step 3: Implement resolver without trusting URL fragments**

Create src/devpi_guardian/enforcement/__init__.py:

~~~python
"""Direct Artifact download enforcement."""
~~~

Create src/devpi_guardian/enforcement/resolve.py:

~~~python
from __future__ import annotations

from devpi_guardian.verdicts.errors import InvalidSha256
from devpi_guardian.verdicts.models import validate_sha256

PROTECTED_ROUTES = {
    "/{user}/{index}/+f/{relpath:.*}",
    "/{user}/{index}/+e/{relpath:.*}",
}


class ArtifactIdentityUnavailable(Exception):
    """A protected release request cannot be tied to a verified SHA-256."""


def resolve_release_sha256(request) -> str | None:
    if request.method not in {"GET", "HEAD"}:
        return None
    route = getattr(request, "matched_route", None)
    if route is None or route.name not in PROTECTED_ROUTES:
        return None

    relpath = request.path_info.strip("/")
    if relpath.endswith(".metadata"):
        relpath = relpath.removesuffix(".metadata")

    xom = request.registry["xom"]
    entry = xom.filestore.get_file_entry(relpath)
    if entry is None and route.name.endswith("/+e/{relpath:.*}"):
        key = xom.filestore.get_key_from_relpath(relpath)
        if key is not None and key.exists():
            entry = xom.filestore.get_file_entry_from_key(key)
    if entry is None:
        raise ArtifactIdentityUnavailable(relpath)

    stage = request.context.stage
    link = stage.get_link_from_entrypath(relpath)
    if link is None:
        raise ArtifactIdentityUnavailable(relpath)
    if str(link.rel) != "releasefile":
        return None

    sha256 = entry.hashes.get("sha256")
    try:
        return validate_sha256(sha256)
    except (InvalidSha256, TypeError):
        raise ArtifactIdentityUnavailable(relpath) from None
~~~

- [ ] **Step 4: Run resolver tests**

Run: uv run pytest tests/enforcement/test_resolve.py -v

Expected: PASS.

- [ ] **Step 5: Commit the devpi resolver**

~~~bash
git add src/devpi_guardian/enforcement tests/enforcement/test_resolve.py
git commit -m "feat: resolve devpi release digests"
~~~

### Task 9: Enforce ALLOW-only direct downloads in a Pyramid tween

**Files:**
- Create: src/devpi_guardian/enforcement/tween.py
- Create: tests/enforcement/test_tween.py

- [ ] **Step 1: Write failing HTTP behavior tests**

Create tests/enforcement/test_tween.py:

~~~python
from types import SimpleNamespace

import pytest

from devpi_guardian.enforcement.tween import (
    VERDICT_READER_REGISTRY_KEY,
    guardian_enforcement_tween_factory,
)
from devpi_guardian.verdicts.errors import StoreUnavailable
from devpi_guardian.verdicts.models import (
    ArtifactState,
    Decision,
    DecisionSource,
    EnforcementDecision,
)

SHA256 = "a" * 64


class Reader:
    def __init__(self, allowed=False, error=None):
        self.allowed = allowed
        self.error = error

    def get_effective_decision(self, sha256):
        if self.error:
            raise self.error
        return EnforcementDecision(
            sha256=sha256,
            allowed=self.allowed,
            effective_decision=Decision.ALLOW if self.allowed else Decision.DENY,
            source=DecisionSource.AUTOMATED,
            artifact_state=ArtifactState.ALLOW if self.allowed else ArtifactState.REVIEW,
            policy_version="policy-1",
        )


@pytest.fixture
def protected_request(monkeypatch):
    monkeypatch.setattr(
        "devpi_guardian.enforcement.tween.resolve_release_sha256",
        lambda request: SHA256,
    )
    return SimpleNamespace(log=SimpleNamespace(info=lambda *args: None))


def make_tween(reader, calls):
    registry = {VERDICT_READER_REGISTRY_KEY: reader}

    def handler(request):
        calls.append(request)
        return SimpleNamespace(status_code=200)

    return guardian_enforcement_tween_factory(handler, registry)


def test_allow_calls_downstream_handler(protected_request) -> None:
    calls = []

    response = make_tween(Reader(allowed=True), calls)(protected_request)

    assert response.status_code == 200
    assert calls == [protected_request]


def test_non_allow_returns_404_without_calling_handler(protected_request) -> None:
    calls = []

    response = make_tween(Reader(allowed=False), calls)(protected_request)

    assert response.status_code == 404
    assert calls == []


def test_store_failure_returns_503_with_retry_after(protected_request) -> None:
    calls = []

    response = make_tween(Reader(error=StoreUnavailable("locked")), calls)(
        protected_request
    )

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "5"
    assert calls == []
~~~

- [ ] **Step 2: Run tween tests to verify they fail**

Run: uv run pytest tests/enforcement/test_tween.py -v

Expected: FAIL because enforcement.tween does not exist.

- [ ] **Step 3: Implement fail-closed response mapping**

Create src/devpi_guardian/enforcement/tween.py:

~~~python
from __future__ import annotations

from pyramid.httpexceptions import HTTPNotFound, HTTPServiceUnavailable

from devpi_guardian.verdicts.errors import StoreUnavailable

from .resolve import ArtifactIdentityUnavailable, resolve_release_sha256

VERDICT_READER_REGISTRY_KEY = "devpi_guardian.verdict_reader"


def guardian_enforcement_tween_factory(handler, registry):
    reader = registry[VERDICT_READER_REGISTRY_KEY]

    def enforce(request):
        try:
            sha256 = resolve_release_sha256(request)
            if sha256 is None:
                return handler(request)
            decision = reader.get_effective_decision(sha256)
        except ArtifactIdentityUnavailable:
            request.log.info("guardian blocked artifact with unresolved SHA-256")
            return HTTPServiceUnavailable()
        except StoreUnavailable:
            request.log.info("guardian verdict store unavailable")
            return HTTPServiceUnavailable(headers={"Retry-After": "5"})

        if not decision.allowed:
            request.log.info(
                "guardian blocked sha256=%s state=%s",
                sha256,
                decision.artifact_state.value,
            )
            return HTTPNotFound()
        return handler(request)

    return enforce
~~~

- [ ] **Step 4: Add an unresolved-identity assertion and run the suite**

Add this test to tests/enforcement/test_tween.py:

~~~python
def test_unresolved_release_returns_503(monkeypatch, protected_request) -> None:
    monkeypatch.setattr(
        "devpi_guardian.enforcement.tween.resolve_release_sha256",
        lambda request: (_ for _ in ()).throw(
            __import__(
                "devpi_guardian.enforcement.resolve",
                fromlist=["ArtifactIdentityUnavailable"],
            ).ArtifactIdentityUnavailable("missing")
        ),
    )
    calls = []

    response = make_tween(Reader(), calls)(protected_request)

    assert response.status_code == 503
    assert calls == []
~~~

Run: uv run pytest tests/enforcement -v

Expected: PASS.

- [ ] **Step 5: Commit the enforcement tween**

~~~bash
git add src/devpi_guardian/enforcement/tween.py tests/enforcement/test_tween.py
git commit -m "feat: block unapproved direct downloads"
~~~

### Task 10: Register configuration, migration, reader, and tween with devpi

**Files:**
- Modify: src/devpi_guardian/plugin.py
- Modify: src/devpi_guardian/verdicts/__init__.py
- Modify: tests/test_package.py

- [ ] **Step 1: Write failing hook registration tests**

Append to tests/test_package.py:

~~~python
from pathlib import Path
from types import SimpleNamespace

from devpi_guardian.enforcement.tween import VERDICT_READER_REGISTRY_KEY
from devpi_guardian.plugin import (
    devpiserver_add_parser_options,
    devpiserver_pyramid_configure,
)


class FakeParser:
    def __init__(self):
        self.calls = []

    def addoption(self, *args, **kwargs):
        self.calls.append((args, kwargs))


class FakePyramidConfig:
    def __init__(self):
        self.registry = {}
        self.tweens = []

    def add_tween(self, name, **kwargs):
        self.tweens.append((name, kwargs))


def test_parser_exposes_guardian_db_option() -> None:
    parser = FakeParser()

    devpiserver_add_parser_options(parser)

    assert parser.calls[0][0] == ("--guardian-db",)
    assert parser.calls[0][1]["dest"] == "guardian_db"


def test_pyramid_hook_migrates_and_registers_reader_and_tween(tmp_path) -> None:
    pyramid = FakePyramidConfig()
    config = SimpleNamespace(
        args=SimpleNamespace(guardian_db=str(tmp_path / "guardian.db")),
        server_path=Path(tmp_path / "server"),
    )

    devpiserver_pyramid_configure(config, pyramid)

    assert VERDICT_READER_REGISTRY_KEY in pyramid.registry
    assert pyramid.tweens == [
        (
            "devpi_guardian.enforcement.tween.guardian_enforcement_tween_factory",
            {"under": "devpi_server.views.tween_keyfs_transaction"},
        )
    ]
~~~

- [ ] **Step 2: Run hook tests to verify they fail**

Run: uv run pytest tests/test_package.py -v

Expected: FAIL because the hook functions do not exist.

- [ ] **Step 3: Implement devpi hook registration**

Replace src/devpi_guardian/plugin.py with:

~~~python
from __future__ import annotations

from pathlib import Path

from pluggy import HookimplMarker

from .enforcement.tween import VERDICT_READER_REGISTRY_KEY
from .verdicts.db import ConnectionFactory, migrate
from .verdicts.reader import SQLiteVerdictReader

server_hookimpl = HookimplMarker("devpiserver")


@server_hookimpl
def devpiserver_add_parser_options(parser) -> None:
    parser.addoption(
        "--guardian-db",
        action="store",
        dest="guardian_db",
        default=None,
        help="path to the persistent devpi-guardian SQLite database",
    )


@server_hookimpl
def devpiserver_pyramid_configure(config, pyramid_config) -> None:
    configured = config.args.guardian_db
    db_path = (
        Path(configured)
        if configured is not None
        else Path(config.server_path) / "guardian" / "guardian.db"
    )
    factory = ConnectionFactory(db_path)
    migrate(factory)
    pyramid_config.registry[VERDICT_READER_REGISTRY_KEY] = SQLiteVerdictReader(factory)
    pyramid_config.add_tween(
        "devpi_guardian.enforcement.tween.guardian_enforcement_tween_factory",
        under="devpi_server.views.tween_keyfs_transaction",
    )
~~~

Update src/devpi_guardian/verdicts/__init__.py:

~~~python
from .db import ConnectionFactory, migrate
from .interfaces import ArtifactStore, AuditWriter, VerdictReader
from .models import ArtifactState, Decision, EnforcementDecision
from .reader import SQLiteVerdictReader
from .store import SQLiteArtifactStore

__all__ = [
    "ArtifactState",
    "ArtifactStore",
    "AuditWriter",
    "ConnectionFactory",
    "Decision",
    "EnforcementDecision",
    "SQLiteArtifactStore",
    "SQLiteVerdictReader",
    "VerdictReader",
    "migrate",
]
~~~

- [ ] **Step 4: Run plugin discovery and hook tests**

Run: uv run pytest tests/test_package.py -v

Expected: PASS.

Run: uv run python -c "from devpi_server.config import get_pluginmanager; pm = get_pluginmanager(); assert any(name == 'guardian' for name, _ in pm.list_name_plugin())"

Expected: exit 0, proving the installed entry point is discovered by devpi-server 6.20.3.

- [ ] **Step 5: Commit plugin registration**

~~~bash
git add src/devpi_guardian/plugin.py src/devpi_guardian/verdicts/__init__.py tests/test_package.py
git commit -m "feat: register guardian enforcement plugin"
~~~

### Task 11: Prove direct +f and uv URL enforcement against a real devpi server

**Files:**
- Modify: pyproject.toml
- Create: tests/integration/conftest.py
- Create: tests/integration/test_direct_download.py

- [ ] **Step 1: Add integration-only build and client dependencies**

Add to the test extra in pyproject.toml:

~~~toml
  "build>=1,<2",
  "devpi-client>=7,<8",
~~~

Run: uv sync --extra test

Expected: exit 0 and uv.lock contains build and devpi-client.

- [ ] **Step 2: Create a real devpi process fixture**

Create tests/integration/conftest.py:

~~~python
from __future__ import annotations

import os
import socket
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import pytest


@dataclass(frozen=True)
class RunningDevpi:
    base_url: str
    guardian_db: Path
    client_dir: Path

    def api(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
        environment = os.environ.copy()
        environment["DEVPI_CLIENTDIR"] = str(self.client_dir)
        return subprocess.run(
            ["devpi", *args],
            cwd=cwd,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )


def _free_port() -> int:
    with socket.socket() as candidate:
        candidate.bind(("127.0.0.1", 0))
        return candidate.getsockname()[1]


@pytest.fixture
def running_devpi(tmp_path) -> RunningDevpi:
    server_dir = tmp_path / "server"
    client_dir = tmp_path / "client"
    guardian_db = tmp_path / "guardian.db"
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    subprocess.run(
        ["devpi-init", "--serverdir", str(server_dir)],
        check=True,
        capture_output=True,
        text=True,
    )
    process = subprocess.Popen(
        [
            "devpi-server",
            "--serverdir",
            str(server_dir),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--guardian-db",
            str(guardian_db),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                with urllib.request.urlopen(f"{base_url}/+status", timeout=1):
                    break
            except OSError:
                if process.poll() is not None:
                    output = process.stdout.read() if process.stdout else ""
                    raise RuntimeError(output)
                if time.monotonic() >= deadline:
                    raise RuntimeError("devpi-server did not become ready")
                time.sleep(0.1)

        server = RunningDevpi(base_url, guardian_db, client_dir)
        server.api("use", base_url)
        server.api("login", "root", "--password=")
        server.api("index", "-c", "root/dev")
        server.api("use", "root/dev")
        yield server
    finally:
        process.terminate()
        process.wait(timeout=10)
~~~

- [ ] **Step 3: Write a focused real-server test**

Create tests/integration/test_direct_download.py:

~~~python
from __future__ import annotations

import hashlib
import html.parser
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta

import pytest

from devpi_guardian.verdicts.db import ConnectionFactory
from devpi_guardian.verdicts.models import (
    ArtifactInput,
    Decision,
    ReleaseInput,
    VerdictInput,
)
from devpi_guardian.verdicts.store import SQLiteArtifactStore
from tests.conftest import RecordingAuditWriter

pytestmark = pytest.mark.integration


class FirstLink(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.href = None

    def handle_starttag(self, tag, attrs):
        if tag == "a" and self.href is None:
            self.href = dict(attrs).get("href")


def test_direct_url_is_blocked_until_same_sha256_is_allowed(
    running_devpi, tmp_path
) -> None:
    project = tmp_path / "demo"
    package = project / "src" / "demo_guardian"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text('__version__ = "1.0.0"\n')
    (project / "pyproject.toml").write_text(
        """
[build-system]
requires = ["setuptools>=80"]
build-backend = "setuptools.build_meta"

[project]
name = "demo-guardian"
version = "1.0.0"
""".strip()
    )
    running_devpi.api("upload", cwd=project)
    wheel = next((project / "dist").glob("*.whl"))
    content = wheel.read_bytes()
    sha256 = hashlib.sha256(content).hexdigest()

    with urllib.request.urlopen(
        f"{running_devpi.base_url}/root/dev/+simple/demo-guardian/"
    ) as response:
        parser = FirstLink()
        parser.feed(response.read().decode())
    assert parser.href is not None
    direct_url = urllib.parse.urljoin(running_devpi.base_url, parser.href)

    with pytest.raises(urllib.error.HTTPError) as blocked:
        urllib.request.urlopen(direct_url)
    assert blocked.value.code == 404

    now = datetime.now(UTC)
    store = SQLiteArtifactStore(
        ConnectionFactory(running_devpi.guardian_db),
        RecordingAuditWriter(),
        now=lambda: now,
    )
    store.discover_artifact(
        ArtifactInput(sha256, len(content), now),
        ReleaseInput(
            "root/dev",
            "demo-guardian",
            "1.0.0",
            wheel.name,
            sha256,
            direct_url,
            now,
        ),
    )
    store.claim_next("integration-worker", now + timedelta(minutes=5))
    store.record_verdict(
        VerdictInput(
            sha256, Decision.ALLOW, 0, "policy-1", "analyzer-1", None, now
        ),
        [],
    )

    with urllib.request.urlopen(direct_url) as allowed:
        assert allowed.read() == content
~~~

- [ ] **Step 4: Run the real-server test**

Run: uv run pytest tests/integration/test_direct_download.py -v -m integration

Expected: PASS; the same direct +f URL returns 404 before the ALLOW verdict and exact wheel bytes after ALLOW.

- [ ] **Step 5: Add HEAD and uv direct-URL assertions**

Append to test_direct_url_is_blocked_until_same_sha256_is_allowed before recording ALLOW:

~~~python
    head_request = urllib.request.Request(direct_url, method="HEAD")
    with pytest.raises(urllib.error.HTTPError) as blocked_head:
        urllib.request.urlopen(head_request)
    assert blocked_head.value.code == 404

    environment = os.environ.copy()
    environment["UV_NO_CACHE"] = "1"
    venv = tmp_path / "uv-venv"
    subprocess.run(["uv", "venv", str(venv)], check=True, env=environment)
    blocked_uv = subprocess.run(
        ["uv", "pip", "install", "--python", str(venv / "bin" / "python"), direct_url],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert blocked_uv.returncode != 0
~~~

After recording ALLOW, append:

~~~python
    subprocess.run(
        ["uv", "pip", "install", "--python", str(venv / "bin" / "python"), direct_url],
        check=True,
        env=environment,
    )
~~~

Run: uv run pytest tests/integration/test_direct_download.py -v -m integration

Expected: PASS, including HEAD and uv installation from the exact approved URL.

- [ ] **Step 6: Commit the integration proof**

~~~bash
git add pyproject.toml uv.lock tests/integration
git commit -m "test: verify direct artifact enforcement"
~~~

### Task 12: Verify failure modes, latency, documentation, and full quality gates

**Files:**
- Modify: tests/verdicts/test_reader.py
- Modify: tests/verdicts/test_store_claims.py
- Modify: tests/enforcement/test_tween.py
- Modify: README.md

- [ ] **Step 1: Add a fresh-store latency test**

Append to tests/verdicts/test_reader.py:

~~~python
import statistics
import time

import pytest


@pytest.mark.performance
def test_single_verdict_lookup_p95_is_under_100_ms(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(factory, SHA_ALLOW, "ALLOW", automated="ALLOW")
    reader = SQLiteVerdictReader(factory, now=lambda: NOW)

    durations = []
    for _ in range(1_000):
        started = time.perf_counter_ns()
        assert reader.get_effective_decision(SHA_ALLOW).allowed is True
        durations.append((time.perf_counter_ns() - started) / 1_000_000)

    p95 = statistics.quantiles(durations, n=100)[94]
    assert p95 < 100
~~~

- [ ] **Step 2: Add real lock, corruption, and reconnection failure tests**

Append to tests/verdicts/test_reader.py:

~~~python
from devpi_guardian.verdicts.errors import StoreUnavailable


def test_reader_propagates_store_unavailable() -> None:
    class UnavailableFactory:
        path = "guardian.db"

        def connect(self):
            raise StoreUnavailable("guardian.db")

    with pytest.raises(StoreUnavailable):
        SQLiteVerdictReader(UnavailableFactory(), now=lambda: NOW).get_effective_decision(
            SHA_ALLOW
        )


def test_corrupt_database_is_store_unavailable(tmp_path) -> None:
    path = tmp_path / "guardian.db"
    path.write_bytes(b"not-a-sqlite-database")

    with pytest.raises(StoreUnavailable):
        SQLiteVerdictReader(
            ConnectionFactory(path), now=lambda: NOW
        ).get_effective_decision(SHA_ALLOW)
~~~

Add these imports to the import section of tests/verdicts/test_store_claims.py:

~~~python
import pytest

from devpi_guardian.verdicts.errors import StoreUnavailable
~~~

Then append:

~~~python


def test_writer_lock_times_out_then_reconnects(tmp_path, audit_writer) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db", busy_timeout_ms=1)
    migrate(factory)
    store = SQLiteArtifactStore(factory, audit_writer, now=lambda: NOW)

    with factory.connect() as locker:
        locker.execute("BEGIN IMMEDIATE")
        with pytest.raises(StoreUnavailable):
            discover(store)
        locker.rollback()

    discover(store)
    assert store.claim_next("worker-after-lock", NOW + timedelta(minutes=5)) is not None
~~~

Run: uv run pytest tests/verdicts/test_reader.py tests/verdicts/test_store_claims.py -v

Expected: PASS; a real competing writer times out as StoreUnavailable, the next connection succeeds after lock release, and corrupt bytes never produce an enforcement decision.

- [ ] **Step 3: Document the integration surface**

Append to README.md:

~~~markdown
## F3/F4 integration

- F1/F2 import VerdictReader and call get_effective_decisions for Simple links.
- F5 constructs SQLiteArtifactStore with the F12 AuditWriter and uses claim_next,
  record_verdict, mark_analysis_error, and request_rescan.
- F10 passes VerdictInput plus EvidenceInput values to record_verdict.
- F11 maps ArtifactNotFound to 404, TransitionConflict to 409, and
  StoreUnavailable to 503.
- F12 implements AuditWriter.append_in_transaction using the same sqlite3
  connection supplied by F4.

Start devpi-server with:

    devpi-server --guardian-db /var/lib/devpi-guardian/guardian.db

The database path must be on a persistent volume. Missing decisions, database
failures, noncanonical SHA-256 values, REVIEW, DENY, and ERROR all block delivery.
~~~

- [ ] **Step 4: Run the complete test matrix**

Run: uv run pytest -v

Expected: PASS with no skipped F3/F4 tests.

Run: uv run pytest -m performance -v

Expected: PASS and measured P95 below 100ms.

- [ ] **Step 5: Run all quality gates and build the wheel**

Run: uv run ruff format --check .

Expected: exit 0.

Run: uv run ruff check .

Expected: exit 0.

Run: uv run flake8 src tests

Expected: exit 0.

Run: uv build

Expected: exit 0 and dist contains both a source archive and wheel.

Run: uv run python -c "from importlib import resources; assert resources.files('devpi_guardian.verdicts.sql').joinpath('001_initial.sql').is_file()"

Expected: exit 0, proving the migration is packaged.

- [ ] **Step 6: Commit final verification and documentation**

~~~bash
git add README.md tests
git commit -m "docs: describe guardian verdict integration"
~~~

- [ ] **Step 7: Review the diff against every completion criterion**

Run: git diff main...HEAD --stat

Expected: only F3/F4 source, tests, package metadata, news, README, design, and plan files are present.

Run: git status --short

Expected: no output.
