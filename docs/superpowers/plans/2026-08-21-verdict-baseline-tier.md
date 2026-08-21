# Verdict Baseline Tier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve F6's `selection.tier` through F10's `VerdictInput` and F4's immutable SQLite verdict history.

**Architecture:** Add a strict `BaselineTier` Literal contract to the DTO, then introduce schema version 2 with a nullable checked column and an INSERT pair guard that leaves legacy v1 rows untouched. The store validates before connecting, persists and reads back the tier transactionally, while the reader-side invariant validator accepts legacy `baseline_sha256 + NULL tier` rows but rejects tier-only and unknown values.

**Tech Stack:** Python 3.11 dataclasses and Literal typing, sqlite3 resource migrations and triggers, pytest, Ruff, Flake8, uv/build.

---

## File map

- Modify `src/devpi_guardian/verdicts/models.py`: define and runtime-validate `BaselineTier`; extend `VerdictInput`.
- Modify `src/devpi_guardian/verdicts/db.py`: upgrade the migration runner from one fixed schema to sequential versions 1 and 2.
- Create `src/devpi_guardian/verdicts/sql/002_baseline_tier.sql`: add the column, pair trigger, and tier-aware immutable-history trigger.
- Modify `src/devpi_guardian/verdicts/store.py`: preflight, persist, and read back `baseline_tier`.
- Modify `src/devpi_guardian/verdicts/invariants.py`: validate persisted tiers while allowing unclassified v1 baseline rows.
- Modify `src/devpi_guardian/verdicts/reader.py`: include the tier in current-verdict rows passed to invariant validation.
- Modify `tests/verdicts/test_models.py`: cover the three Literal values and invalid/mismatched DTO inputs.
- Modify `tests/verdicts/test_db.py`: cover v2 creation, v1 upgrade, legacy preservation, CHECK/pair guards, and history immutability.
- Modify `tests/verdicts/test_store_verdicts.py`: cover transactional persistence and pre-connection rejection.
- Modify `tests/verdicts/test_invariants.py`: cover supported, legacy, unknown, and tier-only persisted states.
- Modify `tests/verdicts/test_store_overrides.py` and `tests/integration/test_direct_download.py`: supply the new required constructor argument.
- Modify `tests/test_package.py`: assert schema version 2 and the documented F6/F10 contract.
- Modify `README.md` and `docs/superpowers/specs/2026-08-17-devpi-guardian-f3-f4-design.md`: publish the integration contract.
- Create `news/3.feature`: record the user-visible contract extension.

### Task 1: Add the strict VerdictInput contract

**Files:**
- Modify: `src/devpi_guardian/verdicts/models.py:3-13,193-213`
- Modify: `tests/verdicts/test_models.py:1-265`
- Modify: `tests/verdicts/test_store_verdicts.py:39-80,585-625`
- Modify: `tests/verdicts/test_store_overrides.py:120-145,630-655`
- Modify: `tests/integration/test_direct_download.py:139-163,492-506`

- [ ] **Step 1: Write focused failing model tests**

Add `BASELINE_SHA256 = "b" * 64` beside `SHA256` in `tests/verdicts/test_models.py`, add `baseline_tier=None` to the three existing `VerdictInput` constructors, and append:

```python
class DerivedTier(str):
    pass


@pytest.mark.parametrize(
    "tier",
    ["same_tag", "universal_wheel", "sdist"],
)
def test_verdict_accepts_supported_baseline_tiers(tier: str) -> None:
    verdict = VerdictInput(
        sha256=SHA256,
        decision=Decision.REVIEW,
        score=1.0,
        policy_version="policy-1",
        analyzer_version="analyzer-1",
        baseline_sha256=BASELINE_SHA256,
        baseline_tier=tier,  # type: ignore[arg-type]
    )

    assert verdict.baseline_tier == tier


@pytest.mark.parametrize(
    "tier",
    ["same-tag", "", 1, True, DerivedTier("same_tag")],
)
def test_verdict_rejects_unsupported_baseline_tiers(tier: object) -> None:
    with pytest.raises(ValueError, match="baseline_tier"):
        VerdictInput(
            sha256=SHA256,
            decision=Decision.REVIEW,
            score=1.0,
            policy_version="policy-1",
            analyzer_version="analyzer-1",
            baseline_sha256=BASELINE_SHA256,
            baseline_tier=tier,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("baseline_sha256", "baseline_tier"),
    [(None, "same_tag"), (BASELINE_SHA256, None)],
)
def test_verdict_requires_baseline_sha256_and_tier_together(
    baseline_sha256: str | None,
    baseline_tier: str | None,
) -> None:
    with pytest.raises(ValueError, match="baseline_sha256 and baseline_tier"):
        VerdictInput(
            sha256=SHA256,
            decision=Decision.REVIEW,
            score=1.0,
            policy_version="policy-1",
            analyzer_version="analyzer-1",
            baseline_sha256=baseline_sha256,
            baseline_tier=baseline_tier,  # type: ignore[arg-type]
        )
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```bash
uv run pytest tests/verdicts/test_models.py -q
```

Expected: FAIL because `VerdictInput.__init__()` does not accept `baseline_tier`.

- [ ] **Step 3: Implement the Literal and runtime validation**

Change the typing import in `src/devpi_guardian/verdicts/models.py` and add the exact type, values, and validator after `_SHA256_PATTERN`:

```python
from typing import Any, Literal, cast

BaselineTier = Literal["same_tag", "universal_wheel", "sdist"]

_BASELINE_TIERS = frozenset(("same_tag", "universal_wheel", "sdist"))


def validate_baseline_tier(value: object) -> BaselineTier:
    if type(value) is not str or value not in _BASELINE_TIERS:
        raise ValueError("invalid baseline_tier")
    return cast(BaselineTier, value)
```

Replace `VerdictInput` with:

```python
@dataclass(frozen=True, slots=True)
class VerdictInput:
    sha256: str
    decision: Decision
    score: float
    policy_version: str
    analyzer_version: str
    baseline_sha256: str | None
    baseline_tier: BaselineTier | None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        validate_sha256(self.sha256)
        _require_decision(self.decision, "decision")
        object.__setattr__(self, "score", _normalize_score(self.score))
        if self.baseline_sha256 is not None:
            validate_sha256(self.baseline_sha256)
        if (self.baseline_sha256 is None) != (self.baseline_tier is None):
            raise ValueError("baseline_sha256 and baseline_tier must be paired")
        if self.baseline_tier is not None:
            validate_baseline_tier(self.baseline_tier)
        versions = self.policy_version.strip(), self.analyzer_version.strip()
        if not all(versions):
            message = "policy_version and analyzer_version"
            raise ValueError(f"{message} must not be blank")
        require_utc(self.created_at, "created_at")
```

- [ ] **Step 4: Update every executable VerdictInput caller**

Apply these exact argument changes so the new field remains required and the test suite has no silent legacy caller:

```python
# tests/verdicts/test_store_verdicts.py: verdict() values
"baseline_sha256": None,
"baseline_tier": None,

# tests/verdicts/test_store_verdicts.py: unchecked_verdict() values
"baseline_sha256": valid.baseline_sha256,
"baseline_tier": valid.baseline_tier,

# Both baseline-bearing calls in test_store_verdicts.py
verdict(
    baseline_sha256=BASELINE_SHA256,
    baseline_tier="same_tag",
)

# Keyword constructors in test_store_overrides.py
baseline_sha256=None,
baseline_tier=None,
created_at=NOW,

# Positional constructors in test_store_overrides.py and
# tests/integration/test_direct_download.py: insert a second None after
# baseline_sha256 and before created_at.
VerdictInput(
    sha256,
    decision,
    score,
    policy_version,
    analyzer_version,
    None,
    None,
    created_at,
)
```

Confirm executable constructors contain the field:

```bash
rg -n "VerdictInput\(" tests
rg -n "baseline_tier" tests/verdicts/test_models.py tests/verdicts/test_store_verdicts.py tests/verdicts/test_store_overrides.py tests/integration/test_direct_download.py
```

Expected: every keyword constructor has `baseline_tier`; every positional constructor has two adjacent nullable baseline arguments.

- [ ] **Step 5: Verify GREEN and the full regression suite**

Run:

```bash
uv run pytest tests/verdicts/test_models.py -q
uv run pytest -q
uv run ruff check src/devpi_guardian/verdicts/models.py tests/verdicts/test_models.py tests/verdicts/test_store_verdicts.py tests/verdicts/test_store_overrides.py tests/integration/test_direct_download.py
```

Expected: all commands exit 0 with no failures or warnings.

- [ ] **Step 6: Commit the domain contract**

```bash
git add src/devpi_guardian/verdicts/models.py tests/verdicts/test_models.py tests/verdicts/test_store_verdicts.py tests/verdicts/test_store_overrides.py tests/integration/test_direct_download.py
git commit -m "feat: add verdict baseline tier contract"
```

### Task 2: Migrate and persist baseline tier atomically

**Files:**
- Create: `src/devpi_guardian/verdicts/sql/002_baseline_tier.sql`
- Modify: `src/devpi_guardian/verdicts/db.py:12-145`
- Modify: `src/devpi_guardian/verdicts/store.py:14-31,635-824`
- Modify: `src/devpi_guardian/verdicts/invariants.py:10-18,248-257`
- Modify: `src/devpi_guardian/verdicts/reader.py:88-105`
- Modify: `tests/verdicts/test_db.py:51-87,380-462,510-595`
- Modify: `tests/verdicts/test_store_verdicts.py:39-80,182-250,585-748`
- Modify: `tests/verdicts/test_invariants.py:10-108`
- Modify: `tests/test_package.py:86-105`

- [ ] **Step 1: Write failing migration and schema tests**

In `tests/verdicts/test_db.py`, add `verdicts_baseline_pair_insert_guard` to `expected_triggers`, change `assert version == 1` to `assert version == 2`, change the future-version seed from `2` to `3`, and generalize the resource helper:

```python
def _packaged_migration_sql(version: int = 1) -> str:
    filename = "001_initial.sql" if version == 1 else "002_baseline_tier.sql"
    return (
        db.resources.files("devpi_guardian.verdicts.sql")
        .joinpath(filename)
        .read_text(encoding="utf-8")
    )
```

Append these upgrade and guard tests:

```python
def test_migrate_upgrades_v1_and_preserves_unclassified_legacy_baseline(
    tmp_path,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    _seed_version_one_schema(factory.path, _packaged_migration_sql(1))
    timestamp = "2026-08-17T00:00:00+00:00"
    artifact_sha256 = "a" * 64
    baseline_sha256 = "b" * 64
    with closing(sqlite3.connect(factory.path)) as connection, connection:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executemany(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at
            ) VALUES (?, 1, ?, ?, ?)
            """,
            [
                (artifact_sha256, "REVIEW", timestamp, timestamp),
                (baseline_sha256, "DISCOVERED", timestamp, timestamp),
            ],
        )
        connection.execute(
            """
            INSERT INTO verdicts(
                sha256, decision, score, policy_version, analyzer_version,
                baseline_sha256, is_current, created_at
            ) VALUES (?, 'REVIEW', 1.0, 'policy-1', 'analyzer-1', ?, 1, ?)
            """,
            (artifact_sha256, baseline_sha256, timestamp),
        )

    migrate(factory)
    migrate(factory)

    with closing(factory.connect()) as connection:
        versions = [
            row[0]
            for row in connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version",
            )
        ]
        legacy = connection.execute(
            "SELECT baseline_sha256, baseline_tier FROM verdicts",
        ).fetchone()

    assert versions == [1, 2]
    assert tuple(legacy) == (baseline_sha256, None)


@pytest.mark.parametrize(
    ("baseline_sha256", "baseline_tier"),
    [(None, "same_tag"), ("b" * 64, None), ("b" * 64, "unknown")],
)
def test_schema_rejects_new_invalid_baseline_tier_pairs(
    tmp_path,
    baseline_sha256: str | None,
    baseline_tier: str | None,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    timestamp = "2026-08-17T00:00:00+00:00"
    with closing(factory.connect()) as connection, connection:
        connection.executemany(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at
            ) VALUES (?, 1, 'DISCOVERED', ?, ?)
            """,
            [("a" * 64, timestamp, timestamp), ("b" * 64, timestamp, timestamp)],
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO verdicts(
                    sha256, decision, score, policy_version, analyzer_version,
                    baseline_sha256, is_current, created_at, baseline_tier
                ) VALUES (?, 'REVIEW', 1.0, 'policy-1', 'analyzer-1', ?, 1, ?, ?)
                """,
                ("a" * 64, baseline_sha256, timestamp, baseline_tier),
            )
```

Extend the verdict mutation parameter list with:

```python
[
    "UPDATE verdicts SET baseline_tier = 'sdist'",
    "UPDATE verdicts SET baseline_tier = 'sdist', is_current = 0",
]
```

In `tests/test_package.py`, change the plugin migration assertion to:

```python
migration_query = "SELECT MAX(version) FROM schema_migrations"
assert connection.execute(migration_query).fetchone() == (2,)
```

- [ ] **Step 2: Write failing store and persisted-invariant tests**

Replace the existing baseline persistence test in `tests/verdicts/test_store_verdicts.py` with:

```python
@pytest.mark.parametrize(
    "baseline_tier",
    ["same_tag", "universal_wheel", "sdist"],
)
def test_record_verdict_persists_baseline_sha256_and_tier(
    tmp_path,
    audit_writer,
    baseline_tier: str,
) -> None:
    store, claim = prepare_scanning(tmp_path, audit_writer)
    store.discover_artifact(
        artifact(sha256=BASELINE_SHA256),
        release(
            sha256=BASELINE_SHA256,
            version="0.9.0",
            filename="demo_package-0.9.0.whl",
        ),
    )
    audit_writer.events.clear()

    store.record_verdict(
        claim,
        verdict(
            baseline_sha256=BASELINE_SHA256,
            baseline_tier=baseline_tier,
        ),
        (),
    )

    row = fetchall(
        store,
        "SELECT baseline_sha256, baseline_tier FROM verdicts",
    )[0]
    assert tuple(row) == (BASELINE_SHA256, baseline_tier)
```

Keep the missing-baseline test but pass `baseline_tier="same_tag"`. Add these cases to `test_record_verdict_validates_mutated_dto_before_connecting`:

```python
[
    ({"baseline_tier": "same_tag"}, ValueError),
    ({"baseline_tier": "unknown"}, ValueError),
    ({"baseline_tier": 1}, ValueError),
    ({"baseline_sha256": BASELINE_SHA256}, ValueError),
]
```

Add `"baseline_tier": valid.baseline_tier` to `unchecked_verdict()` so mutated DTOs carry the full slot set.

In `tests/verdicts/test_invariants.py`, add `"baseline_tier": None` to `persisted_rows()` and append:

```python
@pytest.mark.parametrize(
    "baseline_tier",
    ["same_tag", "universal_wheel", "sdist"],
)
def test_persisted_verdict_accepts_supported_baseline_tier(
    baseline_tier: str,
) -> None:
    artifact, verdict, override = persisted_rows()
    verdict["baseline_sha256"] = "b" * 64
    verdict["baseline_tier"] = baseline_tier

    validate_persisted_state(artifact, verdict, override, NOW)


def test_persisted_verdict_allows_unclassified_v1_baseline() -> None:
    artifact, verdict, override = persisted_rows()
    verdict["baseline_sha256"] = "b" * 64

    validate_persisted_state(artifact, verdict, override, NOW)


@pytest.mark.parametrize("baseline_tier", ["unknown", 1, b"same_tag"])
def test_persisted_verdict_rejects_invalid_baseline_tier(
    baseline_tier: object,
) -> None:
    artifact, verdict, override = persisted_rows()
    verdict["baseline_sha256"] = "b" * 64
    verdict["baseline_tier"] = baseline_tier

    with pytest.raises(PersistedStateCorruption, match="baseline tier"):
        validate_persisted_state(artifact, verdict, override, NOW)


def test_persisted_verdict_rejects_tier_without_baseline() -> None:
    artifact, verdict, override = persisted_rows()
    verdict["baseline_tier"] = "same_tag"

    with pytest.raises(PersistedStateCorruption, match="baseline tier"):
        validate_persisted_state(artifact, verdict, override, NOW)
```

- [ ] **Step 3: Run the focused tests and verify RED**

Run:

```bash
uv run pytest tests/verdicts/test_db.py tests/verdicts/test_store_verdicts.py tests/verdicts/test_invariants.py tests/test_package.py -q
```

Expected: FAIL because schema version 2, `baseline_tier` persistence, and persisted-tier validation do not exist.

- [ ] **Step 4: Create schema migration 002**

Create `src/devpi_guardian/verdicts/sql/002_baseline_tier.sql` with:

```sql
ALTER TABLE verdicts
ADD COLUMN baseline_tier TEXT
CHECK(
    baseline_tier IS NULL
    OR (
        typeof(baseline_tier) = 'text'
        AND baseline_tier IN ('same_tag', 'universal_wheel', 'sdist')
    )
);

DROP TRIGGER verdicts_history_update_guard;

CREATE TRIGGER verdicts_history_update_guard
BEFORE UPDATE ON verdicts
WHEN NOT (
    OLD.is_current = 1
    AND NEW.is_current = 0
    AND NEW.id IS OLD.id
    AND NEW.sha256 IS OLD.sha256
    AND NEW.decision IS OLD.decision
    AND NEW.score IS OLD.score
    AND NEW.policy_version IS OLD.policy_version
    AND NEW.analyzer_version IS OLD.analyzer_version
    AND NEW.baseline_sha256 IS OLD.baseline_sha256
    AND NEW.created_at IS OLD.created_at
    AND NEW.baseline_tier IS OLD.baseline_tier
)
BEGIN
    SELECT RAISE(ABORT, 'immutable verdict history');
END;

CREATE TRIGGER verdicts_baseline_pair_insert_guard
BEFORE INSERT ON verdicts
WHEN (NEW.baseline_sha256 IS NULL) != (NEW.baseline_tier IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'baseline sha256 and tier must be paired');
END;
```

- [ ] **Step 5: Upgrade the migration runner to sequential schemas**

Replace the fixed migration constants and add resource helpers in `src/devpi_guardian/verdicts/db.py`:

```python
_MAX_BUSY_TIMEOUT_MS = 2_147_483_647
_MIGRATION_FILES = ("001_initial.sql", "002_baseline_tier.sql")
_SUPPORTED_SCHEMA_VERSION = len(_MIGRATION_FILES)


def _read_migration(version: int) -> str:
    return (
        resources.files("devpi_guardian.verdicts.sql")
        .joinpath(_MIGRATION_FILES[version - 1])
        .read_text(encoding="utf-8")
    )


def _migration_sql_through(version: int) -> str:
    return "\n".join(_read_migration(item) for item in range(1, version + 1))
```

Replace `_read_version()` with contiguous-history validation:

```python
def _read_version(connection: sqlite3.Connection, path: Path) -> int:
    query = "SELECT version FROM schema_migrations ORDER BY version"
    rows = connection.execute(query).fetchall()
    versions = [row[0] for row in rows]
    if not versions:
        raise MigrationError(str(path))
    if any(type(version) is not int for version in versions):
        raise MigrationError(str(path))
    current = max(versions)
    if current > _SUPPORTED_SCHEMA_VERSION:
        raise MigrationError(str(path))
    if versions != list(range(1, current + 1)):
        raise MigrationError(str(path))
    return current
```

Replace `migrate()` with:

```python
def migrate(factory: ConnectionFactory) -> None:
    connection = factory.connect()
    try:
        journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
        if journal_mode is None or journal_mode[0] != "wal":
            raise MigrationError(str(factory.path))
        has_migrations = connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'schema_migrations'
            """
        ).fetchone()
        current = 0
        if has_migrations:
            current = _read_version(connection, factory.path)
            expected = _expected_catalog(_migration_sql_through(current))
            _validate_catalog(connection, expected, factory.path)

        for version in range(current + 1, _SUPPORTED_SCHEMA_VERSION + 1):
            sql = _read_migration(version)
            connection.executescript("BEGIN IMMEDIATE;\n" + sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, datetime.now(UTC).isoformat()),
            )
            expected = _expected_catalog(_migration_sql_through(version))
            _validate_catalog(connection, expected, factory.path)
            connection.commit()
    except MigrationError:
        if connection.in_transaction:
            connection.rollback()
        raise
    except (ImportError, OSError, UnicodeError, sqlite3.Error) as exc:
        if connection.in_transaction:
            connection.rollback()
        raise MigrationError(str(factory.path)) from exc
    finally:
        connection.close()
```

- [ ] **Step 6: Persist and read back the tier in record_verdict**

Import `validate_baseline_tier` from `.models` in `src/devpi_guardian/verdicts/store.py`. In the preflight `try` block read `baseline_tier = verdict.baseline_tier`, then validate the pair before comparing claim SHA-256:

```python
if baseline_sha256 is not None:
    baseline_sha256 = validate_sha256(baseline_sha256)
if (baseline_sha256 is None) != (baseline_tier is None):
    raise ValueError("baseline_sha256 and baseline_tier must be paired")
if baseline_tier is not None:
    baseline_tier = validate_baseline_tier(baseline_tier)
if sha256 != claim_sha256:
    raise TransitionConflict(sha256)
```

Replace the verdict INSERT with:

```python
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
```

Replace the stored-verdict query and tuple with:

```python
stored_verdict = connection.execute(
    """
    SELECT sha256, decision, score, policy_version,
           analyzer_version, baseline_sha256, is_current, created_at,
           baseline_tier
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
```

- [ ] **Step 7: Validate persisted tiers and include the column in reader rows**

Import `validate_baseline_tier` in `src/devpi_guardian/verdicts/invariants.py` and add this after the existing baseline SHA-256 validation:

```python
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
```

Change the current-verdict SELECT in `src/devpi_guardian/verdicts/reader.py` to include the appended column:

```python
SELECT id, sha256, decision, score,
       policy_version, analyzer_version,
       baseline_sha256, is_current, created_at, baseline_tier
```

- [ ] **Step 8: Verify GREEN for persistence and all verdict behavior**

Run:

```bash
uv run pytest tests/verdicts/test_db.py tests/verdicts/test_store_verdicts.py tests/verdicts/test_invariants.py tests/test_package.py -q
uv run pytest tests/verdicts -q
uv run pytest tests/enforcement tests/integration -q
uv run ruff check src/devpi_guardian/verdicts tests/verdicts tests/test_package.py
```

Expected: all commands exit 0; schema versions are `[1, 2]`, all three tiers persist exactly, and legacy v1 baseline rows retain `NULL` tier.

- [ ] **Step 9: Commit the persistence path**

```bash
git add src/devpi_guardian/verdicts/db.py src/devpi_guardian/verdicts/sql/002_baseline_tier.sql src/devpi_guardian/verdicts/store.py src/devpi_guardian/verdicts/invariants.py src/devpi_guardian/verdicts/reader.py tests/verdicts/test_db.py tests/verdicts/test_store_verdicts.py tests/verdicts/test_invariants.py tests/test_package.py
git commit -m "feat: persist verdict baseline tier"
```

### Task 3: Publish the contract and run final acceptance

**Files:**
- Modify: `tests/test_package.py:125-end`
- Modify: `README.md:174-201`
- Modify: `docs/superpowers/specs/2026-08-17-devpi-guardian-f3-f4-design.md:108-125,345-370,375-400`
- Create: `news/3.feature`

- [ ] **Step 1: Add a failing documentation-contract test**

Append to `tests/test_package.py`:

```python
def test_readme_documents_verdict_baseline_tier_contract() -> None:
    readme = Path(__file__).parents[1].joinpath("README.md").read_text()
    f10_section = readme.split("F10 supplies the exact current DTO fields", 1)[1]
    f10_section = f10_section.split("Manual transitions", 1)[0]
    f10_section = " ".join(f10_section.split())

    for phrase in (
        'Literal["same_tag", "universal_wheel", "sdist"]',
        "baseline_sha256 and baseline_tier must both be set or both be None",
        "baseline_tier=None",
        "sdist comparisons have lower confidence",
    ):
        assert phrase in f10_section
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```bash
uv run pytest tests/test_package.py::test_readme_documents_verdict_baseline_tier_contract -q
```

Expected: FAIL because the README does not yet name the Literal or pairing rule.

- [ ] **Step 3: Update README and authoritative F3/F4 design**

Add `baseline_tier=None` after `baseline_sha256=None` in the README constructor and add this exact paragraph inside the F10 section:

```markdown
`baseline_tier` has type
`Literal["same_tag", "universal_wheel", "sdist"]`. `baseline_sha256 and
baseline_tier must both be set or both be None`; F6 passes `selection.tier`
unchanged through F10. In particular, `sdist comparisons have lower confidence`
and remain distinguishable in F4's immutable verdict history.
```

In `docs/superpowers/specs/2026-08-17-devpi-guardian-f3-f4-design.md`:

```markdown
# Add baseline_tier to the verdicts row in the table:
`baseline_sha256`, `baseline_tier`, `is_current`, `created_at`

# Replace the analyzer handoff bullet with:
- Artifact SHA-256, baseline SHA-256, baseline tier, analyzer version을 항상 함께 전달한다. baseline이 없으면 baseline SHA-256과 tier를 모두 `None`으로 전달한다.

# Replace the policy-engine bullet with:
- 정책 엔진은 `decision`, `score`, `policy_version`, `analyzer_version`, `baseline_sha256`, `baseline_tier`가 채워진 `VerdictInput`을 만든다. `baseline_tier`는 `same_tag`, `universal_wheel`, `sdist` 중 하나이며 baseline SHA-256과 함께 존재하거나 함께 `None`이어야 한다.

# Add to the F4 completion criteria:
- 새 자동 verdict는 F6의 baseline tier를 허용된 세 값 중 하나로 불변 보존하며, 기존 v1 baseline verdict의 알 수 없는 tier는 `NULL`로 보존한다.
```

Create `news/3.feature` containing:

```text
Preserve F6 baseline selection tiers in F10 VerdictInput values and immutable F4 verdict history.
```

- [ ] **Step 4: Verify the documentation test is GREEN**

Run:

```bash
uv run pytest tests/test_package.py::test_readme_documents_verdict_baseline_tier_contract -q
```

Expected: PASS.

- [ ] **Step 5: Run the complete acceptance matrix**

Run each command separately and inspect its complete output:

```bash
uv run pytest -v
uv run ruff format --check .
uv run ruff check .
uv run flake8 src tests
uv build
```

Expected: every command exits 0; pytest reports no failed tests, format/lint output is clean, and both wheel and source distribution are built.

- [ ] **Step 6: Inspect requirement coverage and the final diff**

Run:

```bash
rg -n "baseline_tier|BaselineTier" src tests README.md docs/superpowers/specs news
git diff --check HEAD~2
git status --short
```

Expected: the type, DTO, migration, store, invariant reader, tests, README, authoritative design, and news entry all appear; `git diff --check` is silent; only Task 3 documentation files remain uncommitted.

- [ ] **Step 7: Commit documentation and acceptance evidence**

```bash
git add README.md docs/superpowers/specs/2026-08-17-devpi-guardian-f3-f4-design.md news/3.feature tests/test_package.py
git commit -m "docs: publish baseline tier contract"
```

- [ ] **Step 8: Re-run final verification after the commit**

```bash
uv run pytest -q
uv run ruff format --check .
uv run ruff check .
uv run flake8 src tests
uv build
git status --short --branch
```

Expected: all quality commands exit 0 and the feature worktree is clean except that its branch is ahead of the remote.
