# PR #1 Safe Activation and F5 Quarantine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refuse first-time Guardian activation on a devpi that already contains Artifact candidates, bind successful activation to one devpi UUID, document the F5 quarantine byte path, and add a Python 3.11–3.14 CI gate while keeping PR #1 Draft.

**Architecture:** A third immutable SQLite migration stores a singleton activation marker. A storage-only activation service owns marker validation, a devpi adapter inventories existing release metadata and file entries in one KeyFS snapshot without network access, and the plugin completes both checks before mutating the Pyramid registry. F5 bytes remain outside SQLite and public `+f`/`+e` routes in the SHA-256 quarantine CAS contract approved by the hardening design.

**Tech Stack:** Python 3.11–3.14, devpi-server 6.20.3, stdlib sqlite3, Pyramid, pytest, pytest-devpi-server, Ruff, Flake8, uv, GitHub Actions

---

## Source requirements

Implement against both:

- `docs/superpowers/specs/2026-08-17-devpi-guardian-f3-f4-design.md`
- `docs/superpowers/specs/2026-08-24-pr1-safe-activation-f5-quarantine-design.md`

The hardening design takes precedence for activation support, F5 Artifact bytes, CI,
independent review, and Draft status. The baseline before this plan is commit `009d693`
with `881 passed` on Python 3.12.

## Locked file structure

```text
src/devpi_guardian/
├── activation.py                 # SQLite marker validation and first activation
├── legacy_inventory.py           # Read-only devpi KeyFS Artifact candidate scan
├── plugin.py                     # Startup ordering and sanitized fatal mapping
└── verdicts/
    ├── db.py                     # Ordered migration list includes v3
    └── sql/
        └── 003_guardian_activation.sql
tests/
├── activation/
│   ├── __init__.py
│   ├── test_activation.py
│   └── test_legacy_inventory.py
├── integration/
│   └── test_activation.py
├── test_package.py
└── verdicts/test_db.py
.github/workflows/ci.yml
docs/reviews/2026-08-24-pr1-hardening-review.md
news/4.feature
README.md
```

`activation.py` must not import devpi internals. `legacy_inventory.py` must not open the
Guardian SQLite database. `plugin.py` is the only module that composes those boundaries.

### Task 1: Add the immutable activation schema

**Files:**

- Create: `src/devpi_guardian/verdicts/sql/003_guardian_activation.sql`
- Modify: `src/devpi_guardian/verdicts/db.py`
- Modify: `tests/verdicts/test_db.py`
- Modify: `tests/test_package.py`

- [ ] **Step 1: Write failing v3 migration tests**

Update `test_migrate_creates_schema_and_is_idempotent` to require schema version `3`, the
`guardian_activation` table, and both immutability triggers. Extend
`_packaged_migration_sql` with the exact mapping below and add focused tests that insert
one valid row and prove UPDATE and DELETE fail with `sqlite3.IntegrityError`.

```python
names = {
    1: "001_initial.sql",
    2: "002_baseline_tier.sql",
    3: "003_guardian_activation.sql",
}
```

Add `test_migrate_v3_failure_rolls_back_and_retry_succeeds`, seeding a migrated v2 DB,
monkeypatching `_read_migration(3)` to append invalid SQL, and asserting versions remain
`[1, 2]` before a clean retry produces `[1, 2, 3]`. Update the plugin package test to
expect `MAX(version) == 3`.

- [ ] **Step 2: Run the focused tests and observe the expected failure**

Run:

```bash
uv run pytest tests/verdicts/test_db.py::test_migrate_creates_schema_and_is_idempotent tests/verdicts/test_db.py::test_guardian_activation_row_is_immutable tests/verdicts/test_db.py::test_migrate_v3_failure_rolls_back_and_retry_succeeds tests/test_package.py::test_pyramid_hook_migrates_and_registers_reader_and_tween -v
```

Expected: failures because migration 3 and its table do not exist and the current schema
version is 2.

- [ ] **Step 3: Add the packaged SQL migration**

Create `003_guardian_activation.sql` with exactly one possible row and immutable fields:

```sql
CREATE TABLE guardian_activation (
    singleton INTEGER NOT NULL PRIMARY KEY
        CHECK(typeof(singleton) = 'integer' AND singleton = 1),
    devpi_uuid TEXT NOT NULL
        CHECK(
            typeof(devpi_uuid) = 'text'
            AND length(devpi_uuid) BETWEEN 1 AND 4096
            AND length(trim(devpi_uuid)) > 0
            AND instr(devpi_uuid, char(0)) = 0
        ),
    activated_at TEXT NOT NULL,
    activation_version INTEGER NOT NULL
        CHECK(
            typeof(activation_version) = 'integer'
            AND activation_version = 1
        )
);

CREATE TRIGGER guardian_activation_immutable_update_guard
BEFORE UPDATE ON guardian_activation
BEGIN
    SELECT RAISE(ABORT, 'immutable guardian activation');
END;

CREATE TRIGGER guardian_activation_immutable_delete_guard
BEFORE DELETE ON guardian_activation
BEGIN
    SELECT RAISE(ABORT, 'immutable guardian activation');
END;
```

Append `"003_guardian_activation.sql"` to `_MIGRATION_FILES`. Do not modify migration 1
or 2.

- [ ] **Step 4: Run v3 migration tests and the complete DB test module**

Run:

```bash
uv run pytest tests/verdicts/test_db.py tests/test_package.py -v
```

Expected: all tests pass with schema version 3; existing v1/v2 recovery and catalog
fingerprint tests remain green.

- [ ] **Step 5: Commit Task 1**

```bash
git add src/devpi_guardian/verdicts/db.py src/devpi_guardian/verdicts/sql/003_guardian_activation.sql tests/verdicts/test_db.py tests/test_package.py
git commit -m "feat: add immutable Guardian activation schema"
```

### Task 2: Implement the storage-only activation service

**Files:**

- Create: `src/devpi_guardian/activation.py`
- Create: `tests/activation/__init__.py`
- Create: `tests/activation/test_activation.py`

- [ ] **Step 1: Write failing marker behavior tests**

Use a migrated temporary `ConnectionFactory`, a fixed UTC clock, and a recording
inventory callable. The first three tests establish the public behavior directly:

```python
NOW = datetime(2026, 8, 24, tzinfo=UTC)
DEVPI_UUID = "devpi-test-uuid"


def test_first_empty_activation_persists_marker_once(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    calls = 0

    def find_candidate() -> None:
        nonlocal calls
        calls += 1

    created = ensure_guardian_activation(
        factory,
        DEVPI_UUID,
        find_candidate,
        now=lambda: NOW,
    )

    with closing(factory.connect()) as connection:
        row = connection.execute(
            "SELECT singleton, devpi_uuid, activated_at, activation_version "
            "FROM guardian_activation"
        ).fetchone()
    assert created is True
    assert calls == 1
    assert tuple(row) == (1, DEVPI_UUID, NOW.isoformat(), 1)


def test_existing_marker_skips_inventory(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    first = ensure_guardian_activation(
        factory, DEVPI_UUID, lambda: None, now=lambda: NOW
    )

    def unexpected_inventory() -> None:
        raise AssertionError("inventory must not run on restart")

    second = ensure_guardian_activation(
        factory,
        DEVPI_UUID,
        unexpected_inventory,
        now=lambda: NOW + timedelta(days=1),
    )

    assert first is True
    assert second is False


def test_candidate_refuses_without_persisting_marker(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)

    with pytest.raises(GuardianActivationError) as error:
        ensure_guardian_activation(
            factory,
            DEVPI_UUID,
            lambda: "release_link",
            now=lambda: NOW,
        )

    assert error.value.category is ActivationFailureCategory.EXISTING_ARTIFACTS
    with closing(factory.connect()) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM guardian_activation"
        ).fetchone()[0]
    assert count == 0
```

Add separate focused tests named `test_marker_uuid_mismatch_fails_closed`,
`test_malformed_persisted_timestamp_fails_closed`,
`test_unknown_activation_version_fails_closed`,
`test_inventory_exception_is_sanitized`, `test_sqlite_error_is_sanitized`, and
`test_invalid_uuid_and_non_utc_clock_are_rejected_before_write`. Each test must assert
the exact category and that marker row count and callback call count remain unchanged.

Assertions must inspect `failure.category` only and prove exception text does not contain
the DB path, UUID, candidate data, or original exception message.

- [ ] **Step 2: Run the tests and observe the expected import failure**

Run:

```bash
uv run pytest tests/activation/test_activation.py -v
```

Expected: collection fails because `devpi_guardian.activation` does not exist.

- [ ] **Step 3: Implement the public activation contract**

Create the following API:

```python
from collections.abc import Callable
from datetime import datetime
from enum import StrEnum

from devpi_guardian.verdicts.db import ConnectionFactory

ACTIVATION_VERSION = 1


class ActivationFailureCategory(StrEnum):
    EXISTING_ARTIFACTS = "existing_artifacts"
    INVENTORY_UNAVAILABLE = "inventory_unavailable"
    MARKER_CORRUPT = "marker_corrupt"
    STORE_UNAVAILABLE = "store_unavailable"
    UUID_MISMATCH = "uuid_mismatch"


class GuardianActivationError(RuntimeError):
    def __init__(self, category: ActivationFailureCategory) -> None:
        self.category = category
        super().__init__(f"guardian activation failed: {category.value}")


CandidateFinder = Callable[[], str | None]


def ensure_guardian_activation(
    factory: ConnectionFactory,
    devpi_uuid: str,
    find_candidate: CandidateFinder,
    *,
    now: Callable[[], datetime],
) -> bool:
    """Return True only when this call creates the immutable marker."""
```

Implementation requirements:

1. Require an exact `str`, nonblank UTF-8 value, no NUL, and at most 4,096 characters.
2. Require `now()` to return an aware UTC `datetime` and serialize with `.isoformat()`.
3. Open one connection and `BEGIN IMMEDIATE` before reading the singleton row.
4. Fetch at most two rows and validate exact SQLite types, `singleton == 1`, a canonical
   UTC timestamp, and `activation_version == ACTIVATION_VERSION`.
5. An existing valid matching row returns `False` without calling `find_candidate`.
6. A missing row calls `find_candidate` exactly once. Any non-`None` exact string refuses
   with `EXISTING_ARTIFACTS`; an invalid return or raised exception maps to
   `INVENTORY_UNAVAILABLE`.
7. Insert `(1, devpi_uuid, activated_at, 1)` only after the finder returns `None`, commit,
   and return `True`.
8. Roll back on every pre-commit failure. Map `sqlite3.Error` and connection failures to
   `STORE_UNAVAILABLE` without including underlying text.
9. Always close the connection. A close error before commit is store unavailable; a close
   error after a successful commit does not claim the durable marker was rolled back.

Do not add an API that clears, replaces, or bypasses a marker.

- [ ] **Step 4: Run activation tests and relevant migration tests**

Run:

```bash
uv run pytest tests/activation/test_activation.py tests/verdicts/test_db.py -v
```

Expected: all pass.

- [ ] **Step 5: Commit Task 2**

```bash
git add src/devpi_guardian/activation.py tests/activation
git commit -m "feat: bind Guardian activation to devpi identity"
```

### Task 3: Inventory existing devpi Artifact candidates without network access

**Files:**

- Create: `src/devpi_guardian/legacy_inventory.py`
- Create: `tests/activation/test_legacy_inventory.py`

- [ ] **Step 1: Write failing inventory tests with a fake KeyFS snapshot**

The fake transaction must record its `at_serial`, requested key names, and reject any
model, stage, HTTP, mirror refresh, or filestore call. Use the fake to make direct
assertions like these:

```python
def test_empty_snapshot_has_no_candidate() -> None:
    xom = FakeXom(rows={})

    result = find_existing_artifact_candidate(xom)

    assert result is None
    assert xom.keyfs.read_transactions == 1


def test_private_release_elink_is_candidate() -> None:
    xom = FakeXom(
        rows={
            "PROJVERSION": [
                FakeRelpathInfo(
                    keyname="PROJVERSION",
                    relpath="root/dev/demo/1.0/.config",
                    value={
                        "+elinks": [
                            {
                                "rel": "releasefile",
                                "entrypath": "root/dev/+f/aa/bb/demo-1.0.whl",
                            }
                        ]
                    },
                )
            ]
        }
    )

    assert find_existing_artifact_candidate(xom) == "release_link"


def test_known_toxresult_entry_is_ignored() -> None:
    entrypath = "root/dev/+f/aa/bb/demo.whl.toxresult"
    xom = FakeXom(
        rows={
            "PROJVERSION": [
                FakeRelpathInfo(
                    keyname="PROJVERSION",
                    relpath="root/dev/demo/1.0/.config",
                    value={
                        "+elinks": [
                            {"rel": "toxresult", "entrypath": entrypath}
                        ]
                    },
                )
            ],
            "STAGEFILE": [
                FakeRelpathInfo(
                    keyname="STAGEFILE",
                    relpath=entrypath,
                    value={"project": "demo", "version": "1.0"},
                )
            ],
        }
    )

    assert find_existing_artifact_candidate(xom) is None
```

Add focused cases for a persisted simple release link, cached mirror file, tombstones,
doczip, an unclassified live file, malformed simple/version data, and the single-snapshot
no-network constraint. The malformed cases return the exact bounded value
`"unclassified"` rather than raising data-bearing exceptions.

Use representative persisted shapes:

```python
private_version = {
    "+elinks": [
        {
            "rel": "releasefile",
            "entrypath": "root/dev/+f/aa/bb/demo-1.0.whl",
        }
    ]
}
mirror_simple = {
    "links": [("demo-1.0.whl", "root/pypi/+e/demo-1.0.whl")],
}
```

- [ ] **Step 2: Run the inventory tests and observe the expected import failure**

Run:

```bash
uv run pytest tests/activation/test_legacy_inventory.py -v
```

Expected: collection fails because `devpi_guardian.legacy_inventory` does not exist.

- [ ] **Step 3: Implement the bounded candidate scanner**

Create this API:

```python
from enum import StrEnum


class ExistingArtifactCandidate(StrEnum):
    FILE_ENTRY = "file_entry"
    RELEASE_LINK = "release_link"
    UNCLASSIFIED = "unclassified"


def find_existing_artifact_candidate(xom: object) -> str | None:
    """Return a bounded category for the first live Artifact candidate."""
```

Within exactly one `xom.keyfs.read_transaction()`:

1. Obtain typed keys by `keyfs.get_key` for `PROJSIMPLELINKS`, `PROJVERSION`,
   `STAGEFILE`, and `PYPIFILE_NOMD5`.
2. Read each set through `tx.iter_relpaths_at(keys, tx.at_serial)`; do not call xom.model,
   stage methods, filestore methods, or URLs.
3. Treat nonempty well-formed `PROJSIMPLELINKS["links"]` and any
   `PROJVERSION["+elinks"]` item whose exact `rel` is `"releasefile"` as
   `RELEASE_LINK`.
4. Collect exact string `entrypath` values for `doczip` and `toxresult` links. A live
   `STAGEFILE` at one of those paths is known non-Artifact and may be ignored.
5. Treat every other live `STAGEFILE` or `PYPIFILE_NOMD5` as `FILE_ENTRY`.
6. Ignore only explicit `value is None` tombstones and well-formed empty collections.
7. Return `UNCLASSIFIED` for unexpected types, missing required fields, unsafe paths,
   duplicate contradictory relation data, or iterator/key access failure. Never include
   relpath, filename, digest, project, or URL in the return value or exception text.
8. Stop as soon as a release link is known; otherwise finish relation classification
   before deciding whether file entries are known non-Artifact.

Return `ExistingArtifactCandidate.<member>.value`, not the enum object, so the activation
boundary receives an exact built-in `str`.

- [ ] **Step 4: Run focused inventory and resolver tests**

Run:

```bash
uv run pytest tests/activation/test_legacy_inventory.py tests/enforcement/test_resolve.py -v
```

Expected: all pass and existing resolver behavior is unchanged.

- [ ] **Step 5: Commit Task 3**

```bash
git add src/devpi_guardian/legacy_inventory.py tests/activation/test_legacy_inventory.py
git commit -m "feat: detect legacy devpi artifacts at activation"
```

### Task 4: Wire the startup gate before all Pyramid side effects

**Files:**

- Modify: `src/devpi_guardian/plugin.py`
- Modify: `tests/test_package.py`
- Create: `tests/integration/test_activation.py`
- Modify: `tests/integration/conftest.py`

- [ ] **Step 1: Write failing plugin ordering tests**

Extend `FakePyramidConfig` with an injected fake XOM under registry key `"xom"` and give
the fake config `nodeinfo={"uuid": "devpi-test-uuid"}`. Monkeypatch migration,
activation, inventory, reader, metrics, and `add_tween` with one event list and assert the
exact order:

```python
assert events == [
    "migrate",
    "activation",
    "inventory",
    "reader",
    "metrics",
    "registry-reader",
    "registry-metrics",
    "tween",
]
```

Add separate tests proving migration failure, inventory refusal, UUID mismatch, and
activation store failure leave the registry containing only its original `xom` and add no
tween. Assert the raised startup text contains only the bounded activation category and
does not contain a DB path, UUID, entrypath, filename, or nested exception message.

- [ ] **Step 2: Write failing real-process activation tests**

Add a test lifecycle helper that can stop a server, preserve devpi files, remove only the
temporary-test Guardian DB and WAL/SHM files, and start while expecting readiness failure.
The integration test must:

1. Start empty devpi and assert marker `(devpi_uuid, activation_version=1)` exists.
2. Restart with the same DB and prove the marker is unchanged.
3. Upload a private release, stop the server, remove the test Guardian DB, and assert the
   next startup fails with `existing_artifacts` before readiness.
4. Repeat candidate detection through unit inventory fixtures for cached mirror and
   persisted mirror link; the subprocess test need not contact public PyPI.
5. Assert the startup log omits filename, SHA-256, absolute DB path, and URL secrets.

- [ ] **Step 3: Run the focused tests and observe failure**

Run:

```bash
uv run pytest tests/test_package.py tests/integration/test_activation.py -v
```

Expected: failures because the plugin does not invoke activation or inventory.

- [ ] **Step 4: Implement startup composition**

In `devpiserver_pyramid_configure`, preserve deterministic DB path selection, then use
this order:

```python
factory = ConnectionFactory(db_path)
migrate(factory)
xom = pyramid_config.registry["xom"]
devpi_uuid = config.nodeinfo["uuid"]
try:
    ensure_guardian_activation(
        factory,
        devpi_uuid,
        lambda: find_existing_artifact_candidate(xom),
        now=lambda: datetime.now(UTC),
    )
except GuardianActivationError as exc:
    raise Fatal(str(exc)) from None
reader = SQLiteVerdictReader(factory)
block_metrics = InMemoryBlockMetricRecorder()
pyramid_config.registry[VERDICT_READER_REGISTRY_KEY] = reader
pyramid_config.registry[BLOCK_METRIC_REGISTRY_KEY] = block_metrics
pyramid_config.add_tween(
    "devpi_guardian.enforcement.tween.guardian_enforcement_tween_factory",
    under="devpi_server.views.tween_keyfs_transaction",
)
```

Import `Fatal` from `devpi_server.main`. Do not catch or downgrade migration failures. Do
not provide a command-line bypass. Activation and inventory must finish before the first
Guardian registry assignment.

- [ ] **Step 5: Run plugin, integration, and enforcement tests**

Run:

```bash
uv run pytest tests/test_package.py tests/integration/test_activation.py tests/integration/test_direct_download.py tests/integration/test_pytest_devpi_server.py tests/enforcement -v
```

Expected: all pass. Existing direct `+f`/`+e`, mirror, pip/uv, restart, and non-release
pass-through coverage remains green.

- [ ] **Step 6: Commit Task 4**

```bash
git add src/devpi_guardian/plugin.py tests/test_package.py tests/integration/conftest.py tests/integration/test_activation.py
git commit -m "feat: refuse unsafe Guardian activation"
```

### Task 5: Add CI and publish the support/F5 operating contract

**Files:**

- Create: `.github/workflows/ci.yml`
- Modify: `tests/test_package.py`
- Modify: `README.md`
- Create: `news/4.feature`

- [ ] **Step 1: Write failing workflow and README contract tests**

Add tests that read files as text and assert all locked requirements. The workflow test
must use concrete positive and negative assertions:

```python
def test_ci_covers_supported_python_and_quality_gates() -> None:
    workflow = Path(__file__).parents[1].joinpath(
        ".github/workflows/ci.yml"
    ).read_text(encoding="utf-8")

    for version in ('"3.11"', '"3.12"', '"3.13"', '"3.14"'):
        assert version in workflow
    for required in (
        "contents: read",
        "cancel-in-progress: true",
        "uv sync --locked --extra test",
        "uv run pytest -v",
        "uv run ruff format --check .",
        "uv run ruff check .",
        "uv run flake8 src tests",
        "uv run python -m build",
    ):
        assert required in workflow
    for forbidden in (
        "pull-requests: write",
        "contents: write",
        "continue-on-error",
        "-m 'not integration'",
        '-m "not integration"',
    ):
        assert forbidden not in workflow
```

Add `test_readme_documents_new_install_activation_boundary` and
`test_readme_documents_f5_quarantine_contract` using the same section-isolation pattern as
the existing README contract tests, then assert each exact phrase listed below.

The CI test must require Python `3.11`, `3.12`, `3.13`, `3.14`, `contents: read`,
`cancel-in-progress: true`, `uv sync --locked --extra test`, full `uv run pytest -v`, all
three lint/format commands, and `uv run python -m build`. It must reject
`pull-requests: write`, `contents: write`, `continue-on-error`, and pytest marker
exclusions.

The README tests must require the phrases `new Guardian deployments only`,
`existing_artifacts`, `no compatibility bypass`, `GUARDIAN_QUARANTINE_DIR`, the exact
`objects/sha256/<first-2>/<next-2>/<sha256>` layout, publish-before-discover ordering,
same-open-file digest verification, and prohibition on public `+f`/`+e` worker bypass.

- [ ] **Step 2: Run the contract tests and observe failure**

Run:

```bash
uv run pytest tests/test_package.py -v
```

Expected: the new tests fail because the workflow and README sections do not exist.

- [ ] **Step 3: Create the least-privilege CI workflow**

Use full commit SHA pins verified from official repositories on 2026-08-24:

```yaml
name: CI

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  tests:
    name: tests (Python ${{ matrix.python-version }})
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.11", "3.12", "3.13", "3.14"]
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: astral-sh/setup-uv@20cfd1bf945f4377ade1205e4dbc17946fc9a30d # v10.0.1
        with:
          python-version: ${{ matrix.python-version }}
          enable-cache: true
      - run: uv sync --locked --extra test
      - run: uv run pytest -v

  quality:
    name: quality (Python 3.11)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: astral-sh/setup-uv@20cfd1bf945f4377ade1205e4dbc17946fc9a30d # v10.0.1
        with:
          python-version: "3.11"
          enable-cache: true
      - run: uv sync --locked --extra test
      - run: uv run ruff format --check .
      - run: uv run ruff check .
      - run: uv run flake8 src tests
      - run: uv run python -m build
```

- [ ] **Step 4: Update README and release note**

Add an installation support section that defines first activation, marker/UUID behavior,
legacy refusal, DB loss refusal, offline backfill deferral, and absence of a compatibility
bypass. Add an F5 quarantine section with the exact absolute-path configuration, digest
layout, atomic publish-before-discover sequence, safe open/rehash sequence, error mapping,
and explicit statement that `origin_url` and public `+f`/`+e` are not byte bypasses.

Create `news/4.feature`:

```text
Refuse first-time Guardian activation on devpi instances with existing Artifact candidates, document the SHA-256 F5 quarantine path, and add Python 3.11–3.14 CI.
```

- [ ] **Step 5: Run documentation/CI tests and quality checks**

Run:

```bash
uv run pytest tests/test_package.py -v
uv run ruff format --check .
uv run ruff check .
uv run flake8 src tests
uv run python -m build
```

Expected: every command exits 0.

- [ ] **Step 6: Commit Task 5**

```bash
git add .github/workflows/ci.yml README.md news/4.feature tests/test_package.py
git commit -m "ci: verify Guardian support and quality matrix"
```

### Task 6: Full verification, independent review, and Draft handoff

**Files:**

- Create: `docs/reviews/2026-08-24-pr1-hardening-review.md`
- Modify only if findings require fixes: files from Tasks 1–5

- [ ] **Step 1: Run the complete local acceptance suite**

Run fresh commands:

```bash
uv run pytest -v
uv run ruff format --check .
uv run ruff check .
uv run flake8 src tests
uv run python -m build
```

Record exit status, exact test count, Python version, and reviewed implementation SHA.

- [ ] **Step 2: Run independent specification-compliance review**

Dispatch a fresh `gpt-5.6-sol` reviewer with only the two approved design documents, this
plan, base SHA `009d693`, implementation SHA, and diff. Require findings ordered by
Critical/Important/Minor with exact file/line evidence. Fix every Critical or Important
finding using focused red-green tests and repeat specification review until approved.

- [ ] **Step 3: Run independent security/code-quality review**

Only after specification approval, dispatch a different fresh `gpt-5.6-sol` reviewer.
Require review of SQLite transaction/error behavior, KeyFS snapshot classification,
startup side-effect ordering, sanitization, CI permissions/SHA pins, regression risk, and
test adequacy. Fix every Critical or Important finding and repeat until approved.

- [ ] **Step 4: Write and commit the review artifact**

The dated artifact must contain the title `PR #1 Hardening Independent Review`, the actual
40-character implementation commit SHA reviewed before the artifact commit, both distinct
reviewer identities, both final results, zero open Critical/Important counts, the literal
commands with their actual exit status/test count, and `Draft status: retained`. List every
resolved finding and its fix commit; write `None` when there were no findings.
Commit:

```bash
git add docs/reviews/2026-08-24-pr1-hardening-review.md
git commit -m "docs: record independent PR 1 hardening review"
```

- [ ] **Step 5: Push, observe CI, and update the existing Draft PR**

Push the feature branch, wait for all matrix and quality checks, and update PR #1 with the
support boundary, F5 quarantine path, verification count, review result, and check names.
Do not run `gh pr ready`; verify `isDraft` remains `true` after the update.

- [ ] **Step 6: Controller acceptance**

The controller independently inspects `git diff 009d693...HEAD`, reruns the complete local
acceptance suite, reads GitHub check conclusions, and confirms each completion criterion
in the hardening design before reporting completion.
