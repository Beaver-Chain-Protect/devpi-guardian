# Allowed Release Query Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a public project-based query that returns every currently effective `ALLOW` release for F6 without requiring a known SHA-256.

**Architecture:** Extend the existing `VerdictReader` with an immutable `AllowedRelease` result. `SQLiteVerdictReader` reads project mappings and their effective decisions in one read transaction and one evaluation timestamp, reusing `validate_persisted_state()` rather than duplicating precedence SQL. The existing origin URL sanitizer becomes a shared internal helper so stored mappings can be validated without changing the write contract.

**Tech Stack:** Python 3.11+, SQLite, devpi-common PEP 503 normalization, pytest, Ruff, Flake8.

---

## File structure

- Create `src/devpi_guardian/verdicts/releases.py`: shared project/origin validation used by writer and reader.
- Modify `src/devpi_guardian/verdicts/models.py`: add immutable `AllowedRelease`.
- Modify `src/devpi_guardian/verdicts/interfaces.py`: expose the project query on `VerdictReader`.
- Modify `src/devpi_guardian/verdicts/invariants.py`: validate persisted release-mapping rows.
- Modify `src/devpi_guardian/verdicts/reader.py`: reuse one connection/snapshot for mapping and effective-decision reads.
- Modify `src/devpi_guardian/verdicts/store.py`: import the shared origin sanitizer with no behavior change.
- Modify `src/devpi_guardian/verdicts/__init__.py`: export the public result model.
- Modify `tests/verdicts/test_reader.py`: cover result semantics, corruption, chunking, and errors.
- Modify `tests/verdicts/test_store_claims.py`: prove the sanitizer extraction preserves writer behavior.
- Modify `README.md`: document the F6 handoff and origin URL contract.
- Create `news/2.feature`: record the public query addition.

### Task 1: Public model, shared validation, and snapshot query

**Files:**
- Create: `src/devpi_guardian/verdicts/releases.py`
- Modify: `src/devpi_guardian/verdicts/models.py`
- Modify: `src/devpi_guardian/verdicts/interfaces.py`
- Modify: `src/devpi_guardian/verdicts/invariants.py`
- Modify: `src/devpi_guardian/verdicts/reader.py`
- Modify: `src/devpi_guardian/verdicts/store.py`
- Modify: `src/devpi_guardian/verdicts/__init__.py`
- Test: `tests/verdicts/test_reader.py`
- Test: `tests/verdicts/test_store_claims.py`

- [ ] **Step 1: Add focused failing tests for the public contract**

Add a release seed helper that inserts the immutable mapping after `seed_artifact()`:

```python
def seed_release(
    factory: ConnectionFactory,
    sha256: str,
    *,
    stage: str = "root/dev",
    project: str = "demo-package",
    version: str = "1.0.0",
    filename: str = "demo_package-1.0.0-py3-none-any.whl",
    origin_url: str | None = None,
) -> None:
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO release_mappings(
                stage, project, version, filename, sha256,
                origin_url, discovered_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stage,
                project,
                version,
                filename,
                sha256,
                origin_url
                or f"https://devpi.example/{stage}/+f/aa/{filename}",
                NOW.isoformat(),
            ),
        )
```

Add tests that assert:

```python
assert reader.list_allowed_releases("Demo_Package") == (
    AllowedRelease(
        stage="root/dev",
        project="demo-package",
        version="1.0.0",
        filename="demo_package-1.0.0-py3-none-any.whl",
        sha256=SHA_ALLOW,
        origin_url=(
            "https://devpi.example/root/dev/+f/aa/"
            "demo_package-1.0.0-py3-none-any.whl"
        ),
    ),
)
```

Cover all of these cases explicitly:

1. PEP 503 input normalization and immutable tuple/result model.
2. All stages are returned, including multiple mappings for one SHA-256.
3. Ordering is exactly `(stage, version, filename, sha256, origin_url)`.
4. Automated ALLOW and valid manual ALLOW are included.
5. REVIEW, DENY, ERROR, DISCOVERED, SCANNING, valid manual DENY, and an expired manual ALLOW over REVIEW are excluded.
6. An expired manual DENY falls back to automated ALLOW and is included.
7. Missing project returns `()`.
8. `None`, bytes, subclasses of `str`, blank input, and a name that normalizes to empty raise `ValueError` before `connect()`.
9. A malformed selected mapping field, noncanonical stored origin URL, malformed timestamp, missing artifact, duplicate current verdict, and duplicate current override each raise `StoreUnavailable` without partial results. Unrelated project rows, including noncanonical project spellings, are outside this exact-key lookup; whole-database integrity auditing is out of scope.
10. At least 401 distinct mapped SHA-256 values cross the existing chunk boundary and return correctly.
11. The clock and factory are each evaluated once per call.

- [ ] **Step 2: Run the focused tests and capture RED**

Run:

```bash
uv run pytest tests/verdicts/test_reader.py tests/verdicts/test_store_claims.py -q
```

Expected: new tests fail because `AllowedRelease` and
`SQLiteVerdictReader.list_allowed_releases()` do not exist. Existing tests remain green.

- [ ] **Step 3: Add the immutable public result and protocol method**

Add to `models.py`:

```python
@dataclass(frozen=True, slots=True)
class AllowedRelease:
    stage: str
    project: str
    version: str
    filename: str
    sha256: str
    origin_url: str
```

Add to `VerdictReader`:

```python
def list_allowed_releases(
    self,
    project: str,
) -> tuple[AllowedRelease, ...]: ...
```

Export `AllowedRelease` from `devpi_guardian.verdicts`.

- [ ] **Step 4: Extract shared release validation without changing writer behavior**

Move the existing `_sanitize_origin_url()` implementation from `store.py` to
`releases.py` as `sanitize_origin_url()`. Preserve the exact accepted inputs and exact
sanitized output. `store.py` must continue calling it after its existing strict
nonblank-string checks.

Also add caller-only normalization:

```python
def normalize_requested_project(value: object) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError("project must be a nonblank string")
    normalized = normalize_name(value)
    if not normalized:
        raise ValueError("project must have a normalized name")
    return normalized
```

Do not add a scheme restriction; F4's existing write contract accepts any valid
absolute URL. The F5/F6 integration contract requires canonical devpi HTTP(S), which
is documented separately.

- [ ] **Step 5: Validate persisted release mappings**

In `invariants.py`, add a helper that consumes one mapping row and returns
`AllowedRelease`. Reuse `_sqlite_id()`, `_canonical_sha256()`, and
`_stored_timestamp()`. For `stage`, `project`, `version`, and `filename`, require the
same exact built-in, nonblank string shape accepted by the current writer; do not add a
new length or scheme restriction. Require all of the following:

```python
project_raw = _field(row, "project")
if type(project_raw) is not str or not project_raw.strip():
    raise PersistedStateCorruption("invalid persisted release project")
project = project_raw
if not project or normalize_name(project) != project:
    raise PersistedStateCorruption("invalid persisted release project")

origin_url = _field(row, "origin_url")
if type(origin_url) is not str or not origin_url.strip():
    raise PersistedStateCorruption("invalid persisted release origin_url")
try:
    canonical_origin = sanitize_origin_url(origin_url)
except ValueError as exc:
    raise PersistedStateCorruption(
        "invalid persisted release origin_url",
    ) from exc
if canonical_origin != origin_url:
    raise PersistedStateCorruption(
        "noncanonical persisted release origin_url",
    )
```

Validate `id`, `stage`, `version`, `filename`, `sha256`, and `discovered_at` as well.
Return the six-field public DTO; do not expose the database row ID or timestamp.

- [ ] **Step 6: Refactor reader state evaluation for connection reuse**

Extract the chunked artifact/verdict/override work currently inside
`get_effective_decisions()` into a private method that accepts an already-open
connection, the canonical distinct SHA list, and one `as_of` value:

```python
def _read_effective_decisions(
    self,
    connection: sqlite3.Connection,
    requested: list[str],
    as_of: datetime,
) -> dict[str, EnforcementDecision]:
    ...
```

Keep the existing `ROW_NUMBER() ... current_rank <= 2` duplicate bound and
`validate_persisted_state()` calls unchanged. `get_effective_decisions()` should still
open exactly one connection, start `BEGIN`, call this helper, commit, and retain its
existing public behavior.

- [ ] **Step 7: Implement the project query in one snapshot**

Implement `list_allowed_releases()` with this shape:

```python
canonical_project = normalize_requested_project(project)
as_of = require_utc(self._now(), "now")
with closing(self._factory.connect()) as connection:
    connection.execute("BEGIN")
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
```

Read the exact normalized project mapping rows in `_CHUNK_SIZE` batches using
`fetchmany()`. Validate every selected row, call `_read_effective_decisions()` for
the distinct SHA-256 values in that batch, and
append only mappings whose returned decision has `allowed is True`. Sort once using
the exact public ordering before returning a tuple. Keep all reads inside the same
`BEGIN` transaction and use the same `as_of` value.

Map `sqlite3.Error`, `TypeError`, `ValueError`, and `OverflowError` to
`StoreUnavailable(str(self._factory.path))` exactly as the existing reader does. Caller
project validation must happen outside that mapping so invalid input remains
`ValueError`.

- [ ] **Step 8: Run focused GREEN and regression tests**

Run:

```bash
uv run pytest tests/verdicts/test_reader.py tests/verdicts/test_store_claims.py -q
uv run pytest tests/verdicts -q
uv run ruff format --check src tests
uv run ruff check src tests
uv run flake8 src tests
```

Expected: all commands pass. Confirm the store sanitization tests prove no writer
behavior changed.

- [ ] **Step 9: Commit Task 1**

```bash
git add \
  src/devpi_guardian/verdicts/releases.py \
  src/devpi_guardian/verdicts/models.py \
  src/devpi_guardian/verdicts/interfaces.py \
  src/devpi_guardian/verdicts/invariants.py \
  src/devpi_guardian/verdicts/reader.py \
  src/devpi_guardian/verdicts/store.py \
  src/devpi_guardian/verdicts/__init__.py \
  tests/verdicts/test_reader.py \
  tests/verdicts/test_store_claims.py
git commit -m "feat: query allowed releases by project"
```

### Task 2: F6 handoff documentation and release note

**Files:**
- Modify: `README.md`
- Create: `news/2.feature`
- Test: `tests/test_package.py`

- [ ] **Step 1: Add a documentation assertion that fails first**

Extend `tests/test_package.py` to assert that the installed README contains the public
F6 method and origin contract markers:

```python
readme = Path("README.md").read_text(encoding="utf-8")
assert "list_allowed_releases" in readme
assert "origin_url" in readme
assert "canonical devpi" in readme
```

- [ ] **Step 2: Run the focused documentation test and capture RED**

Run:

```bash
uv run pytest tests/test_package.py -q
```

Expected: the new README assertions fail.

- [ ] **Step 3: Document the F6 connection boundary**

Add a README subsection after the existing `VerdictReader` example:

```python
from devpi_guardian.verdicts import AllowedRelease

releases: tuple[AllowedRelease, ...] = reader.list_allowed_releases(
    "Demo_Package",
)
for release in releases:
    print(
        release.stage,
        release.version,
        release.filename,
        release.sha256,
        release.origin_url,
    )
```

State explicitly that the query searches every stage, uses current effective ALLOW
semantics including manual overrides, and returns deterministic immutable results.
Explain that `origin_url` is not a filesystem path: F5 must record the canonical devpi
HTTP(S) `+f`/`+e` URL, F4 strips userinfo/query/fragment, and F6 downloads it through
devpi enforcement rather than using it as a trust bypass.

Add `news/2.feature`:

```text
Expose effective ALLOW releases by normalized project name for trusted-baseline consumers.
```

- [ ] **Step 4: Run documentation and full quality gates**

Run:

```bash
uv run pytest tests/test_package.py -q
uv run pytest -q
uv run ruff format --check .
uv run ruff check .
uv run flake8 src tests
uv lock --check
uv build
git diff --check
```

Expected: every command passes; only known third-party deprecation warnings may remain.

- [ ] **Step 5: Commit Task 2**

```bash
git add README.md news/2.feature tests/test_package.py
git commit -m "docs: explain F6 allowed release lookup"
```

### Task 3: Review, integration verification, and PR update

**Files:**
- Review: all files changed since `0632e18`
- Update: existing draft PR for `feature/f3-f4-enforcement-store`

- [ ] **Step 1: Run Sol specification review**

Check every requirement in
`docs/superpowers/specs/2026-08-18-allowed-release-query-design.md` against the diff.
Fix every missing or extra behavior, rerun focused tests, and repeat until approved.

- [ ] **Step 2: Run independent Sol quality review**

Review input validation, SQLite snapshot behavior, corruption handling, bounded reads,
manual override expiry, URL sanitization compatibility, public typing, and test quality.
Fix every Critical or Important finding and repeat the review until approved.

- [ ] **Step 3: Controller verification**

Independently run:

```bash
uv run pytest tests/verdicts/test_reader.py tests/verdicts/test_store_claims.py -q
uv run pytest -q
uv run ruff format --check .
uv run ruff check .
uv run flake8 src tests
uv lock --check
uv build
git diff --check origin/main...HEAD
git status --short
```

Expected: tests, lint, lock, build, and diff checks pass; worktree is clean.

- [ ] **Step 4: Push and update the existing PR**

Push `feature/f3-f4-enforcement-store`, update PR #1's summary and test evidence with the
F6 query, and confirm the PR URL remains:

```text
https://github.com/Beaver-Context-Protocol/devpi-guardian/pull/1
```
