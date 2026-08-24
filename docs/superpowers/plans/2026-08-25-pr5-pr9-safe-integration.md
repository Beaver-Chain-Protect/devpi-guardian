# PR #5/#9 Safe Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the completed F5/F6/F7/F10/F11/F12 behavior from PR #5 and PR #9 onto the PR #1 main line without weakening activation, enforcement, history, fencing, or quarantine security.

**Architecture:** Keep `3d21039` and its activation/F3/F4 implementation as the base, then add the missing packages in dependency order. Adapt only the verdict-store extension points and plugin composition; preserve the newer analyzer, activation, inventory, CI, and enforcement implementations already on main. The quarantine boundary owns a dedicated descriptor-relative CAS and hands verified descriptor bytes—not a mutable public or local path—to analysis.

**Tech Stack:** Python 3.11+, devpi-server 6.20.3 hooks, Pyramid, SQLite/WAL, `os.open(..., dir_fd=...)`, pytest, uv, Ruff, flake8, GitHub Actions.

---

## Source and execution rules

- Integration base: `3d210395dc806cc0420bda97c6e6e8a8dc1a1883`.
- PR #5 source: `22bc029e584af43e6c79b72a3d6fcef35f49f05f`.
- PR #9 source: `52593ae444f416625a0e96f0a4874bc30987ce8d`.
- Work only in `.worktrees/pr5-pr9-integration` on `integration/pr5-pr9`.
- Use `apply_patch` for every file edit. Do not checkout paths or apply the PR tree wholesale.
- For each behavior, port or write the focused test first, run it and record the expected failure,
  then port/adapt the minimum production code and rerun the focused suite.
- Never replace these main files with their PR #9 versions:
  `.github/workflows/ci.yml`, `AGENTS.md`, `src/devpi_guardian/activation.py`,
  `src/devpi_guardian/legacy_inventory.py`, or any existing analyzer module.
- Do not delete or weaken activation and integration tests from main.
- After every numbered task: commit, run the focused tests again, then complete separate
  specification-compliance and code-quality reviews before starting the next task.

## File responsibility map

- `verdicts/db.py` and `verdicts/sql/*.sql`: ordered schema v1-v6 and catalog validation.
- `verdicts/models.py`, `interfaces.py`, `reader.py`, `store.py`: shared public F4/F6/F11
  data contracts and SQLite behavior.
- `baseline/`: F6 selection/release lookup and F7 comparison/evidence.
- `worker/discovery.py`: durable discovery queue only.
- `worker/quarantine.py`: descriptor-relative CAS, secure publish and verified open.
- `worker/models.py`: worker boundary models, including owned verified streams.
- `worker/preparer.py`, `devpi_source.py`, `discovery_consumer.py`: bytes acquisition and
  CAS-before-F4 handoff.
- `worker/analysis.py`, `pipeline.py`, `runtime.py`: analyzer composition, fenced cycle and
  devpi thread lifecycle.
- `audit/` and `policy/`: F12 append-only chain and F10 deterministic policy.
- `admin/`: F11 service, HTTP views, CLI/client and production providers.
- `plugin.py`: configuration validation and activation-first composition only.

---

### Task 1: Add schema v6 and shared verdict APIs

**Files:**
- Create: `src/devpi_guardian/verdicts/sql/004_artifact_cooldown.sql`
- Create: `src/devpi_guardian/verdicts/sql/005_audit_events.sql`
- Create: `src/devpi_guardian/verdicts/sql/006_baseline_overrides.sql`
- Modify: `src/devpi_guardian/verdicts/db.py`
- Modify: `src/devpi_guardian/verdicts/models.py`
- Modify: `src/devpi_guardian/verdicts/interfaces.py`
- Modify: `src/devpi_guardian/verdicts/reader.py`
- Modify: `src/devpi_guardian/verdicts/store.py`
- Modify: `src/devpi_guardian/verdicts/__init__.py`
- Test: `tests/verdicts/test_db.py`
- Create: `tests/verdicts/test_cooldown.py`
- Modify: `tests/verdicts/test_reader.py`
- Modify: `tests/verdicts/test_store_verdicts.py`
- Modify: `tests/test_package.py`

- [ ] **Step 1: Add failing migration-order and upgrade tests**

Add assertions equivalent to the following, while retaining every activation migration test:

```python
def test_migrate_activation_database_to_schema_v6(tmp_path):
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    with factory.connect() as connection:
        assert [
            row[0]
            for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")
        ] == [1, 2, 3, 4, 5, 6]
        names = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert {"guardian_activation", "audit_events", "baseline_overrides"} <= names
```

Also assert the wheel/sdist contains exactly migration files 001 through 006.

- [ ] **Step 2: Verify the schema tests fail for the missing v4-v6 files**

Run:

```bash
uv run pytest tests/verdicts/test_db.py tests/test_package.py -q
```

Expected: FAIL because the current supported schema stops at version 3 and the new tables are
absent. Activation tests must remain green outside those expected failures.

- [ ] **Step 3: Add and register the renumbered migrations**

Adapt PR #9 SQL without changing its schema, but name the files 004/005/006. Set the ordered tuple
exactly to:

```python
_MIGRATION_FILES = (
    "001_initial.sql",
    "002_baseline_tier.sql",
    "003_guardian_activation.sql",
    "004_artifact_cooldown.sql",
    "005_audit_events.sql",
    "006_baseline_overrides.sql",
)
```

Use the current main migration catalog validation unchanged.

- [ ] **Step 4: Run migration and activation regression tests**

Run:

```bash
uv run pytest tests/verdicts/test_db.py tests/activation tests/integration/test_activation.py -q
```

Expected: PASS, including idempotent v6 migration and the existing v3 activation behavior.

- [ ] **Step 5: Add failing public-API, cooldown and admin-reader tests**

Port the PR #9 tests for `ReleaseArtifact`, quarantine pagination/details, reader health,
release-artifact lookup, `set_baseline_eligibility`, and automated-ALLOW cooldown. Preserve main's
fail-closed reader corruption cases. A focused cooldown assertion is:

```python
decision = reader.get_effective_decision(DIGEST)
assert decision.allowed is False
assert decision.reason == "automated_allow_cooldown"
```

- [ ] **Step 6: Verify the new API tests fail for missing models and methods**

Run:

```bash
uv run pytest tests/verdicts/test_cooldown.py tests/verdicts/test_reader.py \
  tests/verdicts/test_store_verdicts.py -q
```

Expected: collection or assertion failures naming the missing PR #9 public API, not database
corruption or activation failures.

- [ ] **Step 7: Merge the PR #9 verdict extensions into the main implementations**

Add `ReleaseArtifact`, `ArtifactAdminSummary`, `EvidenceRecord`, `ArtifactAdminDetails`, and
`QuarantinePage`; extend `VerdictInput` with validated `cooldown_until`; add the reader methods in
the public `VerdictReader` protocol; add `set_baseline_eligibility()` to `ArtifactStore` and
`SQLiteArtifactStore`. Preserve these main invariants:

```python
class SQLiteArtifactStore:
    def __init__(self, factory: ConnectionFactory, audit_writer: AuditWriter) -> None:
        self._factory = factory
        self._audit_writer = audit_writer

    # All verdict/evidence/audit transitions stay in one _write() transaction.
```

Do not copy PR #9 files wholesale: retain main's claim fencing, immutable history, catalog checks,
and fail-closed `SQLiteVerdictReader` validation while adding the new query surfaces.

- [ ] **Step 8: Run all verdict, activation and enforcement tests**

Run:

```bash
uv run pytest tests/verdicts tests/activation tests/enforcement -q
```

Expected: PASS.

- [ ] **Step 9: Commit the schema/API foundation**

```bash
git add src/devpi_guardian/verdicts tests/verdicts tests/test_package.py
git commit -m "feat: extend Guardian schema and verdict APIs"
```

---

### Task 2: Port F6 baseline selection and F7 release diff

**Files:**
- Create: `src/devpi_guardian/baseline/__init__.py`
- Create: `src/devpi_guardian/baseline/artifact_source.py`
- Create: `src/devpi_guardian/baseline/diff.py`
- Create: `src/devpi_guardian/baseline/release_lookup.py`
- Create: `src/devpi_guardian/baseline/selection.py`
- Create: `tests/baseline/__init__.py`
- Create: `tests/baseline/artifacts.py`
- Create: `tests/baseline/fakes.py`
- Create: `tests/baseline/store_seed.py`
- Create: `tests/baseline/test_artifact_source.py`
- Create: `tests/baseline/test_diff.py`
- Create: `tests/baseline/test_release_lookup.py`
- Create: `tests/baseline/test_selection.py`
- Create: `tests/baseline/test_wiring.py`
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Modify: `tests/test_package.py`

- [ ] **Step 1: Port the PR #9 baseline tests before production modules**

Use the tests at source SHA `52593ae` as the behavioral oracle. Keep the real loopback
`requests.Session` coverage and real SQLite release lookup; do not import PR #9 analyzer tests.

- [ ] **Step 2: Verify baseline tests fail because the package is absent**

Run:

```bash
uv run pytest tests/baseline -q
```

Expected: collection failure for `devpi_guardian.baseline`.

- [ ] **Step 3: Port baseline production modules against main's analyzer APIs**

Port the five PR #9 modules using `apply_patch`. Adapt imports and calls to the analyzer versions
already on main rather than replacing analyzer code. Preserve these public boundaries:

```python
class ArtifactBytesSource(Protocol):
    def open(self, sha256: str) -> Path: ...


class ReleaseLookup(Protocol):
    def allowed_releases(self, project: str) -> list[ReleaseRecord]: ...
```

Selection must be deterministic, use only effective `ALLOW` releases, and retain tier attribution
in every diff finding.

- [ ] **Step 4: Make `requests` a locked direct runtime dependency**

Add exactly `"requests>=2.32,<3"` to `[project].dependencies`, run `uv lock`, and add a package
test reading wheel metadata to assert the direct requirement. Do not accept a `pyproject.toml`
change without the corresponding two-line project metadata update in `uv.lock`.

- [ ] **Step 5: Run baseline, analyzer and packaging tests**

Run:

```bash
uv sync --locked --extra test
uv run pytest tests/baseline tests/analyzers tests/test_package.py -q
```

Expected: PASS with the existing main analyzer regression suite unchanged.

- [ ] **Step 6: Commit F6/F7**

```bash
git add src/devpi_guardian/baseline tests/baseline pyproject.toml uv.lock tests/test_package.py
git commit -m "feat: integrate baseline selection and release diff"
```

---

### Task 3: Port the F5 worker core and durable discovery queue

**Files:**
- Create: `src/devpi_guardian/worker/models.py`
- Create: `src/devpi_guardian/worker/interfaces.py`
- Create: `src/devpi_guardian/worker/adapters.py`
- Create: `src/devpi_guardian/worker/analysis.py`
- Create: `src/devpi_guardian/worker/pipeline.py`
- Create: `src/devpi_guardian/worker/discovery.py`
- Create: `src/devpi_guardian/worker/__init__.py`
- Create: `tests/worker/test_adapters.py`
- Create: `tests/worker/test_analysis_engine.py`
- Create: `tests/worker/test_discovery.py`
- Create: `tests/worker/test_pipeline.py`

- [ ] **Step 1: Add worker-core tests from PR #9**

Port queue durability/recovery, analysis attribution, fenced verdict recording, diff evidence and
cooldown tests. Change the desired verified boundary before production code so a verified Artifact
owns a binary stream rather than a CAS `local_path`:

```python
with verified.open_for_analysis() as stream:
    assert stream.read() == artifact_bytes
assert stream.closed
```

- [ ] **Step 2: Verify worker tests fail for the absent package**

Run:

```bash
uv run pytest tests/worker/test_adapters.py tests/worker/test_analysis_engine.py \
  tests/worker/test_discovery.py tests/worker/test_pipeline.py -q
```

Expected: collection failure for `devpi_guardian.worker`.

- [ ] **Step 3: Add worker models and protocols with owned-stream lifecycle**

Port PR #9 analysis/report models, but replace the mutable path field with an owned stream opener:

```python
@dataclass(frozen=True, slots=True)
class VerifiedArtifact:
    stage: str
    project: str
    version: str
    filename: str
    sha256: str
    size_bytes: int
    _stream: BinaryIO = field(repr=False, compare=False)

    def open_for_analysis(self) -> AbstractContextManager[BinaryIO]:
        return _RewoundOwnedStream(self._stream)
```

`AnalysisBundle.close()` must close each distinct owned stream once. `QuarantineWorker.run_once()`
must close a prepared bundle in `finally`, including analyzer and policy exceptions.

- [ ] **Step 4: Port queue, adapters, analysis and pipeline**

Port PR #9 behavior with these changes: analysis materializes target/counterpart bytes only from
`open_for_analysis()` into a private temporary workspace; it never reopens a quarantine path or
uses `origin_url`. Keep claim SHA-256/size checks, lease token fencing, evidence attribution,
file-diff evidence, cooldown and `mark_analysis_error()` behavior.

- [ ] **Step 5: Run worker-core and F4 regression suites**

Run:

```bash
uv run pytest tests/worker/test_adapters.py tests/worker/test_analysis_engine.py \
  tests/worker/test_discovery.py tests/worker/test_pipeline.py tests/verdicts -q
```

Expected: PASS and every test-created stream is closed.

- [ ] **Step 6: Commit the worker core**

```bash
git add src/devpi_guardian/worker tests/worker
git commit -m "feat: add fenced quarantine worker core"
```

---

### Task 4: Port F12 audit chain and F10 policy engine

**Files:**
- Create: `src/devpi_guardian/audit/__init__.py`
- Create: `src/devpi_guardian/audit/writer.py`
- Create: `src/devpi_guardian/audit/verifier.py`
- Create: `src/devpi_guardian/policy/__init__.py`
- Create: `src/devpi_guardian/policy/engine.py`
- Create: `tests/audit/test_sqlite_audit.py`
- Create: `tests/policy/test_engine.py`

- [ ] **Step 1: Add PR #9 audit and policy tests**

Retain real SQLite transaction/rollback tests, canonical hash-chain fixtures, tamper detection,
deterministic policy version and evidence-order invariance.

- [ ] **Step 2: Verify tests fail because audit and policy packages are absent**

Run:

```bash
uv run pytest tests/audit tests/policy -q
```

Expected: collection failures for `devpi_guardian.audit` and `devpi_guardian.policy`.

- [ ] **Step 3: Port audit writer and verifier against migration v5**

The writer implements the existing `AuditWriter.append_in_transaction()` protocol and never opens
or commits its own connection. Hash input remains canonical JSON and includes the previous event
hash. Verification returns a typed invalid result for any missing link, malformed digest or event
hash mismatch.

- [ ] **Step 4: Port the deterministic policy engine**

Use the PR #9 `AnalysisReport` boundary introduced in Task 3. Preserve canonical policy JSON,
revisioned `policy_version`, coverage rules, score thresholds and fail-closed analyzer-error
handling. Do not add external policy I/O.

- [ ] **Step 5: Run audit, policy, worker and store tests**

Run:

```bash
uv run pytest tests/audit tests/policy tests/worker/test_pipeline.py tests/verdicts -q
```

Expected: PASS, including transaction rollback proving audit and verdict history are atomic.

- [ ] **Step 6: Commit F10/F12**

```bash
git add src/devpi_guardian/audit src/devpi_guardian/policy tests/audit tests/policy
git commit -m "feat: integrate policy and chained audit"
```

---

### Task 5: Port F11 administrator API and CLI

**Files:**
- Create: `src/devpi_guardian/admin/__init__.py`
- Create: `src/devpi_guardian/admin/service.py`
- Create: `src/devpi_guardian/admin/views.py`
- Create: `src/devpi_guardian/admin/client.py`
- Create: `src/devpi_guardian/admin/cli.py`
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `tests/admin/test_reader.py`
- Create: `tests/admin/test_service.py`
- Create: `tests/admin/test_views.py`
- Create: `tests/admin/test_cli.py`

- [ ] **Step 1: Add F11 service/view/client/CLI tests before code**

Port PR #9 tests for quarantine listing/details, approve/block/revoke/rescan transitions,
authenticated actor propagation, 404/409/503 mapping, audit/diff/baseline/policy optional ports and
JSON CLI output. Keep mutations fail-closed when providers are unavailable.

- [ ] **Step 2: Verify admin tests fail because the package and script are absent**

Run:

```bash
uv run pytest tests/admin -q
```

Expected: collection failures for `devpi_guardian.admin`.

- [ ] **Step 3: Port the F11 service, routes, client and CLI**

Keep the PR #9 provider protocols but do not add `ProductionAdminProviders` yet. Route registration
must store only `GuardianAdminService` at `ADMIN_SERVICE_REGISTRY_KEY`; views may not access SQLite
or quarantine paths directly.

- [ ] **Step 4: Register and lock the console script**

Add exactly:

```toml
[project.scripts]
guardian = "devpi_guardian.admin.cli:main"
```

Run `uv lock` after `pyproject.toml` changes.

- [ ] **Step 5: Run admin, verdict and package tests**

Run:

```bash
uv sync --locked --extra test
uv run pytest tests/admin tests/verdicts tests/test_package.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit F11 surfaces**

```bash
git add src/devpi_guardian/admin tests/admin pyproject.toml uv.lock tests/test_package.py
git commit -m "feat: add Guardian admin API and CLI"
```

---

### Task 6: Implement the hardened quarantine CAS and bytes connectors

**Files:**
- Create: `src/devpi_guardian/worker/quarantine.py`
- Create: `src/devpi_guardian/worker/preparer.py`
- Create: `src/devpi_guardian/worker/devpi_source.py`
- Create: `src/devpi_guardian/worker/discovery_consumer.py`
- Create: `src/devpi_guardian/worker/upload.py`
- Modify: `src/devpi_guardian/worker/__init__.py`
- Create: `tests/worker/test_quarantine.py`
- Create: `tests/worker/test_preparer.py`
- Create: `tests/worker/test_devpi_source.py`
- Create: `tests/worker/test_discovery_consumer.py`
- Create: `tests/worker/test_upload.py`

- [ ] **Step 1: Write the full quarantine contract tests first**

Start from PR #9 preparer/source/consumer tests, but replace its quarantine tests with tests for:

```python
assert store.object_relative_path(DIGEST) == Path(
    "objects", "sha256", DIGEST[:2], DIGEST[2:4], DIGEST
)
```

Also test relative root rejection; root and component symlink rejection; exact owner and 0700 root /
0600 object modes; non-regular and `st_nlink != 1` rejection; digest/size mismatch cleanup; atomic
no-overwrite under two concurrent publishers; idempotent same bytes; corrupt existing object;
descriptor remains bound after the pathname is replaced; and every failure closes descriptors.

- [ ] **Step 2: Verify quarantine tests fail before implementation**

Run:

```bash
uv run pytest tests/worker/test_quarantine.py -q
```

Expected: collection failure because `worker.quarantine` is absent.

- [ ] **Step 3: Implement descriptor-relative root and object traversal**

`QuarantineStore` requires an existing or newly created absolute root owned by the effective user
with mode 0700. Hold a root descriptor opened with `O_DIRECTORY | O_NOFOLLOW`; create/open every
component with `dir_fd`, and derive paths only from validated SHA-256:

```python
def object_relative_path(sha256: str) -> Path:
    digest = validate_sha256(sha256)
    return Path("objects", "sha256", digest[:2], digest[2:4], digest)
```

Object checks use `fstat`: regular file, current `geteuid()` owner where available, mode 0600,
link count 1, expected size, streaming SHA-256.

- [ ] **Step 4: Implement atomic no-overwrite publish and verified open**

Create `.incoming` files using `O_CREAT | O_EXCL | O_NOFOLLOW` and mode 0600. After streaming
verification and `fsync`, publish without overwrite using same-filesystem `linkat` semantics
(`os.link` with source/destination dir descriptors), unlink the incoming name, fsync both parent
directories, then securely open and reverify the final object. If destination already exists,
verify it and treat only identical bytes as idempotent success.

Return a `VerifiedArtifact` owning the already verified descriptor. Never return the CAS pathname
as the analysis input.

- [ ] **Step 5: Run quarantine tests and race tests**

Run:

```bash
uv run pytest tests/worker/test_quarantine.py -q
```

Expected: PASS, including concurrent no-overwrite and path-replacement tests.

- [ ] **Step 6: Add failing preparer, devpi source, discovery and upload tests**

Port PR #9 tests, then add private-upload behavior proving `persist()` completes before
`discover_artifact()` and no HTTP/public URL is used. The desired connector call is:

```python
connector.capture(stage=stage, project="demo", version="1.0", link=link)
assert events == ["quarantine_published", "artifact_discovered"]
```

- [ ] **Step 7: Implement bytes connectors**

Adapt PR #9 `DevpiArtifactBytesSource`, `DiscoveryConsumer`, `SimpleLinkResolver` and
`QuarantineArtifactPreparer` to the descriptor-backed store. Add `PrivateUploadConnector` which
streams `link.entry.file_open_read()` directly into quarantine, closes the verified descriptor,
then calls `store.discover_artifact(ArtifactInput(...), ReleaseInput(...))`. Mirror misses may use
the stage's internal HTTP client; neither connector calls Guardian `+f`/`+e` URLs or trusts a
filename/origin URL as a filesystem path.

- [ ] **Step 8: Run all worker and verdict tests**

Run:

```bash
uv run pytest tests/worker tests/verdicts -q
```

Expected: PASS.

- [ ] **Step 9: Commit the hardened CAS and connectors**

```bash
git add src/devpi_guardian/worker tests/worker
git commit -m "feat: harden quarantine storage and artifact intake"
```

---

### Task 7: Compose activation-first runtime and production admin providers

**Files:**
- Create: `src/devpi_guardian/worker/runtime.py`
- Create: `src/devpi_guardian/admin/providers.py`
- Modify: `src/devpi_guardian/plugin.py`
- Modify: `src/devpi_guardian/__init__.py`
- Modify: `tests/test_guardian_stage.py`
- Modify: `tests/activation/test_activation.py`
- Create: `tests/admin/test_providers.py`
- Create: `tests/worker/test_runtime.py`
- Modify: `tests/integration/conftest.py`

- [ ] **Step 1: Add failing configuration and zero-side-effect startup tests**

Test that primary runtime rejects a missing, relative, server-directory-contained, symlinked or
unsafe-mode quarantine root before migration/runtime publication. Instrument registry, thread pool
and route/tween calls, then assert activation failure leaves all untouched:

```python
with pytest.raises(Fatal, match="guardian activation"):
    devpiserver_pyramid_configure(config, pyramid_config)
assert thread_pool.registered == []
assert VERDICT_READER_REGISTRY_KEY not in registry
assert ADMIN_SERVICE_REGISTRY_KEY not in registry
assert pyramid_config.tweens == []
```

Also test replica worker non-registration, corrupt audit startup failure, worker session shutdown,
and private upload hook forwarding only after successful activation.

- [ ] **Step 2: Verify runtime tests fail against the current plugin**

Run:

```bash
uv run pytest tests/activation/test_activation.py tests/worker/test_runtime.py \
  tests/admin/test_providers.py tests/test_guardian_stage.py -q
```

Expected: failures for missing options, providers, thread registration and upload hook; all old
activation tests remain green.

- [ ] **Step 3: Port runtime and providers**

Adapt PR #9 `GuardianWorkerThread`, `WorkerCoordinator`, `build_worker_thread` and
`ProductionAdminProviders`. Runtime receives an already validated `QuarantineStore` rather than
constructing an unchecked path. Provider SQL stays read-only; mutations call public store methods.

- [ ] **Step 4: Refactor plugin composition into prepare-then-publish phases**

The hook order must be structurally visible:

```python
settings = _validate_settings(config)
factory = ConnectionFactory(settings.db_path)
migrate(factory)
_verify_audit_or_fatal(factory)
_activate_or_fatal(factory, config, xom)
components = _build_components(settings, factory, xom)
_publish_components(components, pyramid_config, xom)
```

`_build_components` may allocate reader/store/queue/policy/admin/worker after activation, but
`_publish_components` alone may set XOM attributes, register the worker, install admin routes,
registry keys and tween. If component construction fails, close the requests session and
quarantine root descriptor and publish nothing.

Add parser options for absolute quarantine root, base URL, cooldown and poll interval. Primary
runtime with a thread pool requires explicit quarantine root outside `config.server_path`; replica
does not start a worker. Register the private upload connector on XOM only for primary.

- [ ] **Step 5: Add the private upload hook**

Implement the exact devpi hook signature:

```python
@server_hookimpl
def devpiserver_on_upload(stage, project, version, link) -> None:
    connector = get_upload_connector(stage.xom)
    connector.capture(stage=stage, project=project, version=version, link=link)
```

Missing connector on replica is an intentional no-op; missing connector on an activated primary
is a startup invariant error, not a public download bypass.

- [ ] **Step 6: Run startup, runtime, admin and activation tests**

Run:

```bash
uv run pytest tests/activation tests/worker/test_runtime.py tests/admin \
  tests/test_guardian_stage.py -q
```

Expected: PASS with worker registration occurring after activation and before final publication.

- [ ] **Step 7: Commit production wiring**

```bash
git add src/devpi_guardian/plugin.py src/devpi_guardian/__init__.py \
  src/devpi_guardian/worker/runtime.py src/devpi_guardian/admin/providers.py \
  tests/activation tests/worker/test_runtime.py tests/admin tests/test_guardian_stage.py \
  tests/integration/conftest.py
git commit -m "feat: wire activation-first Guardian runtime"
```

---

### Task 8: Prove end-to-end behavior, document provenance and verify the matrix

**Files:**
- Modify: `tests/integration/conftest.py`
- Create: `tests/integration/test_worker_runtime.py`
- Modify: `tests/integration/test_direct_download.py`
- Modify: `README.md`
- Create: `docs/f5-worker.rst`
- Create: `docs/f11-admin-api-cli.rst`
- Create: `docs/reviews/2026-08-25-pr5-pr9-integration-review.md`
- Create: `news/5.feature`
- Create: `news/6.feature`
- Create: `news/7.feature`
- Create: `news/10.feature`
- Create: `news/11.feature`
- Create: `news/12.feature`
- Modify: `tests/test_package.py`

- [ ] **Step 1: Add failing real-devpi integration tests**

Use a quarantine directory outside the devpi server directory with mode 0700. Prove this sequence
for private upload: upload succeeds; quarantine object exists at the SHA-256 CAS path; Artifact is
discovered but direct `+f`/`+e` remains blocked; worker records a terminal verdict; only effective
`ALLOW` permits GET/HEAD. Add a mirror test proving bytes are acquired through the stage internal
client, not by requesting Guardian's protected public URL.

- [ ] **Step 2: Verify the new E2E tests fail before fixture/runtime completion**

Run:

```bash
uv run pytest tests/integration/test_worker_runtime.py -q -m integration
```

Expected: FAIL at the first missing fixture or runtime observation, while existing direct-download
integration tests remain independently runnable.

- [ ] **Step 3: Complete the E2E fixture and runtime behavior**

Pass explicit `--guardian-quarantine-root`, wait on observable DB/health conditions rather than
fixed sleeps, and sanitize process failure output. Apply only the minimal runtime fixes exposed by
the E2E test, with a focused regression test before each production fix.

- [ ] **Step 4: Add documentation and packaging provenance**

Adapt PR #5/#9 operator documentation to the final option names and secure CAS layout. Explicitly
state that existing devpi instances still require future offline backfill, the quarantine root must
be dedicated/0700/outside server storage, and PR #5/#9 were selectively integrated from SHAs
`22bc029` and `52593ae`. Keep PR #1 activation and CI documentation.

- [ ] **Step 5: Run fresh local acceptance verification**

Run all commands and retain complete exit status:

```bash
uv sync --locked --extra test
uv run pytest -q
uv run ruff format --check .
uv run ruff check .
uv run flake8 src tests
uv lock --check
uv build
git diff --check origin/main...HEAD
```

Expected: zero failures, zero lint errors, locked project metadata and successful sdist/wheel.

- [ ] **Step 6: Record independent review disposition**

After the required fresh specification reviewer and security/code-quality reviewer approve the
final HEAD, record reviewer identifiers, base/head SHAs, commands, and every resolved finding in
`docs/reviews/2026-08-25-pr5-pr9-integration-review.md`. Critical and Important open counts must
both be zero.

- [ ] **Step 7: Commit acceptance artifacts**

```bash
git add README.md docs news tests/integration tests/test_package.py
git commit -m "docs: record safe Guardian feature integration"
```

- [ ] **Step 8: Re-run the entire acceptance verification at the final commit**

Repeat Step 5 without modifying files. Expected: all commands exit 0. Only this fresh output may
be used in the PR handoff.
