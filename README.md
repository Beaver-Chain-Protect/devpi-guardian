# devpi-guardian

devpi-guardian is a devpi-server plugin that exposes a release file only when its
verified Artifact SHA-256 has a valid effective `ALLOW` verdict. The enforcement
path is fail-closed: an unknown Artifact, an in-progress analysis, a denied or
errored analysis, an identity lookup failure, and a verdict-store failure never
reach the devpi file handler.

The [approved F3/F4 design][approved-design] is in the repository.

[approved-design]: https://github.com/Beaver-Context-Protocol/devpi-guardian/blob/main/docs/superpowers/specs/2026-08-17-devpi-guardian-f3-f4-design.md

## New-install activation boundary

PR1 supports new Guardian deployments only. “New” means the first consistent
Guardian activation snapshot has no existing Artifact candidates; a newly created
devpi server directory is not enough. Guardian writes one immutable
`guardian_activation` marker containing the devpi `devpi_uuid` and activation
version. The first activation marker is created only after the offline KeyFS
snapshot is checked, and later starts require the same UUID and preserved marker.

Activation refuses with the bounded category `existing_artifacts` when any existing
private or root-pypi Artifact candidate is found, including a cached mirror file or
persisted release link. Inventory is a single offline snapshot: there is no
online/public network inventory, mirror refresh, or public download. A missing
Guardian DB on a restored devpi is a DB loss and is refused rather than treated as a
new install. Migration/backfill is deferred and not supported in PR1; existing
instances must remain without this plugin until the separate offline process exists.
There is no compatibility bypass: no legacy allow flag, pass-through, route exception,
or worker token can weaken the gate.

Operational preflight must verify the devpi snapshot is empty of Artifact candidates,
that one migration/activation owner is used, and that the Guardian database and its
WAL/SHM files are on a persistent volume. Use a SQLite-consistent backup before
changes, and keep a rollback plan that removes the plugin and restores the prior
devpi service if activation fails. Any uncertainty remains fail-closed before
readiness; do not serve unverified bytes to make rollback easier.

## F5 quarantine

F5 reads unapproved Artifact bytes only from the `--guardian-quarantine-root` directory, an absolute
dedicated permission-restricted path outside public devpi storage/routes. Deployment
must not expose it through HTTP. The content-addressed layout is exactly
`objects/sha256/<first-2>/<next-2>/<sha256>`; SQLite, filenames, projects, versions,
and URLs never choose a filesystem path. Unapproved bytes never live in SQLite or
public `+f`/`+e` storage as a worker input. Devpi may store and serve approved
artifacts, but F5 never uses public `+f`/`+e` for unapproved worker input.

The private upload connector copies a verified FileEntry read stream into the
quarantine writer. The mirror discovery connector downloads an upstream candidate
and verifies its supplied upstream hash before publishing. Existing devpi data is
not copied through this path; it is offline backfill-only work deferred beyond PR1.

Writers create an exclusive temporary file under `.incoming` on the same filesystem,
hash and size the stream, and fsync the file. The final object must have the expected
owner/mode; symlinks, hard links, non-regular files, unsafe permissions, and path
escape are rejected. A digest/size mismatch discards the temporary file without
discovery. Publish-before-discover ordering is mandatory: the publish operation is
an atomic no-overwrite publish. An existing final digest
is accepted only after duplicate digest byte identity is verified, and no existing
object is overwritten. The final file and required parent directories are fsynced
before `discover_artifact()` writes discoverable metadata.

F5 derives the final path only from the fenced `ClaimedArtifact.sha256` and
`size_bytes`. It never fetches `origin_url` or interprets it as a local path. The
reader uses no-symlink/no traversal semantics, a pre-opened quarantine root fd, and
component `openat` (or an equivalent safe API), `O_NOFOLLOW`, and `fstat` to verify
each directory and regular file. It checks the claimed size and computes a streaming
digest on the same open file descriptor. After hashing, rewind the descriptor and
pass that same descriptor to the analyzer; it is kept open for analysis. This
same-open-file digest verification means parsing occurs only after the digest matches.
The reader only then parses the descriptor.

Mismatch/missing/I/O/symlink failures are fail-closed, including permission, type,
and size errors: F5 calls `mark_analysis_error()` with the same fenced claim and produces
no verdict. F5 alone reads unapproved bytes from this path. F6 still uses HTTP(S)
canonical +f/+e after ALLOW. There is no worker/public route bypass token, header, query, or
loopback exception. Orphan objects remain safe under the cleanup/retention contract;
PR1 does not silently delete them.

The integrated worker requires an explicit `--guardian-quarantine-root` absolute directory.
Create a dedicated directory with mode `0700`, owned by the devpi service account, outside
the devpi `--serverdir`; it must not be mounted or routed as public storage. Private uploads
are copied into this CAS before discovery. Mirror candidates are read through devpi's internal
stage client and upstream stream, never through Guardian's protected public `+f`/`+e` URL.
The worker publishes health and queue state through the F11 API while it waits for durable
discovery and terminal verdict transitions. Existing devpi installations with artifacts are
not automatically backfilled: offline migration/backfill remains unsupported until a future
dedicated process is delivered.

## Implemented features

- A read-only `guardian` index type that requires at least one devpi base index.
- Batched SHA-256 filtering for HTML and PEP 691 Simple responses: only links with
  an effective `ALLOW` verdict are visible to pip and uv.
- Fail-closed direct release enforcement for `+f`/`+e`, `GET`/`HEAD`, and PEP 658
  `.metadata` requests.
- SHA-256 SQLite verdict persistence with migrations, bounded reads, immutable
  verdict/evidence history, claim fencing, lease recovery, and fail-closed corruption
  handling.
- Automated verdict completion; audited manual `ALLOW`/`DENY`, revoke, and rescan
  transitions; and deterministic read-time override expiry.
- F6 project lookup of effective `ALLOW` releases through the public
  `VerdictReader.list_allowed_releases()` API and exported `AllowedRelease` model.
- A devpi plugin with sanitized structured block logs and bounded in-process metrics.
- The real devpi subprocess suite covers pip/uv, restarts, concurrency, direct URLs, and
  hashless mirror identity-unavailable fail-closed behavior. Identity failure remains
  `503` even when a matching `ALLOW` exists.
- A narrower official `pytest-devpi-server` fixture smoke test exercises the installed
  plugin.
- The integrated F5 runtime proof exercises private upload → CAS → discovery → terminal
  verdict and verifies that only an effective `ALLOW` enables `GET`/`HEAD`, including
  protected metadata. Mirror bytes are proven to arrive through the internal stage client,
  while the hashless mirror `+e` path stays fail-closed.

## Safe PR5/PR9 integration provenance

The F5/F6/F7/F10/F11/F12 functionality was selectively integrated from PR5 commit
`22bc029e584af43e6c79b72a3d6fcef35f49f05f` and PR9 commit
`52593ae444f416625a0e96f0a4874bc30987ce8d` onto the PR1 activation and enforcement line.
The PR branches were not merged wholesale. PR1 activation ordering, fail-closed public
download enforcement, immutable SQLite history, claim fencing, and Python 3.11–3.14 CI
documentation remain authoritative.

## F8/F9 artifact analyzers

The repository also includes deterministic, non-executing F8/F9 analyzers under
`src/devpi_guardian/analyzers/`. F8 scans installation surfaces and F9 compares matching
sdist/wheel releases for wheel-only risk signals. Their findings are advisory inputs for
the policy/evidence layers; they do not change enforcement or verdict behavior. See the
[F8/F9 handoff](docs/analyzers/f8-f9-handoff.md) for the public API, JSON schema, and demo
commands.

## Repository structure

The repository keeps enforcement, verdict storage, integration coverage, and delivery
metadata in this layout:

```text
.
├── src/
│   └── devpi_guardian/
│       ├── enforcement/       # Resolve identities, enforce, and record metrics.
│       ├── verdicts/           # SQLite schema, reader, models, and store.
│       ├── analyzers/          # Deterministic F8/F9 artifact analysis and schemas.
│       └── plugin.py           # Register the devpi-server plugin and wire startup.
├── tests/
│   ├── enforcement/           # Direct-download enforcement and metrics tests.
│   ├── verdicts/               # Persistence, reader, claim, and transition tests.
│   ├── analyzers/              # F8/F9 analyzer, contract, and integration tests.
│   └── integration/            # Real devpi-server and resolver integration tests.
├── docs/
│   ├── analyzers/               # F8/F9 public API and integration handoff.
│   └── superpowers/
│       ├── specs/              # Approved designs and supporting specifications.
│       └── plans/              # Implementation plans.
├── tools/                      # Offline F8/F9 corpus and demo utilities.
├── news/                       # Release-note fragments.
├── pyproject.toml              # Packaging, dependencies, and tool configuration.
└── uv.lock                     # Locked development and runtime dependencies.
```

## Guardian index and Simple filtering (F1/F2)

Create a Guardian index over an existing devpi stage or mirror:

```console
devpi index -c root/guardian type=guardian bases=root/pypi
```

The stage is read-only and rejects configuration without an explicit `bases`
value. Configure installers to use its standard devpi Simple endpoint:

```console
pip install --index-url https://devpi.example.com/root/guardian/+simple/ PACKAGE
uv pip install --index-url https://devpi.example.com/root/guardian/+simple/ PACKAGE
```

Only canonical SHA-256 links with an effective `ALLOW` verdict are returned.
Verdict-store failures during a required lookup return `503 Service Unavailable`
with `Retry-After: 5`.

F1/F2 do not periodically download or discover new PyPI Artifacts, run security
analysis, or implement a time-based cooldown. F5 must discover and persist an
Artifact and its release mapping before F4 can return a verdict. Until that
pipeline exists, an unknown Artifact remains hidden. F3 separately protects
direct `+f`/`+e` URLs across all indexes, so bypassing the Guardian Simple page
does not bypass enforcement.

The batching, failure, metadata-preservation, and completion contracts are
defined once in the
[F1/F2 specification](docs/superpowers/specs/2026-08-20-f1-f2-guardian-index-simple-filter.md).

## Shared verdict reader and connection boundaries

The plugin creates one persistent `ConnectionFactory`, runs `migrate` once
before readiness, and constructs the shared `SQLiteVerdictReader` during
Pyramid configuration:

```python
from pathlib import Path

from devpi_guardian.verdicts.db import ConnectionFactory, migrate
from devpi_guardian.verdicts.reader import SQLiteVerdictReader

factory = ConnectionFactory(Path("/var/lib/devpi-guardian/guardian.db"))
migrate(factory)  # one startup process, before devpi is ready
reader = SQLiteVerdictReader(factory)
```

The installed plugin puts that same eagerly created reader in both the Pyramid
registry and the devpi XOM object. F3 and later request-layer consumers use
`VERDICT_READER_REGISTRY_KEY` (`devpi_guardian.verdict_reader`):

```python
from devpi_guardian.enforcement.tween import VERDICT_READER_REGISTRY_KEY
from devpi_guardian.verdicts.interfaces import VerdictReader

reader: VerdictReader = pyramid_config.registry[VERDICT_READER_REGISTRY_KEY]
decision = reader.get_effective_decision(sha256)
decisions = reader.get_effective_decisions(sha256s)
```

F2 runs in the stage/model layer, where a Pyramid request is not guaranteed.
It obtains the already initialized object through `get_verdict_reader(stage.xom)`:

```python
from devpi_guardian.plugin import get_verdict_reader

reader = get_verdict_reader(stage.xom)
decisions = reader.get_effective_decisions(sha256s)
```

The accessor never creates or migrates a database. Startup migration and reader
construction remain exclusively in `devpiserver_pyramid_configure`; accessing
F2 before successful initialization fails closed.

`SQLiteVerdictReader` returns an `EnforcementDecision` with `sha256`,
`allowed`, `effective_decision`, `source`, `artifact_state`, and
`policy_version`. A missing SHA-256 is a normal `allowed=False` result with
`source=MISSING`; connection, lock, malformed-database, and persisted-state
failures raise `StoreUnavailable` instead. F2 and the direct-download tween
must use this reader rather than duplicate SQL or precedence logic.

F6 consumers can obtain the effective allowed releases for a project from the
same public reader used by F2 and F3:

```python
from devpi_guardian.enforcement.tween import VERDICT_READER_REGISTRY_KEY
from devpi_guardian.verdicts import AllowedRelease
from devpi_guardian.verdicts.interfaces import VerdictReader

reader: VerdictReader = pyramid_config.registry[VERDICT_READER_REGISTRY_KEY]
releases: tuple[AllowedRelease, ...] = reader.list_allowed_releases("Demo_Package")
for release in releases:
    print(
        release.project,
        release.stage,
        release.version,
        release.filename,
        release.sha256,
        release.origin_url,
    )
```

The public signature is
`list_allowed_releases(project: str) -> tuple[AllowedRelease, ...]`.
The caller project is PEP 503-normalized. The query searches every stage by
canonical project and returns a deterministic immutable tuple ordered by
`stage/version/filename/sha256/origin_url`; no results is `()`.

The exact precedence is: an unexpired current manual override wins; manual DENY
excludes and manual ALLOW includes; expires_at <= evaluation time is ignored,
then only automated ALLOW includes (all other fallback decisions exclude).
Thus only current effective `ALLOW` releases appear, including automatic ALLOW
results and valid manual ALLOW overrides, with manual DENY, expiry, and automated
fallback using the same precedence as F2/F3.

`origin_url` is sanitized canonical origin metadata. Admin responses may return that
metadata, but it never contains credentials, query strings, fragments, or local
filesystem paths. F5 records canonical devpi HTTP(S) `+f`/`+e` URLs, and F6 issues
HTTP(S) through those routes and Guardian enforcement; it never treats `origin_url`
as a trust bypass or local open. F4 does not fetch the URL or independently rehash
its contents.

F5 runs in the devpi process after activation. The plugin creates one
`ConnectionFactory`, `SQLiteAuditWriter`, `SQLiteArtifactStore`, and
`SQLiteVerdictReader`, then builds the primary `GuardianWorkerThread` with the in-
process devpi XOM, quarantine store, internal stage client, and the shared reader.
The worker is registered with devpi's thread pool only after activation and startup
verification succeed; replicas do not start it. F12's persistent SQLite audit writer
is part of this same composition and transaction boundary.

`claim_next` atomically changes `DISCOVERED` to `SCANNING` and returns a
`ClaimedArtifact` containing `sha256`, `size_bytes`, `worker_id`,
`lease_expires_at`, and a canonical `lease_token`. The token is an opaque
64-character lowercase hexadecimal value, is hidden from the DTO repr, and is
required for `record_verdict` and `mark_analysis_error`; an expired or changed
claim returns `TransitionConflict` rather than recording a result.

F10 supplies the exact current DTO fields when completing a claim:

```python
from datetime import UTC, datetime

from devpi_guardian.verdicts.models import Decision, EvidenceInput, VerdictInput

verdict = VerdictInput(
    sha256=claim.sha256,
    decision=Decision.ALLOW,
    score=0.98,
    policy_version="policy-1",
    analyzer_version="analyzer-1",
    baseline_sha256=None,
    baseline_tier=None,
    created_at=datetime.now(UTC),
)
evidence = [
    EvidenceInput(
        rule_id="rule-example",
        action=Decision.ALLOW,
        file_path="src/example.py",
        line=1,
        message="analysis completed",
        details={"example": "value"},
    )
]
store.record_verdict(claim, verdict, evidence)
```

`baseline_tier` is typed as `Literal["same_tag", "universal_wheel", "sdist"]`.
`baseline_sha256 and baseline_tier must both be set or both be None`.
F6 passes `selection.tier` unchanged through F10, so `baseline_tier=None` is
used when no baseline is selected. `sdist comparisons have lower confidence`
than same-tag or universal-wheel comparisons and remain distinguishable in F4's
immutable verdict history.

Manual transitions are also transaction-bound and audited:

```python
store.set_manual_override(override)  # ManualOverrideInput: ALLOW or DENY
store.revoke_manual_override(sha256, actor, reason)
store.request_rescan(sha256, actor, reason)
```

Overrides require an existing terminal Artifact (`ALLOW`, `REVIEW`, `DENY`, or
`ERROR`), a nonblank actor and reason, and an optional future expiry. A current
manual `DENY` wins; a current manual `ALLOW` is next; otherwise the current
automated verdict is used. Revoking an override returns to that automated
fallback. `request_rescan` deactivates the current override in the same
transaction and returns the Artifact to `DISCOVERED`, so it remains blocked
through discovery and scanning until a new verdict is recorded.

F12 implements `SQLiteAuditWriter.append_in_transaction(connection, event)` using
the exact `sqlite3.Connection` supplied by F4. The plugin injects this persistent
writer into `SQLiteArtifactStore`, so verdict, evidence, override, and audit writes
share one transaction; if audit recording fails, the state transition is rolled back.
The audit chain is verified during startup and exposed through the F11 health/admin
surfaces.

## Running devpi-server

Configure a primary with the persistent database, mandatory dedicated quarantine root,
and canonical base URL:

```console
devpi-server \
  --guardian-db /var/lib/devpi-guardian/guardian.db \
  --guardian-quarantine-root /var/lib/devpi-guardian/quarantine \
  --guardian-base-url https://devpi.example.test
```

`--guardian-quarantine-root` is required for a primary. Supply the canonical
`--guardian-base-url` explicitly for deployments; if omitted, the plugin derives a
canonical URL from devpi's outside URL or host/port settings. The database path may be
explicitly placed on a persistent volume. Keep the database and its WAL files together
across restarts. The plugin runs and validates its packaged migrations before registering
enforcement; a migration failure prevents startup readiness.

For direct `GET` and `HEAD` requests under `+f` and `+e` (including
`.metadata` requests), the tween resolves the devpi release-file identity and
consults the reader before invoking the existing handler:

- a structurally valid effective `ALLOW` reaches the handler;
- a missing, `DISCOVERED`, `SCANNING`, `REVIEW`, `DENY`, or `ERROR` result is a
  sanitized `404`, unless a valid current manual `ALLOW` makes it effective;
- missing or invalid SHA-256 identity is a `503`;
- a locked, unavailable, or corrupt verdict store is a `503` with
  `Retry-After: 5`;
- non-releasefile requests remain with devpi's existing handler.

Response bodies and logs do not expose the SHA-256 decision reason, URL
credentials, or query secrets. The tween does not trust URL fragments,
filenames, or client headers as Artifact identity.

The raw-target guard for protected `GET`/`HEAD` requests requires at least one
of `REQUEST_URI`, `RAW_URI`, or `RAW_PATH_INFO`; every present key must match
the decoded identity. Literal route markers and canonical UTF-8 encoding are
accepted, with only the uppercase encoded fixed marker `/%2Bf/` or `/%2Be/`
allowed as the pip compatibility exception. Lowercase or double encoding,
encoded slash, and encoded `+` in the user, index, or tail are rejected.

## Error mapping for API callers

Map domain errors consistently at the management/API boundary:

| Error | HTTP status | Meaning |
| --- | ---: | --- |
| `ArtifactNotFound` | 404 | Referenced Artifact or baseline is absent |
| `TransitionConflict` | 409 | Compare-and-swap or lease precondition failed |
| `StoreUnavailable` | 503 | SQLite connection, lock timeout, corruption, or unavailable store |
| `InvalidSha256` | 400 | Input is not a lowercase 64-character SHA-256 |

`MigrationError` is a startup/configuration failure and should not be hidden by
serving with an unvalidated database.

## Operations and security

- During P0 first initialization, exactly one startup/migration owner must run
  `migrate` before readiness. Do not concurrently start multiple Guardian devpi
  instances against an empty database. After the owner is ready, later starts
  validate the initialized schema idempotently.
- Each process and thread obtains its own `ConnectionFactory.connect()` SQLite
  connection; connections are not shared across threads or processes.
- Keep the database, `-wal`, and `-shm` files on the same persistent volume.
  For backup, use SQLite's backup API or checkpoint and take a consistent
  snapshot; do not copy only the main database file while WAL writes are
  active.
- There is no verdict cache. Approval, revocation, expiry, and rescan decisions
  are read from SQLite on each enforcement lookup.
- Block direct PyPI or other upstream egress at the network/deployment layer.
  F3 protects files served through devpi; it cannot protect a client that
  bypasses devpi and downloads from an external endpoint directly.

## In-process block metrics

The installed plugin puts a thread-safe `InMemoryBlockMetricRecorder` in the
Pyramid registry under
`devpi_guardian.direct_download_block_metrics`. The tween records blocked
requests on a best-effort basis without changing the HTTP decision. Call
`snapshot()` on that registry object to obtain the current in-process counter
mapping; no external metrics exporter is included.

Each `BlockMetricDimensions` key contains exactly `route`, `sha256`,
`effective_decision`, and `block_category`. Route is `+f`, `+e`, or `unknown`;
identity failures use `unknown` for SHA-256 and decision; categories currently
include `identity_unavailable`, `store_unavailable`, and `not_allowed`. The
default recorder admits exactly 4,096 distinct normal series, then increments
one fixed `cardinality_overflow` series; existing keys keep incrementing after
the cap. Thus `snapshot()` is bounded to at most 4,097 series. Input fields
are validated as bounded route, canonical SHA-256-or-`unknown`, decision, and
category values; URL credentials, filenames, and query secrets are never
dimensions. Allowed requests do not increment the counter.

## Performance evidence

The marked test measures a file-backed SQLite database with one Artifact and
one current automated `ALLOW` verdict. Each of 1,000 sequential calls performs
a full `SQLiteVerdictReader` lookup, including opening and closing a connection
for that call. On macOS with Python 3.12.x, independent runs on 2026-08-18
reported P95 values from 0.783 ms to 1.472 ms, against the `<100 ms` budget.
Reproduce with:

```console
uv run pytest -m performance -s -v
```

## Development verification

Bootstrap the locked test environment, then run the complete checks:

```console
uv sync --extra test
uv run pytest -q
uv run ruff format --check .
uv run ruff check .
uv run flake8 src tests
uv lock --check
uv build
```

## F3/F4 completion criteria

- SQLite migration is repeatable on an empty or already initialized database,
  and artifacts, mappings, verdict history, evidence, overrides, and the persistent
  F12 audit chain survive process restart. F4 proves same-transaction rollback when
  audit recording fails.
- All writes and audit events share one transaction; automated verdicts and
  evidence remain immutable, and only one current verdict and override apply to
  an Artifact.
- Concurrent workers cannot claim one Artifact twice; expired claims recover to
  `DISCOVERED`; claim-token and lease mismatches cannot record a verdict.
- Effective-decision precedence, override expiry, revoke, and rescan semantics
  are deterministic and fail closed.
- The reader and writer map unavailable, lock-timeout, malformed, and corrupt
  SQLite states to `StoreUnavailable`. The reproducible performance condition
  and observed P95 range are recorded above, with every result below 100 ms.
- Only an effective `ALLOW` release file reaches the devpi handler for `+f`,
  `+e`, `GET`, `HEAD`, and `.metadata`; direct URLs cannot bypass the reader.
- The real subprocess harness in `tests/integration/conftest.py` and the
  official `pytest-devpi-server` fixture smoke test in
  `tests/integration/test_pytest_devpi_server.py` verify direct-route blocking,
  allow behavior, restart persistence, and `+e` failure handling. A controlled
  stopped-server KeyFS cache-entry proof also verifies the genuine hashless `+e`
  lifecycle after SHA metadata is committed through devpi's internal cache path. The broader
  integration proof verifies 64 concurrent blocked requests (8 workers over 8
  rounds), exact-version pip behavior when an Artifact is allowed or revoked,
  uv direct URL lock/sync behavior, and `%2Bf`/`%2Be` route-marker compatibility
  in resolver tests.
- The plugin-installed in-process block counter records validated bounded
  series with a fixed overflow series; exporting snapshots is an external
  deployment responsibility.
