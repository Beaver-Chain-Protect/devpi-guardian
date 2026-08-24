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

F5 reads unapproved Artifact bytes only from `GUARDIAN_QUARANTINE_DIR`, an absolute
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

## Implemented features

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

## Repository structure

The repository keeps enforcement, verdict storage, integration coverage, and delivery
metadata in this layout:

```text
.
├── src/
│   └── devpi_guardian/
│       ├── enforcement/       # Resolve identities, enforce, and record metrics.
│       ├── verdicts/           # SQLite schema, reader, models, and store.
│       └── plugin.py           # Register the devpi-server plugin and wire startup.
├── tests/
│   ├── enforcement/           # Direct-download enforcement and metrics tests.
│   ├── verdicts/               # Persistence, reader, claim, and transition tests.
│   └── integration/            # Real devpi-server and resolver integration tests.
├── docs/
│   └── superpowers/
│       ├── specs/              # Approved designs and supporting specifications.
│       └── plans/              # Implementation plans.
├── news/                       # Release-note fragments.
├── pyproject.toml              # Packaging, dependencies, and tool configuration.
└── uv.lock                     # Locked development and runtime dependencies.
```

## F3/F4 handoff and connection boundaries

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

F2 should receive that reader through dependency injection. In the installed
plugin, the Pyramid registry key is
`VERDICT_READER_REGISTRY_KEY` (`devpi_guardian.verdict_reader`):

```python
from devpi_guardian.enforcement.tween import VERDICT_READER_REGISTRY_KEY
from devpi_guardian.verdicts.interfaces import VerdictReader

reader: VerdictReader = pyramid_config.registry[VERDICT_READER_REGISTRY_KEY]
decision = reader.get_effective_decision(sha256)
decisions = reader.get_effective_decisions(sha256s)
```

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

`origin_url` is an absolute URL, not a local filesystem path. The existing F4
sanitizer removes userinfo, query, and fragment, but does not constrain the
stored scheme. For F6 integration, F5 MUST record the canonical devpi HTTP(S)
`+f`/`+e` artifact URL. F6 MUST issue HTTP(S) through canonical devpi `+f`/`+e`
and Guardian enforcement; never use `origin_url` as a trust bypass or local open.
F4 does not fetch the URL or independently rehash its contents.

F5 does not receive the in-process factory object created by the devpi plugin.
Deployment configuration owns one absolute database path. After the migration
owner reports readiness, F5 independently constructs a `ConnectionFactory`
from that exact path and does not query Guardian tables directly:

```console
export GUARDIAN_DB=/var/lib/devpi-guardian/guardian.db
devpi-server --guardian-db "$GUARDIAN_DB"
```

The plugin does not read `GUARDIAN_DB` automatically; the same deployment
configuration explicitly supplies `--guardian-db`, and the F5 process reads
the variable when constructing its own factory:

```python
import os
from pathlib import Path

from devpi_guardian.verdicts.store import SQLiteArtifactStore
from devpi_guardian.verdicts.db import ConnectionFactory

# Run this only after the devpi process using --guardian-db is ready.
f5_factory = ConnectionFactory(Path(os.environ["GUARDIAN_DB"]).resolve())
# audit_writer is an injected F12 implementation of AuditWriter.
store = SQLiteArtifactStore(f5_factory, audit_writer)
claim = store.claim_next(worker_id, lease_until)
if claim is not None:
    store.record_verdict(claim, verdict, evidence)
    # On analysis failure, use the same claim instead:
    # store.mark_analysis_error(claim, error)
store.recover_expired_claims(now)
```

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

F12 implements `AuditWriter.append_in_transaction(connection, event)` using
the exact `sqlite3.Connection` supplied by F4. The writer records its event in
that transaction; if audit recording fails, the state transition is rolled
back. Persistent audit-adapter integration is a separate F12 delivery; current
F4 proof covers the same-transaction rollback behavior with a recording stub.

## Running devpi-server

Use `--guardian-db` to choose the persistent SQLite path:

```console
devpi-server --guardian-db /var/lib/devpi-guardian/guardian.db
```

If omitted, the plugin uses
`<devpi-server-path>/guardian/guardian.db`. Put the database and its WAL files
on a persistent volume and keep that volume across restarts. The plugin runs
and validates its packaged migration once, before registering enforcement; a
migration failure prevents startup readiness.

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

## F3/F4 completion criteria

- SQLite migration is repeatable on an empty or already initialized database,
  and artifacts, mappings, verdict history, evidence, and overrides survive
  process restart. Persistent F12 audit-adapter integration is separate; F4
  proves same-transaction rollback when audit recording fails.
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
  allow behavior, restart persistence, and `+e` failure handling. The broader
  integration proof verifies 64 concurrent blocked requests (8 workers over 8
  rounds), exact-version pip behavior when an Artifact is allowed or revoked,
  uv direct URL lock/sync behavior, and `%2Bf`/`%2Be` route-marker compatibility
  in resolver tests.
- The plugin-installed in-process block counter records validated bounded
  series with a fixed overflow series; exporting snapshots is an external
  deployment responsibility.
