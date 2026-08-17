# devpi-guardian

devpi-guardian is a devpi-server plugin that exposes a release file only when its
verified Artifact SHA-256 has a valid effective `ALLOW` verdict. The enforcement
path is fail-closed: an unknown Artifact, an in-progress analysis, a denied or
errored analysis, an identity lookup failure, and a verdict-store failure never
reach the devpi file handler.

The approved F3/F4 design is in
docs/superpowers/specs/2026-08-17-devpi-guardian-f3-f4-design.md.

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

F5 receives the same factory plus its F12 writer and constructs the public
store; it does not query Guardian tables directly:

```python
from devpi_guardian.verdicts.store import SQLiteArtifactStore

# audit_writer is an injected F12 implementation of AuditWriter.
store = SQLiteArtifactStore(factory, audit_writer)
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
back.

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

- Use one process to run `migrate` before readiness. Each process and thread
  obtains its own `ConnectionFactory.connect()` SQLite connection; connections
  are not shared across threads or processes.
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
include `identity_unavailable`, `store_unavailable`, and `not_allowed`.
Allowed requests do not increment the counter, and URL credentials, filenames,
and query secrets are not dimensions.

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
  and artifacts, mappings, verdict history, evidence, overrides, and audit data
  survive process restart.
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
- Integration coverage verifies verdict and override persistence across a
  devpi restart, 64 concurrent blocked requests (8 workers over 8 rounds),
  exact-version pip behavior when an Artifact is allowed or revoked, uv direct
  URL lock/sync behavior, and `%2Bf`/`%2Be` route-marker compatibility in the
  resolver tests.
- The plugin-installed in-process block counter records only blocked requests
  with the four bounded dimensions above; exporting those snapshots is an
  external deployment responsibility.
