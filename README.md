# devpi-guardian

devpi-guardian is a devpi-server plugin that exposes a release file only when its
verified Artifact SHA-256 has a valid effective `ALLOW` verdict. The enforcement
path is fail-closed: an unknown Artifact, an in-progress analysis, a denied or
errored analysis, an identity lookup failure, and a verdict-store failure never
reach the devpi file handler.

The approved F3/F4 design is in
docs/superpowers/specs/2026-08-17-devpi-guardian-f3-f4-design.md.

## F3/F4 integration contract

F2 and the direct-download tween use the same `VerdictReader`; callers do not
query Guardian SQLite tables directly.

```python
from devpi_guardian.verdicts.interfaces import ArtifactStore, VerdictReader

decision = verdict_reader.get_effective_decision(sha256)
decisions = verdict_reader.get_effective_decisions(sha256s)
```

`SQLiteVerdictReader` returns an `EnforcementDecision` with `sha256`,
`allowed`, `effective_decision`, `source`, `artifact_state`, and
`policy_version`. A missing SHA-256 is a normal `allowed=False` result with
`source=MISSING`; connection, lock, malformed-database, and persisted-state
failures raise `StoreUnavailable` instead.

Workers and administrative callers use `ArtifactStore`:

```python
claim = store.claim_next(worker_id, lease_until)
if claim is not None:
    # Pass the complete ClaimedArtifact, including lease_token, unchanged.
    store.record_verdict(claim, verdict, evidence)
    # Or, if analysis fails: store.mark_analysis_error(claim, error)

store.recover_expired_claims(now)
```

`claim_next` atomically changes `DISCOVERED` to `SCANNING` and returns a
`ClaimedArtifact` containing `sha256`, `size_bytes`, `worker_id`,
`lease_expires_at`, and a canonical `lease_token`. The token is an opaque
64-character lowercase hexadecimal value, is hidden from the DTO repr, and is
required for `record_verdict` and `mark_analysis_error`; an expired or changed
claim returns `TransitionConflict` rather than recording a result.

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

The F12 adapter implements
`AuditWriter.append_in_transaction(connection, event)` using the exact SQLite
connection supplied by F4. If audit recording fails, the state transition is
rolled back.

## Running devpi-server

Use `--guardian-db` to choose the persistent SQLite path:

```console
devpi-server --guardian-db /var/lib/devpi-guardian/guardian.db
```

If omitted, the plugin uses
`<devpi-server-path>/guardian/guardian.db`. Put the database and its WAL files
on a persistent volume and keep that volume across restarts. The plugin runs
and validates its packaged migration before registering enforcement; a
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
  SQLite states to `StoreUnavailable`. A fresh-store 1,000-lookup performance
  test records P95 below 100 ms and is marked `performance`.
- Only an effective `ALLOW` release file reaches the devpi handler for `+f`,
  `+e`, `GET`, `HEAD`, and `.metadata`; direct URLs cannot bypass the reader.
