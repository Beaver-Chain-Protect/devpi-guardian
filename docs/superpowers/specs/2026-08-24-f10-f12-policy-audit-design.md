# F10/F12 policy and audit design

Date: 2026-08-24

Status: approved for the `feature/f10-f12-policy-audit` branch.

## Scope and existing contracts

F10 implements the existing `PolicyEngine.evaluate(target, report) -> VerdictInput`
port. It never writes SQLite and never converts findings to `EvidenceInput`; the F5
pipeline already owns both responsibilities.

F12 implements the existing
`AuditWriter.append_in_transaction(connection, event) -> None` port. It uses only the
connection supplied by F4. It must not open, begin, commit, roll back, or close a
connection. An audit failure aborts the surrounding F4 state transition.

## F10 policy

### Input validation

The policy rejects structurally impossible reports with `PolicyInputError`. F5 records
that failure as an `ERROR`, so malformed input cannot become an automatic `ALLOW`.

- A report contains exactly one F7, F8, and F9 step.
- Step names and statuses use their declared closed sets.
- A selected baseline has a canonical SHA-256 and one of `same_tag`,
  `universal_wheel`, or `sdist`; an absent baseline has neither value.
- F8 cannot be skipped. A selected baseline cannot have a skipped F7 step.
- A skipped analyzer cannot contribute evidence.
- Finding actions are exactly `REVIEW` or `DENY`. Unknown rule identifiers remain
  forward-compatible and retain their declared severity.
- F7 evidence carries the same baseline tier as the report. F8/F9 evidence does not
  claim a baseline tier.

### Decision precedence

Precedence is deterministic and independent of evidence order:

1. Any effective `DENY` finding produces `DENY`.
2. Otherwise, a `REVIEW` finding, analyzer error, or required coverage gap produces
   `REVIEW`.
3. Only a clean report with the configured coverage produces `ALLOW`.

The secure default requires a trusted baseline and an sdist-wheel pair. A first release
or unpaired release is therefore held for review. Deployments may explicitly relax each
coverage requirement, but configuration can never downgrade a `DENY` finding.

### Score and explanation

`score` is an operator triage score in the inclusive range 0--100, not a probability and
not a decision threshold. Multiple conditions take the maximum rather than summing, so
duplicating findings cannot inflate the result.

- clean `ALLOW`: 0
- ordinary `REVIEW`: 50
- missing F9 pair: at least 60
- missing baseline: at least 70
- analyzer error: at least 90
- `DENY`: 100

For an F7 review finding, weaker baseline comparability raises operator attention:
`same_tag=50`, `universal_wheel=60`, and `sdist=70`.

These are the `PolicyConfig` defaults. Custom configuration may only raise the
review, coverage, and analyzer-error floors while preserving precedence and
tier ordering; `score_allow=0` and `score_deny=100` remain anchored.

`assess()` returns a frozen assessment with sorted stable reason codes. `evaluate()`
wraps that assessment in the existing `VerdictInput` without changing the worker port.

### Policy identity

Configuration is immutable and loaded once. Canonical JSON includes the policy name,
revision, algorithm version, coverage flags, score constants, tier scores, and any rule
escalations. `policy_version` stores the full digest:

`<name>/<revision>+sha256:<64 lowercase hex characters>`

A changed policy produces a new automatic verdict through rescan; existing verdict and
audit history is never rewritten.

## F12 audit log

### Persistence and atomicity

Migration 004 creates `audit_events`. Each event stores the existing F4 contract:
actor, action, artifact SHA-256, previous and new effective decisions, reason, policy
version, analyzer version, and UTC occurrence time.

Events are append-only. Database triggers reject update and delete. The writer validates
the DTO, derives the next sequence number, computes a canonical event hash, inserts one
row with parameterized SQL, and returns without touching the surrounding transaction.

### Hash chain

Each row contains `previous_hash` and `event_hash`. The event hash is SHA-256 over the
previous hash and canonical UTF-8 JSON containing every persisted semantic field plus
the event/canonicalization versions and sequence number. F4 already uses
`BEGIN IMMEDIATE`, so concurrent writers serialize one chain head.

A verifier reports the first invalid event and supports an optional expected head hash.
The chain is tamper-evident, not tamper-proof: without an external signed anchor, an
administrator who can replace the database can recompute the complete chain, and tail
deletion is detectable only when an expected head is supplied.

### Data minimization

The audit event does not include request bodies, credentials, lease tokens, artifact
snippets, or origin URLs. Free-text fields must be nonblank, bounded, valid strings, and
must not contain NUL/control characters. Initial retention is the database lifetime;
in-place deletion would violate the append-only contract.

### Runtime wiring

After migration and chain verification, the devpi plugin creates one
`SQLiteAuditWriter` and one `SQLiteArtifactStore`, then supplies that store to F11's
`GuardianAdminService`. Readiness exposes mutations only when transactional audit is
available. External F5 workers independently construct the same writer with their store
after the migration owner is ready.

## Acceptance criteria

- F10 precedence, secure coverage, scoring, configuration digest, malformed-report
  rejection, input-order invariance, and exact DTO propagation are unit tested.
- Migration 004 is repeatable and upgrades a version-3 database without losing data.
- Every F4 lifecycle and administrator transition persists the specified audit fields.
- Audit insert and business state commit or roll back together.
- Audit update/delete and a forked chain head are rejected.
- Chain verification detects modified, missing-middle, and reordered events; an expected
  head detects tail deletion.
- Concurrent transactions produce one linear chain.
- F11 mutations become ready only with the persistent writer and create audit rows.
- Full tests, lint, formatting, lock verification, and package build pass, except for a
  separately documented pre-existing environment failure if reproducible from the base
  commit.
