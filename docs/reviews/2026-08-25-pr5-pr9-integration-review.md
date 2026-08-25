# PR5/PR9 integration review record

Status: **APPROVED**

This record documents the selective integration review for PR5 and PR9. The reviewed
implementation is ready for integration assessment; it has not been pushed or merged by
this task.

## Scope and provenance

- Approved integration base: `3d210395dc806cc0420bda97c6e6e8a8dc1a1883`.
- Selective PR5 source: `22bc029e584af43e6c79b72a3d6fcef35f49f05f`.
- Selective PR9 source: `52593ae444f416625a0e96f0a4874bc30987ce8d`.
- Reviewed implementation head: `105be3415a40aa4cfff3e2c7f71a960c66140505`.

PR5 and PR9 were selectively integrated; their merge histories were not replayed. PR1
activation ordering, immutable verdict and evidence history, claim fencing, and fail-closed
public download enforcement remain the governing contracts.

Existing devpi migration/backfill is not supported. If first-activation inventory finds
Artifact candidates, activation fails closed. Installations are therefore supported only
for new or empty instances until a future offline inventory/backfill process is delivered.
Worker quarantine uses a dedicated absolute `0700` root outside devpi server storage.

## Behavioral and security outcomes

The implementation covers selective activation rollback, including removal of Guardian-owned
runtime state while preserving unrelated plugin state. It keeps direct `+f`/`+e` URL bypasses
blocked, uses the public verdict/store interfaces, and preserves worker shutdown boundaries
and stale-token fencing.

The cached hashless `+e` lifecycle is verified as follows:

1. A stopped-server helper materializes the official cached devpi `FileEntry` with real
   `filestore.maplink(URL(...))` and `file_set_content(..., hashes=Digests(sha256=...))`.
2. After restart, an ordinary Guardian Simple request reaches production
   `GuardianStage` hydration, cross-check, and discovery-sink enqueue. The sink is not called
   directly by the test or a public bypass path.
3. GET/HEAD remain blocked before manual effective `ALLOW`, including after the worker reaches
   a terminal verdict.
4. After manual effective `ALLOW`, real GET/HEAD return the exact cached bytes with status 200.

The original href may be hashless; Artifact identity is determined by the authoritative
cached `FileEntry` SHA. No public URL fragment, filename, or client header bypasses identity
validation.

The privacy boundary sanitizes SQLite evidence before persistence, F11/API responses
(including legacy database rows), and `reason`, `failure_reason`, and `details` fields. It
covers paths, credentials, and non-canonical/composite identity values while preserving only
canonical identity scalars. Baseline selection logging is metadata-free.

Two additional review findings were resolved and reverified:

- Guardian post-link crash residue recovery was verified. Arbitrary hardlinks remain
  fail-closed; recovery performs both parent-directory `fsync` and final `nlink == 1`
  re-verification.
- Expired discovery/analysis claims are recovered on every worker cycle. Failed work is
  retried, while the shutdown boundary and stale-token fencing remain enforced.

## Final reviewers

- Specification/security reviewer `/root/final_spec_review_747caaf`: exact head
  `105be3415a40aa4cfff3e2c7f71a960c66140505`, **APPROVED** — Critical 0, Important 0,
  Minor 0.
- Code-quality reviewer `/root/final_quality_review_747caaf`: exact head
  `105be3415a40aa4cfff3e2c7f71a960c66140505`, **APPROVED** — Critical 0, Important 0,
  Minor 0.

Direct reviewer evidence was summarized from the final passes: quality review covered 173
focused tests plus explicit crash/runtime reproduction; specification review covered 295
focused tests, 183 worker tests, 3 real-devpi worker integration tests, and 502 F3, `+e`,
activation, and privacy regression tests.

## Controller verification at the reviewed implementation head

The controller independently reported:

```text
Python 3.11: 2079 passed, 5 warnings
Python 3.12: 2079 passed, 9 warnings
Python 3.13: 2079 passed, 7 warnings
Python 3.14: 2079 passed, 7 warnings
Ruff format: 148 files already formatted
Ruff lint: pass
Flake8: pass
uv lock --check: pass
uv build: sdist and wheel produced
git diff --check base...HEAD: pass
Worktree: clean
```

Final disposition: **Critical 0 / Important 0 / Minor 0**. The implementation is ready for
integration assessment. This review record does not claim that any branch was pushed or
merged.
