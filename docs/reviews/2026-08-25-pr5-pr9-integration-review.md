# PR5/PR9 safe integration review draft

Status: factual draft pending the final fresh specification and security/code-quality
reviews. This file intentionally does not claim reviewer approval or invent reviewer
identities.

## Scope and provenance

- Approved integration base: `3d210395dc806cc0420bda97c6e6e8a8dc1a1883` (PR1 merge).
- Selective PR5 source: `22bc029e584af43e6c79b72a3d6fcef35f49f05f`.
- Selective PR9 source: `52593ae444f416625a0e96f0a4874bc30987ce8d`.
- Current implementation head: `<PENDING FINAL INTEGRATION COMMIT AND FRESH REVIEW>`.
- Final specification reviewer: `<PENDING — identity and result not yet recorded>`.
- Final security/code-quality reviewer: `<PENDING — identity and result not yet recorded>`.

PR5 and PR9 were selectively integrated; their merge histories were not replayed. PR1
activation ordering, CI documentation, immutable verdict history, claim fencing, and
fail-closed public download enforcement remain the governing contracts.

Existing devpi instances with Artifact candidates remain unsupported until a future offline
inventory/backfill process is delivered. The worker quarantine is a dedicated absolute
`0700` root outside devpi server storage.

## Task 8 evidence recorded before final review

The real-devpi integration proof was first run RED. The initial assertion failed because the
fixture had no cache-entry materialization operation; this was observed before the fixture
helper was added. Subsequent RED runs exposed the subprocess module path and then the expected
devpi project metadata mismatch; both were corrected by wiring the repository path into the
helper environment and using devpi's normalized project name. The focused run then passed:

```text
uv run pytest tests/integration/test_worker_runtime.py -q -m integration
3 passed, 4 warnings
```

The passing proofs observe private upload CAS publication, exact CAS bytes and path, terminal
Artifact state, protected `+f` and `.metadata` GET/HEAD, and release only after a manual
effective `ALLOW`. The new `+e` proof first blocks GET/HEAD on the real hashless mirror route,
stops the already-activated server, fetches the fixture's upstream bytes, and commits them
through devpi's `MutableFileEntry.file_set_content(..., hashes=...)` KeyFS cache transaction.
After restart, the durable discovery sink consumes a canonical SHA-bearing link for that same
`+e` relpath; terminal verdict remains blocked until effective ALLOW, after which real GET/HEAD
reach devpi's handler. This is operationally valid because it reproduces devpi's official
post-fetch cache commit after activation, without rewriting route strings or weakening identity
checks. The existing hashed mirror proof remains and observes the production internal stage
client fetch upstream bytes; the public Guardian route is not used as the worker source.

The complete acceptance matrix, final implementation head, reviewer identities, reviewer
results, and resolved finding disposition must be filled in by the final controller after
the fresh review pass. No Critical/Important count is asserted here pending those reviews.
