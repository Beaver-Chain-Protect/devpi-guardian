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

The new real-devpi integration proof was first run RED. The initial mirror assertion timed
out because a hashless `+e` mirror link cannot enter the SHA-256 discovery queue; this was
observed before fixture/runtime edits. The final focused run then passed:

```text
uv run pytest tests/integration/test_worker_runtime.py -q -m integration
2 passed, 4 warnings
```

The passing proof observes private upload CAS publication, exact CAS bytes and path,
terminal Artifact state, protected `+f` and `.metadata` GET/HEAD, and release only after a
manual effective `ALLOW`. It also calls the real hashless mirror `+e` route before worker
discovery, then enqueues a validated mirror candidate through the durable discovery sink and
observes the production internal stage client fetch the upstream artifact bytes. The public
mirror route is not used as the worker source.

The complete acceptance matrix, final implementation head, reviewer identities, reviewer
results, and resolved finding disposition must be filled in by the final controller after
the fresh review pass. No Critical/Important count is asserted here pending those reviews.
