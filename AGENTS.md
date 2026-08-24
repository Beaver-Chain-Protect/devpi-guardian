# devpi-guardian Agent Operating Rules

This file applies to the entire repository.

## Authoritative inputs

- Approved design: `docs/superpowers/specs/2026-08-17-devpi-guardian-f3-f4-design.md`
- F1/F2 design: `docs/superpowers/specs/2026-08-20-f1-f2-guardian-index-simple-filter.md`
- Approved baseline-tier extension:
  `docs/superpowers/specs/2026-08-21-verdict-baseline-tier-design.md`
- Execution plan: `docs/superpowers/plans/2026-08-17-f3-f4-enforcement-verdict-store.md`
- The baseline-tier extension takes precedence only for the `baseline_tier` contract.
- If code, plan, and design disagree, stop implementation and resolve the disagreement before proceeding.

## Agent roles

- The controller and integration reviewer use `gpt-5.6-sol` for architecture decisions,
  security-sensitive behavior, concurrency, devpi integration, and final acceptance.
- Bounded implementation tasks with an explicit specification are assigned to fresh
  `gpt-5.6-luna` subagents.
- Luna implementers must not make new architecture decisions. They report
  `NEEDS_CONTEXT` or `BLOCKED` when the supplied task requires one.
- Sol reviews every Luna result against the approved design and implementation plan
  before it is integrated.
- Do not run multiple implementation agents concurrently. The SQLite schema, public
  interfaces, store, resolver, tween, and plugin are sequentially dependent.

## Required implementation workflow

1. Work only in an isolated worktree under `.worktrees/`; do not implement on `main`.
2. Execute one numbered plan task at a time.
3. Follow strict red-green-refactor TDD: add a focused failing test, observe the expected
   failure, add the minimum production code, and rerun the relevant tests.
4. The Luna implementer commits the completed task and reports tests, changed files,
   self-review findings, and concerns.
5. A Sol reviewer first performs specification-compliance review by inspecting the code.
6. Only after specification review passes, a Sol reviewer performs code-quality review.
7. Fix every Critical or Important finding and repeat the corresponding review before
   starting the next task.
8. The Sol controller independently checks the diff and runs the relevant tests before
   accepting each task.
9. After all tasks, run the full unit and integration test matrix, lint checks, package
   build, and a final Sol review against every completion criterion.

## Engineering constraints

- F3 is fail-closed: only an effective `ALLOW` may reach the devpi release-file handler.
- F2 and F3 must use the same `VerdictReader`; do not duplicate decision SQL or precedence.
- Other components use the public `VerdictReader` and `ArtifactStore` interfaces and must
  not access Guardian SQLite tables directly.
- Preserve immutable verdict, evidence, override, and audit history.
- All write transitions and audit recording use one SQLite transaction.
- Do not create worker bypass tokens or trust URL fragments, filenames, or client headers
  as Artifact identity.
- Keep changes within the assigned feature scope. F1/F2 may extend plugin bootstrap only
  as required to share the already initialized `VerdictReader` with `GuardianStage`.

## Quality commands

Use the project environment after bootstrap:

```bash
uv run pytest -v
uv run ruff format --check .
uv run ruff check .
uv run flake8 src tests
uv build
```

Never claim a task passes from an agent report alone. Run fresh verification and inspect
the output before accepting or integrating it.
