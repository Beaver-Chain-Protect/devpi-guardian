# README PR Publish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a concise implemented-feature summary and three-level repository tree to README, then publish the verified feature branch as a draft GitHub PR.

**Architecture:** Preserve every existing handoff, operations, security, performance, and completion section. Insert two reader-oriented sections immediately after the introduction, using only facts verified by the current source tree and approved F3/F4 design. Publish the existing feature branch without rebasing or rewriting its reviewed history.

**Tech Stack:** Markdown, Git, GitHub CLI, pytest, Ruff, Flake8, uv

---

### Task 1: Add README feature and structure summaries

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Verify the documented paths and features exist**

Run:

```bash
test -d src/devpi_guardian/enforcement
test -d src/devpi_guardian/verdicts
test -d tests/enforcement
test -d tests/verdicts
test -d tests/integration
test -d docs/superpowers/specs
test -d docs/superpowers/plans
test -f src/devpi_guardian/plugin.py
test -f src/devpi_guardian/enforcement/metrics.py
test -f src/devpi_guardian/verdicts/store.py
```

Expected: exit 0.

- [ ] **Step 2: Add the implemented feature summary**

Insert `## Implemented features` after the approved-design link. Cover exactly:

```markdown
- Fail-closed direct release enforcement for `+f`, `+e`, `GET`, `HEAD`, and PEP 658 `.metadata` requests.
- SHA-256-keyed SQLite verdict persistence with migrations, bounded reads, immutable verdict/evidence history, claim fencing, lease recovery, and fail-closed corruption handling.
- Automated verdict completion plus audited manual `ALLOW`/`DENY`, revoke, expiry, and rescan transitions.
- devpi-server plugin registration, sanitized structured block logs, and a bounded in-process block metric counter.
- Real devpi subprocess and official `pytest-devpi-server` integration coverage for pip, uv, restarts, concurrency, direct URLs, and hashless mirror identity failures.
```

Do not claim that the separate F12 persistent audit adapter is implemented.

- [ ] **Step 3: Add the three-level repository tree**

Insert `## Repository structure` after the feature list. Use this concise structure and add a one-sentence introduction:

```text
.
├── src/devpi_guardian/
│   ├── enforcement/        # direct-route identity resolution, tween, metrics
│   ├── verdicts/           # models, SQLite schema, reader, store, invariants
│   └── plugin.py           # devpi-server hooks and Pyramid registration
├── tests/
│   ├── enforcement/        # resolver, tween, and metric tests
│   ├── verdicts/           # persistence, transitions, corruption, concurrency
│   └── integration/        # real devpi, pip/uv, restart, direct-route tests
├── docs/superpowers/
│   ├── specs/              # approved designs and corrections
│   └── plans/              # executable implementation plans
├── news/                   # release-note fragments
├── pyproject.toml          # package, plugin entry point, dependencies, tooling
└── uv.lock                 # reproducible dependency lock
```

- [ ] **Step 4: Verify README accuracy and formatting**

Run:

```bash
rg -n "^## (Implemented features|Repository structure|F3/F4 handoff)" README.md
git diff --check
uv run ruff format --check .
uv run ruff check .
uv run flake8 src tests
```

Expected: all commands exit 0; the three headings appear once and in that order.

- [ ] **Step 5: Commit the README change**

```bash
git add README.md
git commit -m "docs: summarize repository and features"
```

### Task 2: Review and publish the branch

**Files:**
- Review: `README.md`
- Review: complete `main...HEAD` diff

- [ ] **Step 1: Run final verification**

```bash
uv run pytest -q
uv run pytest tests/integration -q -m integration
uv run pytest -m performance -s -v
uv run ruff format --check .
uv run ruff check .
uv run flake8 src tests
uv lock --check
uv build
git diff --check
git status --short
```

Expected: 801 or more tests pass, 13 or more integration tests pass, P95 is below 100 ms, all quality/build checks pass, and the worktree is clean.

- [ ] **Step 2: Confirm GitHub target and authentication**

```bash
gh auth status
git remote get-url origin
gh repo view Beaver-Context-Protocol/devpi-guardian --json defaultBranchRef,nameWithOwner
```

Expected: authenticated GitHub session, target repository `Beaver-Context-Protocol/devpi-guardian`, and a resolved default branch.

- [ ] **Step 3: Push without rewriting history**

```bash
git push -u origin feature/f3-f4-enforcement-store
```

Expected: the remote tracking branch is created or updated without force push.

- [ ] **Step 4: Open a draft PR**

Create a draft PR whose title summarizes F3/F4 enforcement and verdict persistence. Its body must describe implemented behavior, security/operational impact, handoff documentation, and the exact verification matrix. Target the repository's default branch.

- [ ] **Step 5: Report the published result**

Report the branch, final commit, PR URL, base branch, validation results, and any remaining third-party warnings.
