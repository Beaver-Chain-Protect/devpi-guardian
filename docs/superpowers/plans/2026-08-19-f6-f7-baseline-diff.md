# F6·F7 Trusted Baseline and Baseline-Diff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Pick the most comparable approved release for a new Artifact and report only the security evidence that release did not already carry.

**Architecture:** F6 walks a tier-first priority chain over the releases F4 has approved and returns one baseline selection. F7 extracts both artifacts with F8's hardened archive reader, compares them by path and bytes, and runs F8's own judgement functions on the added and changed files only. Evidence the baseline version already carried is subtracted and recorded rather than reported. Two injected protocols keep F4 access and artifact download out of the analysis code.

**Tech Stack:** Python 3.11–3.14, devpi-server 6.20.3, packaging, stdlib zipfile/tarfile/hashlib, an injected HTTP session, pytest, Ruff, Flake8, uv

> **Retrospective record:** This plan was written after the implementation
> landed. Every task below is complete and its tests pass. It is kept in the
> plan format so the decision order stays reviewable and so later work on
> `baseline/` follows the same task boundaries.

> **2026-08-18 diff-not-rescan correction:** A changed file is analyzed in
> full, but evidence the baseline version already carried is suppressed and
> recorded in `carried_flows`/`carried_evidence` instead of being reported.
> Without this, an unrelated comment above a credential flow resurfaces
> already-approved evidence, and an untouched file and a comment-only edit of
> the same file disagree about the same evidence. Identity for the subtraction
> excludes line numbers, because lines move whenever anything above them
> changes. This correction supersedes Task 4 snippets that report every flow
> found in a changed file.

> **2026-08-18 tag fail-closed correction:** A candidate wheel whose filename
> does not parse into a compatibility tag is an explicit "not a universal
> wheel" verdict and is rejected from every wheel tier. It must never become
> "cannot tell, so skip the check and pass". `acme-py3-none-any.whl` and
> `acme-1.9.0-1-extra-py3-none-any.whl` end in a universal tag but are not
> readable wheel names, and both must be rejected.

> **2026-08-19 entry-point axis correction:** `entry_points.txt` lives inside
> `.dist-info`, which the file comparison excludes, and the directory name
> carries the version, so path-based comparison splits the same logical file
> into `added` + `removed` on every release. Entry points are therefore
> compared as parsed sets via F9's `_collect_entry_points`, leaving the
> `.dist-info` exclusion untouched. This correction supersedes Task 5 snippets
> that only diff file paths.

> **2026-08-19 download-filename correction:** The temporary file a baseline
> download writes must keep the archive suffix from its origin URL.
> `analyzers.archive.extract_artifact` decides zip versus tar from the
> filename, so a file named only by its digest is rejected as an unsupported
> format and the whole diff silently reports no changed files.

## Source design

Implement against docs/superpowers/specs/2026-08-19-devpi-guardian-f6-f7-design.md. If this plan and that design disagree, stop and update the plan before changing code.

## Locked file structure

~~~text
devpi-guardian/
├── pyproject.toml
├── README.md
├── .flake8
├── news/
│   └── 3.feature
├── src/devpi_guardian/
│   ├── analyzers/          (F8·F9, unchanged by this plan)
│   ├── verdicts/           (F3·F4, unchanged by this plan)
│   └── baseline/
│       ├── __init__.py
│       ├── selection.py
│       ├── diff.py
│       ├── release_lookup.py
│       └── artifact_source.py
├── tests/
│   └── baseline/
│       ├── __init__.py
│       ├── fakes.py
│       ├── artifacts.py
│       ├── store_seed.py
│       ├── test_selection.py
│       ├── test_diff.py
│       ├── test_release_lookup.py
│       ├── test_artifact_source.py
│       └── test_wiring.py
└── docs/superpowers/
    ├── specs/2026-08-19-devpi-guardian-f6-f7-design.md
    └── plans/2026-08-19-f6-f7-baseline-diff.md
~~~

Each production module has one responsibility: selection ranks approved releases, diff compares two artifacts and applies F8's judgement to the difference, release_lookup adapts F4's reader, and artifact_source fetches and verifies baseline bytes. Only release_lookup imports `verdicts`; selection and diff stay free of devpi-server imports, like the analyzers.

### Task 1: Define the F6 priority chain over injected protocols

**Files:**
- Create: src/devpi_guardian/baseline/selection.py
- Create: tests/baseline/fakes.py
- Create: tests/baseline/test_selection.py

- [x] **Step 1: Declare the two integration protocols**

F4's release query and the artifact byte source are owned by other features.
Express them as protocols so selection never assumes an implementation:

~~~python
@runtime_checkable
class ReleaseLookup(Protocol):
    def allowed_releases(self, project: str) -> list[ReleaseRecord]: ...


@runtime_checkable
class ArtifactBytesSource(Protocol):
    def open(self, sha256: str) -> Path: ...
~~~

`ReleaseRecord` carries only what selection needs: project, version, filename,
sha256. Building one from an F4 row is the caller's job.

- [x] **Step 2: Write failing tests for filename classification**

Cover `artifact_kind` for `.whl`, every sdist suffix, and unknown extensions;
cover `parse_wheel_tag` for 5-part and 6-part (build-numbered) names,
compressed tags such as `py2.py3-none-any`, and names that must return `None`.

- [x] **Step 3: Implement the chain, tier before version**

Search each tier across every eligible older version before moving to the next
tier, so an exact tag match at 0.0.1 beats a universal wheel at 8.9.0. Within a
tier take the highest version below the target, and break ties on the lowest
filename so lookup ordering cannot change the answer.

An sdist target carries no tag: use the sdist tier only. A wheel target whose
tag will not parse skips the exact-tag tier and keeps the other two.

- [x] **Step 4: Make an unreadable candidate tag fail closed**

~~~python
    candidate_tag = parse_wheel_tag(candidate.filename)
    if candidate_tag is None:
        # Fail closed. An unreadable tag is not evidence that the candidate is
        # a universal wheel, nor that it matches the target tag, so it is
        # rejected from every wheel tier. This is a decision, not a skipped
        # check: an unclassifiable wheel must never reach a tier by default.
        return False
~~~

Test that the candidate clears every eligibility filter first, so the tier
verdict is provably the only reason it was rejected.

- [x] **Step 5: Filter candidates by PEP 440 order**

Prereleases below the target stay eligible. Versions `packaging` cannot parse
have no order against the target and are dropped with a `logging.DEBUG`
reason. The target's own digest is never its own baseline.

- [x] **Step 6: Run the selection tests**

Run: uv run pytest tests/baseline/test_selection.py -v

Expected: PASS.

- [x] **Step 7: Commit the selection chain**

~~~bash
git add src/devpi_guardian/baseline/selection.py tests/baseline
git commit -m "feat: select the trusted baseline release for an artifact"
~~~

### Task 2: Compare two artifacts by path and bytes

**Files:**
- Create: src/devpi_guardian/baseline/diff.py
- Create: tests/baseline/artifacts.py
- Create: tests/baseline/test_diff.py

- [x] **Step 1: Extract both artifacts with F8's reader**

Use `analyzers.archive.extract_artifact`. Its own findings
(`archive_unsafe_member`, `archive_bomb`) are surfaced with the
`diff_artifact` origin, and an unusable extraction ends the comparison.

- [x] **Step 2: Normalize paths with F9's helpers**

Reuse `_strip_sdist_prefix`, `_wheel_paths`, and `_ignored` rather than
restating them, so F7 and F9 cannot drift apart on `pkg-1.0/`, `src/`, or the
metadata exclusion list. An sdist baseline and a wheel target are comparable
because of this.

- [x] **Step 3: Classify added, changed, removed, unchanged**

Compare SHA-256 of file contents. Archive member timestamps are never read, so
a different mtime cannot look like a change. An unreadable member is treated as
changed and analyzed, never as identical.

- [x] **Step 4: Run the file-comparison tests**

Run: uv run pytest tests/baseline/test_diff.py -v

Expected: PASS.

### Task 3: Apply F8's judgement to the difference only

**Files:**
- Modify: src/devpi_guardian/baseline/diff.py
- Modify: tests/baseline/test_diff.py

- [x] **Step 1: Declare F7's own rules with F9's actions**

~~~python
DIFF_RULES: dict[str, Rule] = {
    "baseline_new_credential_network": Rule("DENY", ...),
    "baseline_new_risky_python": Rule("DENY", ...),
    "baseline_new_executable_pth": Rule("DENY", ...),
    "baseline_new_native": Rule("REVIEW", ...),
    "baseline_new_entry_point": Rule("REVIEW", ...),
}
~~~

Reusing a `wheel_only_*` rule id would show operators a message about
sdist/wheel skew for a finding that has nothing to do with it. Error reporting
still uses F8's shared `ast_parse_failed`, `analysis_limit_exceeded`, and
`analyzer_error`. Pin the action equality to the `wheel_only_*` rules in a test.

- [x] **Step 2: Run F8's analyses on added and changed Python files**

Call `find_credential_network_flows` and `scan_calls`; do not write new
judgement logic. Skip a call already reported as a credential-flow sink, the
same way `sdist_wheel._wheel_only_python_findings` does.

- [x] **Step 3: Judge `.pth` and native additions**

Use `sdist_wheel._executable_pth_lines` for startup-executing lines. Report a
native binary only when the baseline had none: a rebuilt binary differs on
every release, so reporting changed ones marks every native release for review
without saying anything.

- [x] **Step 4: Subtract what the baseline already carried**

Identity excludes line numbers:

~~~python
def _flow_key(flow: CredentialFlow) -> tuple[str, str, str]:
    return (flow.source.description, flow.sink.qualified_name, flow.sink.snippet)
~~~

Keeping `snippet` means the same credential sent to a different URL is a new
finding. If the baseline version cannot be read or parsed, subtract nothing and
report everything.

- [x] **Step 5: Mark every finding with its origin**

`Finding` is frozen and must not grow a field, so return
`list[tuple[Finding, Origin]]`. Pin the field list of `Finding` in a test so a
later change cannot quietly extend it.

- [x] **Step 6: Collect new imports and calls as context only**

`NewSurface` is never a verdict. For a changed file report only what the file
added relative to its baseline version.

- [x] **Step 7: Run the judgement tests**

Run: uv run pytest tests/baseline/test_diff.py -v

Expected: PASS.

- [x] **Step 8: Mutation-check the core property**

Force every unchanged file to be treated as changed and confirm the suite
fails; force all changed-file evidence to be suppressed and confirm it fails
again. F7 has no value if either direction passes silently.

### Task 4: Compare entry points as parsed sets

**Files:**
- Modify: src/devpi_guardian/baseline/diff.py
- Modify: tests/baseline/test_diff.py

- [x] **Step 1: Keep the unfiltered path maps**

The file comparison still drops `.dist-info`; entry point parsing needs what is
inside it. Keep both maps rather than weakening `_ignored`.

- [x] **Step 2: Diff the parsed sets**

`_collect_entry_points` reads `entry_points.txt`, `setup.cfg`,
`pyproject.toml`, and `setup.py` into one canonical set, which is independent
of the versioned `.dist-info` directory name and bridges sdist to wheel.
Report entries present only in the artifact; record shared entries as carried.

- [x] **Step 3: Prove the exclusion rule still holds**

Add a regression test placing a hostile `.py` inside `.dist-info` and assert it
is still absent from `files.added` and produces no finding.

- [x] **Step 4: Run the entry point tests**

Run: uv run pytest tests/baseline/test_diff.py -v

Expected: PASS.

### Task 5: Adapt F4's reader to the F6 protocol

**Files:**
- Create: src/devpi_guardian/baseline/release_lookup.py
- Create: tests/baseline/store_seed.py
- Create: tests/baseline/test_release_lookup.py

- [x] **Step 1: Inject the reader, do not construct it**

Per the F4 README a consumer takes the reader from the Pyramid registry:

~~~python
from devpi_guardian.enforcement.tween import VERDICT_READER_REGISTRY_KEY

reader = pyramid_config.registry[VERDICT_READER_REGISTRY_KEY]
lookup = VerdictReaderReleaseLookup(reader)
~~~

Require only `list_allowed_releases`. Baseline selection never asks for an
enforcement decision and should not demand an object that can give one.

- [x] **Step 2: Let store failures propagate**

`StoreUnavailable` must reach `compare_release_to_baseline`, which turns it
into an `analyzer_error`. Returning an empty list would make an unreachable
verdict store indistinguishable from a project's first release.

- [x] **Step 3: Remember origin URLs**

`ArtifactBytesSource.open` receives a digest and nothing else, while the URL
lives on `AllowedRelease.origin_url`. Record it while converting, and expose
`origin_url(sha256)` so a byte source can resolve one without a second query.
Raise rather than guess for a digest the lookup never returned.

- [x] **Step 4: Seed a real database in the tests**

Build the store with F4's own `ConnectionFactory` and `migrate`, seeded the way
tests/verdicts/test_reader.py seeds it. Do not fake the query.

- [x] **Step 5: Run the lookup tests**

Run: uv run pytest tests/baseline/test_release_lookup.py -v

Expected: PASS.

### Task 6: Download and verify baseline artifacts

**Files:**
- Create: src/devpi_guardian/baseline/artifact_source.py
- Create: tests/baseline/test_artifact_source.py

- [x] **Step 1: Inject the HTTP session and know nothing about authentication**

Pass only `url`, `stream`, and `timeout` to the session. Whether it carries a
bearer token, a cookie jar, or a client certificate is the session's business.
When F5 settles on a scheme, only the wiring that builds the session changes.
Pin this with tests that pass differently-authenticated sessions and assert the
exact kwargs.

- [x] **Step 2: Verify the digest, fail closed**

Hash while streaming; on mismatch remove the partial file and raise. F4 records
`origin_url` but never fetches or rehashes it, so this is the only thing
between a tampered response and a diff against the wrong bytes.

- [x] **Step 3: Restrict the scheme**

F4's sanitizer strips userinfo, query, and fragment but does not constrain the
scheme, and its README forbids using `origin_url` as a trust bypass or a local
open. Accept `http` and `https` only.

- [x] **Step 4: Keep the archive suffix on the temporary file**

~~~python
def _local_name(digest: str, url: str) -> str:
    candidate = PurePosixPath(urlsplit(url).path).name
    safe = "".join(c for c in candidate if c.isalnum() or c in "._-").lstrip(".")
    return f"{digest}-{safe}" if safe else digest
~~~

Add a test that feeds the downloaded path straight to `extract_artifact`.

- [x] **Step 5: Normalize every transport failure**

4xx/5xx, connection refusal, timeout, and TLS errors all become one
`ArtifactDownloadError` with the original exception chained, so callers never
need to know which HTTP library is in use. Own the temporary directory as a
context manager.

- [x] **Step 6: Test without the network**

Use fake sessions for the protocol and failure paths, and a loopback
`http.server` for one real `requests.Session` pass.

- [x] **Step 7: Run the byte source tests**

Run: uv run pytest tests/baseline/test_artifact_source.py -v

Expected: PASS.

### Task 7: Join F6 and F7 in one orchestration entry point

**Files:**
- Modify: src/devpi_guardian/baseline/diff.py
- Create: tests/baseline/test_wiring.py

- [x] **Step 1: Distinguish first release from failure**

A project whose first release is being scanned has nothing approved to compare
against: skip F7, return `has_baseline=False`, and emit no finding. A baseline
that was selected but could not be read is `has_baseline=True` plus an
`analyzer_error`, so a broken filestore is never mistaken for a first release.
A failing F4 query is also reported, never raised.

- [x] **Step 2: Carry the baseline digest to the verdict store**

`baseline_sha256` is what F5 puts into `VerdictInput.baseline_sha256`, so "no
baseline" travels as `None` rather than as a silently skipped step.

- [x] **Step 3: Document the F10 hand-off**

`selection.tier` says how comparable the baseline was and nothing downstream
pulls it automatically: `VerdictInput` has no tier field and the pairs in
`findings` carry only `Origin`. State in the docstring that F10 must put
`selection.tier` and the origin into `EvidenceInput.details`.

- [x] **Step 4: Test end to end with the real adapters**

A real SQLite store, a real `requests.Session`, and a loopback server serving
the baseline wheel. Assert the smuggled flow is found, only the selected
baseline was fetched, and the temporary files are gone afterwards.

- [x] **Step 5: Run the wiring tests**

Run: uv run pytest tests/baseline/test_wiring.py -v

Expected: PASS.

### Task 8: Package layout, documentation, and quality gates

**Files:**
- Create: src/devpi_guardian/baseline/__init__.py
- Create: tests/baseline/__init__.py
- Create: news/3.feature
- Create: docs/superpowers/specs/2026-08-19-devpi-guardian-f6-f7-design.md
- Create: docs/superpowers/plans/2026-08-19-f6-f7-baseline-diff.md

- [x] **Step 1: Re-export the public API**

`baseline/__init__.py` re-exports the names consumers use, matching how
`verdicts/__init__.py` and `analyzers/__init__.py` expose theirs, so
`from devpi_guardian.baseline import select_baseline` keeps working.

- [x] **Step 2: Add the news fragment**

~~~text
Add trusted-baseline selection and baseline-diff analysis for new release artifacts.
~~~

- [x] **Step 3: Run the whole suite**

Run: uv run pytest -m "not integration"

Expected: PASS.

- [x] **Step 4: Run lint checks**

Run: uv run ruff check src/devpi_guardian/baseline tests/baseline
Run: uv run ruff format --check src/devpi_guardian/baseline tests/baseline
Run: uv run flake8 src/devpi_guardian/baseline tests/baseline

Expected: exit 0. `.flake8` sets only `max-line-length = 100` and defines no
per-file-ignores; the baseline package needs no entry there because Ruff's
`line-length = 100` already holds every file to the same limit.

- [x] **Step 5: Commit the packaged feature**

~~~bash
git add src/devpi_guardian/baseline tests/baseline news/3.feature docs/superpowers
git commit -m "feat: add trusted-baseline selection and baseline-diff analysis"
~~~

## F6/F7 integration

F5 builds the two adapters and calls one function:

~~~python
from devpi_guardian.baseline import (
    HttpArtifactBytesSource,
    VerdictReaderReleaseLookup,
    compare_release_to_baseline,
)

lookup = VerdictReaderReleaseLookup(reader)
with requests.Session() as session, HttpArtifactBytesSource(session, lookup) as source:
    result = compare_release_to_baseline(target, artifact_path, lookup=lookup, bytes_source=source)
~~~

F10 maps `result.findings` to `EvidenceInput`, carrying each pair's `Origin`
and `result.selection.tier` in `EvidenceInput.details`, and puts
`result.baseline_sha256` into `VerdictInput.baseline_sha256`.

F7 reports only what changed. It must be consumed together with F8's standalone
scan, which owns the artifact-wide install-surface rules F7 deliberately leaves
alone.
