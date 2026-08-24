F5 quarantine worker
====================

F5 prepares untrusted release files and coordinates analysis.  It owns
download verification, content-addressed quarantine storage, worker claims,
and calls to the analysis and policy layers.  Detection rules remain in
F7--F9 and the final decision remains in F10.

Flow
----

The worker processes one SHA-256 identity through the following flow::

   F1/F2 observes a DecisionSource.MISSING Simple link
     -> metadata batch registered in discovery/discovery.db
     -> discovery job atomically claimed with a lease
     -> bytes read from devpi filestore or its configured mirror upstream
     -> bytes downloaded into quarantine/incoming
     -> advertised and actual SHA-256 compared
     -> verified file moved to quarantine/sha256/<prefix>/<digest>.<format>
     -> F4 stores Artifact + release mapping as DISCOVERED
     -> discovery job acknowledged
     -> DISCOVERED artifact claimed from F4
     -> AnalysisEngine.analyze(bundle) called once
     -> PolicyEngine.evaluate(target, report) called once
     -> cooldown deadline calculated
     -> verdict, evidence, and cooldown recorded through F4

An exception before verdict persistence moves the claim to ``ERROR`` through
``ArtifactStore.mark_analysis_error``.  The artifact remains unavailable
because F2 and F3 expose only an effective ``ALLOW``.

The target artifact and any F9 sibling are prepared by F5.  The current F6/F7
adapter resolves and downloads its approved baseline itself, while F5 controls
when that adapter is called and records its result.

Analysis boundary
-----------------

``GuardianAnalysisEngine`` is the single worker-facing analysis entry point.
It composes the existing public APIs:

* F6/F7: ``compare_release_to_baseline``
* F8: ``scan_install_surface_isolated``
* F9: ``compare_sdist_wheel_isolated`` when a same-release pair is available

The report keeps each finding's ``F7``, ``F8``, or ``F9`` attribution.  F7
also keeps the diff origin and baseline tier.  Findings are not deduplicated
across analyzers because F10 may use corroboration in its policy.  F5 does
not assign scores or infer ``ALLOW`` from an empty finding list.

Input contract
--------------

Discovery supplies an ``ArtifactCandidate`` with stage, project, version,
filename, advertised SHA-256, canonical devpi origin URL, and an optional
advertised size.  Analysis receives only ``VerifiedArtifact`` local paths.
F9 receives both the sdist and wheel path for one project and version.

The F4 claim contains only SHA-256, size, and lease data.  F5 resolves the
remaining fields through the shared reader's ``get_artifact_releases`` and
``list_release_artifacts`` methods.  ``VerdictReaderCandidateSource`` adapts
those records into ``ArtifactCandidate`` values.
``QuarantineArtifactPreparer`` reopens the content-addressed files already
verified during discovery, including an available same-release sdist/wheel
counterpart.  It does not request the protected ``/+f/`` route.  F5 never
reads Guardian SQLite tables directly.

The metadata contract supplied for each file is:

* stage, normalized project, version, and filename;
* advertised SHA-256 and size;
* canonical HTTP(S) origin URL.

F5 passes only verified local paths to the analysis engine.  The same
``VerdictReaderReleaseLookup`` instance is passed both as the F6 lookup and
as ``HttpArtifactBytesSource``'s origin resolver.  This is enforced by the
``build_analysis_engine`` wiring function.

Discovery boundary
------------------

F1/F2 hide unknown links and batch-register only decisions whose source is
exactly ``DecisionSource.MISSING``.  F5 provides ``DiscoveryCandidate``,
``FileDiscoverySink``, and ``get_discovery_sink(xom)`` for this request-driven
handoff.  The historical sink name remains stable, while its implementation is
a separate SQLite queue at
``<guardian-db-parent>/discovery/discovery.db``.  The request thread stores
metadata only; it performs no network access or analysis.  Capacity is bounded
and a queue failure returns retryable HTTP 503.

The queue owns ``PENDING``, ``PROCESSING``, ``COMPLETED``, and ``FAILED``
states.  Claiming is atomic, processing has a lease, expired claims return to
``PENDING``, and retry attempts are persisted.  A completed or terminally
failed identity is not recreated by a repeated Simple request.  F4
``TransitionConflict`` and byte identity failures are terminal; transient
source and store failures use the bounded retry path.

The discovery message intentionally omits size and version.  ``stage`` is the
Guardian stage that observed the link.  ``SimpleLinkResolver`` validates the
link against the configured devpi origin, derives the F4 source stage from the
``/{user}/{index}/+f/`` path, and parses the version from ``link.basename``.
The consumer verifies actual SHA-256 and size before calling F4's existing
``discover_artifact`` method.  F4's immutable size contract therefore does not
change.

``DevpiArtifactBytesSource`` avoids an F3 deadlock.  Cached bytes come from the
internal devpi filestore; a mirror cache miss uses the source stage's configured
HTTP client and devpi's stored upstream URL.  There is no worker bypass token or
public ``/+f/`` exception.  The canonical original devpi link is stored in F4,
not a redirect-time CDN URL.

The consumer acknowledges its queue job only after quarantine publication and
F4 registration both succeed.  If F4 is temporarily unavailable, the verified
quarantine file is reused on retry instead of being downloaded again.

Lease and retry boundary
------------------------

The discovery queue implements atomic claim, lease expiry recovery, persistent
attempt counts, delayed retry, and terminal failure.  ``QuarantineWorker``
uses F4's separate atomic ``claim_next`` and ``recover_expired_claims`` calls
for analysis.  The current F4 interface still has no lease renewal method;
long-running analysis needs that extension if it can approach the configured
claim deadline.

F8 and F9 already expose isolated entry points with timeout and memory limits.
The current F6/F7 public entry point is synchronous and has no equivalent
process timeout.  Before production wiring, F6/F7 must provide an isolated
entry point or F5 must run the complete analysis facade in a supervised child
process.

Cooldown boundary
-----------------

F5 also owns the operational cooldown when the product policy requires an
artifact to remain quarantined after analysis completes.  It calculates the
deadline; F4 persists it; F2 and F3 enforce it through their shared effective
decision reader.  F10 continues to decide security evidence independently of
elapsed time.

The preferred enforcement contract is::

   allowed = effective_decision == ALLOW and now >= cooldown_until

``EnforcementDecision.allowed`` remains the only public delivery predicate.
This keeps clock handling out of the Simple filter and direct-download tween.
An ``ALLOW`` verdict may therefore exist while the artifact is still hidden.

Cooldown starts when an automated ``ALLOW`` analysis completes.  The worker
uses a configurable duration with a provisional 24-hour default.  F4 stores
the first cooldown window for each SHA-256 and keeps it across rescans and
manual verdict changes.  ``SQLiteVerdictReader`` returns ``allowed=False``
until the deadline, so F2 and F3 enforce the same clock decision without
duplicating time logic.  Releases in active cooldown are also excluded from
F6 baseline candidates.

An explicit cooldown bypass is not part of F5.  If the team adds one, it must
be an audited F11 operation distinct from an ordinary manual ``ALLOW``.

F10 boundary
------------

The worker depends on a narrow ``PolicyEngine`` protocol.  F10 receives the
combined report, including baseline presence, analyzer coverage, findings,
origins, and baseline tier, and returns F4's ``VerdictInput``.  This keeps
temporary scoring rules out of F5 while F10 is being integrated.

Runtime composition
-------------------

``build_worker_thread`` is the production composition point.  It accepts the
real F4 store, shared F4 reader, F10 policy engine, baseline HTTP session, and
paths, then builds one devpi-ThreadPool-compatible runner.  The coordinator
drains discovery work before claiming analysis work so same-release wheel and
sdist files have the best chance to be available together for F9.

The function deliberately requires an already composed F4 store.  F4 requires
the real F12 ``AuditWriter`` for transactional state and audit changes, so F5
does not install a no-op audit implementation.  Plugin startup now composes the
SQLite store, F12 writer, F10 engine and analysis engine, then registers the
runner with devpi's thread pool.  Replicas do not start an analysis runner.

The operational settings are ``--guardian-base-url``,
``--guardian-quarantine-root``, ``--guardian-cooldown-hours`` and
``--guardian-worker-poll-interval``.  Defaults keep quarantine storage beside
``guardian.db``, use a 24-hour cooldown, and poll at 0.25 seconds.  The F11
health response reports runner state, queue counts, Artifact-state counts,
cycle totals and the most recent worker error.

Current verification
--------------------

Focused tests cover batched discovery, atomic claims, ACK, retry, recovery,
queue limits, safe link resolution, internal devpi byte access, streaming
SHA-256 verification, quarantine reuse, F4 registration ordering, terminal
conflicts, one-call analysis orchestration, same-release pairing, and cooldown
enforcement::

   uv run pytest tests/worker -q
   uv run ruff format --check src/devpi_guardian/worker tests/worker
   uv run ruff check src/devpi_guardian/worker tests/worker
   uv run flake8 src/devpi_guardian/worker tests/worker

The 2026-08-25 production-composition integration run completed with 1,471
passing tests before the final packaging verification.
