F5 quarantine worker
====================

F5 prepares untrusted release files and coordinates analysis.  It owns
download verification, content-addressed quarantine storage, worker claims,
and calls to the analysis and policy layers.  Detection rules remain in
F7--F9 and the final decision remains in F10.

Flow
----

The worker processes one SHA-256 identity through the following flow::

   candidate received
     -> bytes downloaded into quarantine/incoming
     -> advertised and actual SHA-256 compared
     -> verified file moved to quarantine/sha256/<prefix>/<digest>.<format>
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
those records into ``ArtifactCandidate`` values, and
``HttpArtifactPreparer`` downloads and verifies the target plus one matching
sdist/wheel counterpart.  F5 never reads Guardian SQLite tables directly.

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

F1/F2 currently hide unknown links without registering them.  F5 provides
``DiscoveryCandidate``, ``FileDiscoverySink``, and ``get_discovery_sink(xom)``
for the request-driven handoff.  The sink writes immutable JSON metadata jobs
under ``<guardian-db-parent>/discovery/pending`` and performs no download or
analysis in the devpi request thread.  Distinct release mappings sharing one
SHA-256 remain separate jobs, while an identical notification is idempotent.

The discovery message intentionally omits size and version.  The F5 discovery
consumer will resolve the relative link, parse the filename, download into
content-addressed quarantine storage, and verify both SHA-256 and size before
calling F4's existing ``discover_artifact`` method.  F4's immutable size
contract therefore does not need to change.  F1/F2 still needs to call the
registered sink for ``DecisionSource.MISSING`` results.  A poller may replay
configured base Simple pages to recover missed notifications.

Claim-time metadata lookup and same-release pairing are implemented.  Unknown
links remain hidden while the F1/F2 call site is being connected.

Lease and retry boundary
------------------------

``QuarantineWorker`` uses the existing atomic ``claim_next`` and
``recover_expired_claims`` calls.  The current F4 interface has no lease
renewal or retry schedule.  Production wiring needs a ``renew_claim`` method
for downloads and multiple isolated analyses that may approach the lease
deadline.  Retry count and next-attempt time also belong in F4's durable
state rather than process memory.

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

Current verification
--------------------

Focused tests cover one-call orchestration, finding attribution, fail-closed
error recording, expired-claim recovery, streaming SHA-256 verification,
size verification, partial-file cleanup, F4 metadata adaptation, same-release
pair download, and cooldown enforcement::

   uv run pytest tests/worker -q
   uv run ruff format --check src/devpi_guardian/worker tests/worker
   uv run ruff check src/devpi_guardian/worker tests/worker
   uv run flake8 src/devpi_guardian/worker tests/worker
