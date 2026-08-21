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

The current F4 claim contains only SHA-256, size, and lease data.  A concrete
``ArtifactPreparer`` therefore still requires a public F4 release lookup (or
an enriched claim) that supplies stage, project, version, filename, and
origin URL.  F5 does not read Guardian SQLite tables directly.

Discovery boundary
------------------

F1/F2 currently hide unknown links without registering them.  Request-driven
discovery should pass raw candidate metadata to an F5 discovery sink and do
no download or analysis in the devpi request thread.  A poller may replay
configured base Simple pages to recover missed notifications.

The discovery adapter and F4 API must settle two details before concrete
wiring:

* whether the discovery message may omit size until F5 verifies the bytes;
* how F5 resolves a claimed SHA-256 to its release metadata and same-release
  sdist/wheel candidates.

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

The default proposal is to start cooldown when automated analysis completes,
apply it once per SHA-256 identity, preserve it across ordinary manual ALLOW,
and permit bypass only through a separate explicit administrative exception.
Duration, manual bypass, and rescan behavior require team approval before the
SQLite contract is changed.

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
size verification, and partial-file cleanup::

   uv run pytest tests/worker -q
   uv run ruff format --check src/devpi_guardian/worker tests/worker
   uv run ruff check src/devpi_guardian/worker tests/worker
   uv run flake8 src/devpi_guardian/worker tests/worker
