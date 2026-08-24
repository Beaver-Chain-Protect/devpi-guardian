F11 administrator API and CLI
================================

Guardian exposes a versioned administrator API below
``/+guardian/api/v1``.  The routes reuse devpi's ``user_modify`` permission,
and state-changing requests take the actor from the authenticated request.
Approval, blocking, rescanning, and temporary exceptions require a non-empty
reason.

The routes have no user or index path context, so devpi's root ACL grants
``user_modify`` only to ``root`` by default or to the principals configured by
``--restrict-modify``.  Guardian therefore uses devpi's existing root/admin
boundary rather than adding a second authentication system.  Deployments that
set ``--restrict-modify`` must include every intended Guardian administrator,
including ``root`` when root access should remain available.

Available operations
--------------------

The API provides quarantine listing, artifact inspection and diff retrieval,
approval, blocking, rescanning, expiring exceptions, audit listing, baseline
management, policy validation and simulation, and health reporting.  Responses
use stable JSON error codes and HTTP status codes: invalid input is 400,
missing artifacts are 404, invalid state transitions are 409, and unavailable
storage or feature dependencies are 503.

The ``guardian`` command is an API client.  It never opens ``guardian.db``
directly, so validation, authorization, and auditing remain on the server.
For example::

    guardian --api-url https://devpi.example --json quarantine list
    guardian --api-url https://devpi.example artifact inspect <sha256>
    guardian --api-url https://devpi.example artifact approve <sha256> \
        --reason "reviewed by security"
    guardian --api-url https://devpi.example exception add <sha256> \
        --expires-at 2026-08-25T00:00:00+00:00 --reason "temporary release"
    guardian --api-url https://devpi.example artifact diff <sha256>
    guardian --api-url https://devpi.example audit list --sha256 <sha256>
    guardian --api-url https://devpi.example baseline list <project>
    guardian --api-url https://devpi.example baseline add <sha256> \
        --reason "approved baseline"
    guardian --api-url https://devpi.example baseline import baseline.json \
        --reason "initial approved set"
    guardian --api-url https://devpi.example policy validate policy.json
    guardian --api-url https://devpi.example policy simulate policy.json \
        --sha256 <sha256>

For automation, ``--auth-token-file`` reads the token without placing the
secret in the process argument list.  ``--auth-token`` remains available for
short-lived local use.  The two options are mutually exclusive.

Mutation readiness
------------------

F4 requires an F12 ``AuditWriter`` for every state-changing transaction.
Until that writer is registered, read operations remain available and health
reports ``mutations_ready: false``.  Mutation requests then fail closed with
``mutations_unavailable`` instead of writing an unaudited decision.

Integration providers
---------------------

F11 owns the HTTP and CLI contracts but does not duplicate the databases or
domain logic owned by the other features.  ``GuardianAdminService`` accepts
separate optional providers:

* ``WorkerHealthReader`` from F5;
* ``AuditReader`` from F12;
* ``ArtifactDiffReader`` from F7 or the persisted report adapter;
* ``BaselineManager`` from F6 and its approved-baseline persistence;
* ``PolicyManager`` from F10.

Each provider is independent so one feature can be integrated without making
unrelated operations appear ready.  Until its provider is connected, that
operation returns a feature-specific HTTP 503.  Health returns database state,
mutation readiness, worker state, and a readiness flag for every provider.

Provider contracts
------------------

The integration layer supplies objects with these methods::

    worker_health() -> Mapping[str, object]

    list_audit(*, sha256, actor, action, limit, offset) \
        -> Mapping[str, object]

    artifact_diff(sha256) -> Mapping[str, object]

    list_baselines(project) -> Sequence[Mapping[str, object]]
    add_baseline(sha256, *, actor, reason) -> None
    remove_baseline(sha256, *, actor, reason) -> None
    import_baselines(records, *, actor, reason) -> Mapping[str, object]

    validate_policy(policy) -> Mapping[str, object]
    simulate_policy(policy, *, sha256) -> Mapping[str, object]

Baseline changes are administrator mutations and must be audited by their
owning component.  Policy validation and simulation are read-only: simulation
returns a projected result for the named SHA-256 and never persists a verdict.
Artifact diff and policy simulation providers must read already persisted
analysis output; they must not download artifacts or run analyzers in the
devpi request thread.
