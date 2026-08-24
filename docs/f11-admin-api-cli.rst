F11 administrator API and CLI
================================

Guardian exposes a versioned administrator API below
``/+guardian/api/v1``.  The routes reuse devpi's ``user_modify`` permission,
and state-changing requests take the actor from the authenticated request.
Approval, blocking, rescanning, and temporary exceptions require a non-empty
reason.

Available operations
--------------------

The initial API provides quarantine listing, artifact inspection, approval,
blocking, rescanning, expiring exceptions, and health reporting.  Responses
use stable JSON error codes and HTTP status codes: invalid input is 400,
missing artifacts are 404, invalid state transitions are 409, and unavailable
storage dependencies are 503.

The ``guardian`` command is an API client.  It never opens ``guardian.db``
directly, so validation, authorization, and auditing remain on the server.
For example::

    guardian --api-url https://devpi.example --json quarantine list
    guardian --api-url https://devpi.example artifact inspect <sha256>
    guardian --api-url https://devpi.example artifact approve <sha256> \
        --reason "reviewed by security"
    guardian --api-url https://devpi.example exception add <sha256> \
        --expires-at 2026-08-25T00:00:00+00:00 --reason "temporary release"

Mutation readiness
------------------

F4 requires an F12 ``AuditWriter`` for every state-changing transaction.
Until that writer is registered, read operations remain available and health
reports ``mutations_ready: false``.  Mutation requests then fail closed with
``mutations_unavailable`` instead of writing an unaudited decision.
