F11 administrator API and CLI
=============================

The production administrator API is rooted at ``/+guardian/api/v1``. It exposes bounded,
sanitized views and commands for quarantine artifacts, verdict/evidence, baselines, release
diffs, policy, audit, and worker health. The health resource is::

    GET /+guardian/api/v1/health

Use the ``guardian`` console command for the same operations through a configured devpi
endpoint::

    guardian --api-url https://devpi.example.test health
    guardian --api-url https://devpi.example.test artifact inspect <sha256>
    guardian --api-url https://devpi.example.test quarantine list --limit 50

Mutations require an actor and reason and use the public ``ArtifactStore`` transaction
boundaries. Approval, block, revoke, rescan, baseline, and policy actions retain immutable
verdict/evidence/override/audit history. Audit-chain verification is included in health and
startup fails closed if the chain is invalid.

The API and CLI never return quarantine bytes, local filesystem paths, credentials, origin
URLs, or worker bypass tokens. Errors are bounded and sanitized; an unavailable provider
returns the documented service-unavailable response rather than exposing a traceback. Public
devpi ``+f``/``+e`` downloads remain governed by the shared ``VerdictReader`` and only an
effective ``ALLOW`` can reach the release-file handler.
