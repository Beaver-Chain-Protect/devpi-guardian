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

For a devpi-server that requires authentication, pass the devpi username and token. The
CLI sends the token through devpi's ``X-Devpi-Auth`` header; ``--auth-token-file`` reads a
bounded, owner-readable token file without placing the token in the process arguments::

    guardian --api-url https://devpi.example.test --username root \
        --auth-token-file /path/to/token health

Mutations require an actor and reason and use the public ``ArtifactStore`` transaction
boundaries. Approval, block, revoke, rescan, baseline, and policy actions retain immutable
verdict/evidence/override/audit history. Audit-chain verification is included in health and
startup fails closed if the chain is invalid.

The API and CLI never return quarantine bytes, local filesystem paths, credentials, query
strings, fragments, or worker bypass tokens. Sanitized canonical origin metadata may be
returned for release mappings; it contains no credentials, query, fragment, or local path.
Errors are bounded and sanitized; an unavailable provider returns the documented
service-unavailable response rather than exposing a traceback. Public
devpi ``+f``/``+e`` downloads remain governed by the shared ``VerdictReader`` and only an
effective ``ALLOW`` can reach the release-file handler.
