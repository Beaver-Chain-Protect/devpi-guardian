F5 quarantine worker
====================

The Guardian worker is an activation-gated, durable pipeline:

``private upload or mirror discovery -> verified quarantine CAS -> discovery queue ->
analysis/policy -> terminal verdict``

Configure a primary devpi process with an explicit absolute quarantine root::

    devpi-server \
      --guardian-db /var/lib/devpi-guardian/guardian.db \
      --guardian-quarantine-root /var/lib/devpi-guardian/quarantine \
      --guardian-base-url https://devpi.example.test

The quarantine root must be a dedicated directory owned by the devpi service account,
mode ``0700``, and outside ``--serverdir``. Every existing ancestor is checked before
activation: it must be owned by root or the devpi service account and must not be writable
by group or other users. A root-owned sticky ancestor (for example ``/tmp``) is the sole
permitted shared-writable exception; an unsafe writable ancestor is rejected. The worker
creates the following content-addressed layout::

    <root>/objects/sha256/<first-2>/<next-2>/<sha256>

``.incoming`` and the final object are on the same filesystem. Publication verifies the
streaming SHA-256 and size, uses an exclusive staging file and atomic no-overwrite publish,
and rejects symlinks, hard links, non-regular files, unsafe permissions, and path traversal.
Analyzers receive a verified stream opened from the checked descriptor; they do not receive
a mutable local path or a public URL.

Private upload capture publishes the CAS object before writing the Artifact discovery
mapping. Mirror discovery validates the canonical source-stage entry and acquires bytes from
devpi's internal stage/mirror client. It never requests Guardian's protected public
``+f``/``+e`` route as a worker bypass.

Hashless ``+e`` handling has a separate identity gate. Guardian does not fetch an
uncached hashless upstream link merely to manufacture an Artifact identity. Until
devpi has materialized an authoritative cached ``FileEntry`` whose file, stage,
project, version, and SHA-256 agree with the requested link, the ordinary Guardian
Simple response hides the link and F3 blocks direct ``GET``/``HEAD`` as identity
unavailable. Once that cached entry is present, Guardian Simple queues discovery
using the independently validated FileEntry SHA. The worker then acquires bytes
through devpi's internal stage client/upstream stream, never through the public
``+e`` route. The link remains hidden and direct-blocked until an effective
``ALLOW``; after ``ALLOW`` the original link is exposed and may remain hashless,
while direct authorization continues to use the resolved FileEntry SHA.

The F11 health endpoint reports bounded worker, queue, artifact, and audit-chain state at
``/+guardian/api/v1/health``. Operators should poll this observable state (and the Artifact
details endpoint) for discovery and terminal verdict transitions rather than relying on a
fixed delay. A missing, damaged, or unavailable quarantine object records a sanitized
analysis error and cannot produce ``ALLOW``.

Existing devpi installations are not silently imported or backfilled. Offline inventory and
backfill remains a future operational process; until it exists, do not enable Guardian on a
server with existing Artifact candidates.
