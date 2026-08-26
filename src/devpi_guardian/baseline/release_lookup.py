"""F6's `ReleaseLookup`, backed by F4's verdict store.

`baseline.ReleaseLookup` was a protocol with only test doubles behind it while
F4 had no project-scoped query. `SQLiteVerdictReader.list_allowed_releases`
now provides one, so this module is the real implementation.

It also answers the question F6's protocols cannot: `ArtifactBytesSource.open`
receives a SHA-256 and nothing else, while the download URL and stored byte
count live on F4's release mapping. This adapter resolves and remembers both
for every release it hands out, so a byte source can verify the response
without reaching into the verdict store itself.

The reader is injected, not constructed. Per the F4 README, a consumer takes
the same public reader F2 and F3 use out of the Pyramid registry:

    from devpi_guardian.enforcement.tween import VERDICT_READER_REGISTRY_KEY

    reader = pyramid_config.registry[VERDICT_READER_REGISTRY_KEY]
    lookup = VerdictReaderReleaseLookup(reader)

Choosing where the reader comes from belongs to that wiring, not here.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..verdicts.models import AllowedRelease, ReleaseArtifact
from .selection import ReleaseRecord


class UnknownArtifactOrigin(LookupError):
    """No origin URL is known for the requested SHA-256."""


@runtime_checkable
class AllowedReleaseSource(Protocol):
    """The slice of F4's reader this adapter depends on.

    Narrower than `verdicts.interfaces.VerdictReader` on purpose: baseline
    selection never asks for an enforcement decision, so it should not require
    an object that can give one. It does use the reader's existing release
    mapping lookup to obtain the stored byte count. Every `VerdictReader`
    satisfies this.
    """

    def list_allowed_releases(self, project: str) -> tuple[AllowedRelease, ...]: ...

    def get_artifact_releases(self, sha256: str) -> tuple[ReleaseArtifact, ...]: ...


class VerdictReaderReleaseLookup:
    """Adapt F4's `list_allowed_releases` to F6's `ReleaseLookup`.

    Store failures are deliberately not swallowed. `StoreUnavailable` and the
    other `GuardianStoreError` subclasses propagate to
    `diff.compare_release_to_baseline`, which turns them into an
    `analyzer_error` finding. Returning an empty list instead would make an
    unreachable verdict store indistinguishable from a project's first
    release, which is exactly the confusion the orchestrator exists to avoid.
    """

    def __init__(self, reader: AllowedReleaseSource) -> None:
        self._reader = reader
        self._origin_urls: dict[str, tuple[str, int]] = {}

    def allowed_releases(self, project: str) -> list[ReleaseRecord]:
        """Return the project's approved releases as F6 release records.

        The reader normalizes the project name and returns every stage, so the
        same artifact can appear more than once. Duplicate digests are folded
        into one record; the reader's deterministic ordering decides which
        stage's origin URL is remembered.
        """

        records: list[ReleaseRecord] = []
        seen: set[str] = set()
        for release in self._reader.list_allowed_releases(project):
            if release.sha256 in seen:
                continue
            origin_url, size_bytes = self._origin_and_size(release)
            seen.add(release.sha256)
            records.append(
                ReleaseRecord(
                    project=release.project,
                    version=release.version,
                    filename=release.filename,
                    sha256=release.sha256,
                    size_bytes=size_bytes,
                )
            )
            self._origin_urls.setdefault(
                release.sha256,
                (origin_url, size_bytes),
            )
        return records

    def _origin_and_size(self, release: AllowedRelease) -> tuple[str, int]:
        cached = self._origin_urls.get(release.sha256)
        if cached is not None:
            return cached

        matches = tuple(
            mapping
            for mapping in self._reader.get_artifact_releases(release.sha256)
            if (
                mapping.stage == release.stage
                and mapping.project == release.project
                and mapping.version == release.version
                and mapping.filename == release.filename
                and mapping.origin_url == release.origin_url
            )
        )
        if not matches:
            raise UnknownArtifactOrigin(f"no matching release mapping for {release.sha256}")
        sizes = {mapping.size_bytes for mapping in matches}
        if len(sizes) != 1 or any(type(size) is not int or size < 0 for size in sizes):
            raise UnknownArtifactOrigin(f"ambiguous release mapping size for {release.sha256}")
        return release.origin_url, sizes.pop()

    def origin_url(self, sha256: str) -> str:
        """Resolve a digest this lookup has already returned to its URL.

        Satisfies `artifact_source.OriginUrlResolver`. Raising rather than
        guessing keeps a byte source from inventing a download target for an
        artifact F4 never approved.
        """

        try:
            return self._origin_urls[sha256][0]
        except KeyError:
            raise UnknownArtifactOrigin(sha256) from None

    def expected_size(self, sha256: str) -> int:
        """Resolve the stored byte count for a release already returned."""

        try:
            return self._origin_urls[sha256][1]
        except KeyError:
            raise UnknownArtifactOrigin(sha256) from None
