"""Test doubles for the F6 integration protocols.

F4's release query and the artifact byte source are not implemented yet. These
fakes satisfy the protocols exactly so the baseline selection chain can be
exercised now and the real implementations can be dropped in later without
touching selection logic.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path

from devpi_guardian.baseline import ReleaseRecord, canonical_project_name


def digest(seed: str) -> str:
    """A stable, valid SHA-256 for a readable test seed."""

    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def release(
    project: str,
    version: str,
    filename: str,
    *,
    sha256: str | None = None,
    size_bytes: int = 0,
) -> ReleaseRecord:
    return ReleaseRecord(
        project=project,
        version=version,
        filename=filename,
        sha256=sha256 or digest(f"{project}-{version}-{filename}"),
        size_bytes=size_bytes,
    )


class FakeReleaseLookup:
    """In-memory stand-in for F4's `project -> ALLOW releases` query."""

    def __init__(self, releases: Iterable[ReleaseRecord] = ()) -> None:
        self._releases = list(releases)
        self.calls: list[str] = []

    def add(self, record: ReleaseRecord) -> None:
        self._releases.append(record)

    def allowed_releases(self, project: str) -> list[ReleaseRecord]:
        self.calls.append(project)
        key = canonical_project_name(project)
        return [
            record for record in self._releases if canonical_project_name(record.project) == key
        ]


class FakeArtifactBytesSource:
    """In-memory stand-in for the not-yet-decided filestore integration."""

    def __init__(self, root: Path, contents: dict[str, bytes] | None = None) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)
        self._paths: dict[str, Path] = {}
        for sha256, payload in (contents or {}).items():
            self.add(sha256, payload)

    def add(self, sha256: str, payload: bytes, *, filename: str | None = None) -> Path:
        path = self._root / (filename or sha256)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        self._paths[sha256] = path
        return path

    def open(self, sha256: str) -> Path:
        try:
            return self._paths[sha256]
        except KeyError:
            raise FileNotFoundError(sha256) from None
