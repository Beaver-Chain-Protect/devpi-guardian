"""F6: choose the previously approved release a new artifact is compared to.

The selection is deterministic and depends only on release metadata: no
artifact is opened, downloaded, or executed here. Two integration points are
still owned by other features and are therefore expressed as protocols:

* ``ReleaseLookup`` is F4's query for the ALLOW releases of one project.
* ``ArtifactBytesSource`` resolves an approved SHA-256 to readable bytes.

Both are injected. This module never assumes a concrete implementation.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)

# Identical to devpi_guardian.verdicts.models.validate_sha256, restated here so
# that F6 keeps the analyzers' property of importing no devpi-server code.
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}", re.ASCII)

SDIST_SUFFIXES = (
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".tar",
    ".zip",
)

ArtifactKind = Literal["wheel", "sdist", "unknown"]

#: Priority chain of SPEC-F6: an exact compatibility-tag match is the most
#: comparable baseline, a pure-Python wheel is next, an sdist is the last
#: resort, and no match at all means the artifact has no baseline.
BaselineTier = Literal["same_tag", "universal_wheel", "sdist"]

_WHEEL_TIER_CHAIN: tuple[BaselineTier, ...] = ("same_tag", "universal_wheel", "sdist")
_SDIST_TIER_CHAIN: tuple[BaselineTier, ...] = ("sdist",)


def canonical_project_name(name: str) -> str:
    """Normalize a project name the PEP 503 way."""

    return re.sub(r"[-_.]+", "-", name.strip()).lower()


@dataclass(frozen=True, slots=True)
class WheelTag:
    """The three-part compatibility tag at the end of a wheel filename."""

    python: str
    abi: str
    platform: str

    @property
    def text(self) -> str:
        return f"{self.python}-{self.abi}-{self.platform}"

    @property
    def universal(self) -> bool:
        """True for a pure-Python wheel, including compressed tag sets."""

        return set(self.abi.split(".")) == {"none"} and set(self.platform.split(".")) == {"any"}


@dataclass(frozen=True, slots=True)
class ReleaseRecord:
    """One release file already known to the verdict store.

    The fields are the subset of F4's release identity that baseline selection
    needs. Building these from an F4 row is the caller's job.
    """

    project: str
    version: str
    filename: str
    sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.sha256, str) or _SHA256_PATTERN.fullmatch(self.sha256) is None:
            raise ValueError("sha256 must be a lowercase 64-character SHA-256")
        for name in ("project", "version", "filename"):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"{name} must not be blank")


@runtime_checkable
class ReleaseLookup(Protocol):
    """F4's read side: the approved releases of one project."""

    def allowed_releases(self, project: str) -> list[ReleaseRecord]: ...


@runtime_checkable
class ArtifactBytesSource(Protocol):
    """Resolves an approved SHA-256 to a readable local path."""

    def open(self, sha256: str) -> Path: ...


@dataclass(frozen=True, slots=True)
class BaselineSelection:
    """The chosen baseline together with the tier that matched it."""

    release: ReleaseRecord
    tier: BaselineTier
    version: Version


def artifact_kind(filename: str) -> ArtifactKind:
    lowered = filename.lower()
    if lowered.endswith(".whl"):
        return "wheel"
    if lowered.endswith(SDIST_SUFFIXES):
        return "sdist"
    return "unknown"


def parse_wheel_tag(filename: str) -> WheelTag | None:
    """Read the compatibility tag of a PEP 427 wheel filename.

    Returns ``None`` for a non-wheel or a filename that does not carry the
    expected ``name-version[-build]-python-abi-platform`` shape.
    """

    if not filename.lower().endswith(".whl"):
        return None
    parts = filename[: -len(".whl")].split("-")
    if len(parts) not in {5, 6}:
        return None
    python, abi, platform = (part.strip().lower() for part in parts[-3:])
    if not python or not abi or not platform:
        return None
    return WheelTag(python, abi, platform)


def _parse_version(release: ReleaseRecord) -> Version | None:
    try:
        return Version(release.version)
    except InvalidVersion:
        logger.debug(
            "baseline 후보 제외: PEP 440으로 파싱할 수 없는 버전 %r (%s)",
            release.version,
            release.filename,
        )
        return None


def _tier_chain(target: ReleaseRecord) -> tuple[BaselineTier, ...]:
    kind = artifact_kind(target.filename)
    if kind == "sdist":
        return _SDIST_TIER_CHAIN
    if kind != "wheel":
        logger.debug(
            "baseline 선택 생략: wheel도 sdist도 아닌 대상 %s",
            target.filename,
        )
        return ()
    if parse_wheel_tag(target.filename) is None:
        # A wheel whose filename does not carry a readable tag can still be
        # compared against a pure-Python wheel or an sdist; only the exact-tag
        # tier is impossible.
        logger.debug(
            "대상 wheel의 tag를 읽을 수 없어 same_tag 단계를 건너뜀: %s",
            target.filename,
        )
        return _WHEEL_TIER_CHAIN[1:]
    return _WHEEL_TIER_CHAIN


def _matches_tier(tier: BaselineTier, target: ReleaseRecord, candidate: ReleaseRecord) -> bool:
    kind = artifact_kind(candidate.filename)
    if tier == "sdist":
        return kind == "sdist"
    if kind != "wheel":
        return False
    candidate_tag = parse_wheel_tag(candidate.filename)
    if candidate_tag is None:
        # Fail closed. An unreadable tag is not evidence that the candidate is
        # a universal wheel, nor that it matches the target tag, so it is
        # rejected from every wheel tier. This is a decision, not a skipped
        # check: an unclassifiable wheel must never reach a tier by default.
        logger.debug(
            "baseline 후보 제외: wheel tag를 읽을 수 없어 %s 티어에서 탈락 (%s)",
            tier,
            candidate.filename,
        )
        return False
    if tier == "universal_wheel":
        return candidate_tag.universal
    target_tag = parse_wheel_tag(target.filename)
    return target_tag is not None and candidate_tag.text == target_tag.text


def eligible_candidates(
    target: ReleaseRecord, releases: Iterable[ReleaseRecord]
) -> list[tuple[Version, ReleaseRecord]]:
    """Keep only same-project releases that are strictly older than target.

    Prereleases are ordinary candidates as long as ``packaging`` orders them
    below the target. Versions that PEP 440 cannot parse are dropped, because
    they cannot be ordered against the target at all.
    """

    target_version = _parse_version(target)
    if target_version is None:
        logger.debug("baseline 선택 생략: 대상 버전 %r을 파싱할 수 없음", target.version)
        return []
    project_key = canonical_project_name(target.project)

    eligible: list[tuple[Version, ReleaseRecord]] = []
    for candidate in releases:
        if canonical_project_name(candidate.project) != project_key:
            logger.debug(
                "baseline 후보 제외: 다른 프로젝트 %r (대상 %r)",
                candidate.project,
                target.project,
            )
            continue
        if candidate.sha256 == target.sha256:
            continue
        version = _parse_version(candidate)
        if version is None:
            continue
        if not version < target_version:
            logger.debug(
                "baseline 후보 제외: 대상보다 낮지 않은 버전 %s (%s)",
                candidate.version,
                candidate.filename,
            )
            continue
        eligible.append((version, candidate))
    return eligible


def _best_in_tier(
    tier: BaselineTier,
    target: ReleaseRecord,
    candidates: Sequence[tuple[Version, ReleaseRecord]],
) -> BaselineSelection | None:
    matching = [
        (version, candidate)
        for version, candidate in candidates
        if _matches_tier(tier, target, candidate)
    ]
    if not matching:
        return None
    highest = max(version for version, _ in matching)
    # Several files can share the highest version; pick the lowest filename so
    # that the selection is reproducible across lookup orderings.
    chosen = min(
        (candidate for version, candidate in matching if version == highest),
        key=lambda candidate: candidate.filename,
    )
    return BaselineSelection(release=chosen, tier=tier, version=highest)


def select_baseline(target: ReleaseRecord, lookup: ReleaseLookup) -> BaselineSelection | None:
    """Pick the baseline release for ``target``, or ``None`` if there is none.

    The chain is exact compatibility tag, then pure-Python wheel, then sdist;
    an sdist target uses the sdist tier only, since it carries no tag. Each
    tier is searched across every eligible older version before the next tier
    is tried, and the newest such version wins.
    """

    chain = _tier_chain(target)
    if not chain:
        return None
    candidates = eligible_candidates(target, lookup.allowed_releases(target.project))
    if not candidates:
        return None
    for tier in chain:
        selection = _best_in_tier(tier, target, candidates)
        if selection is not None:
            logger.debug(
                "baseline 선택: %s (tier=%s, 대상=%s)",
                selection.release.filename,
                tier,
                target.filename,
            )
            return selection
    return None
