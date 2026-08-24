"""F6·F7: choose an approved baseline release and diff an artifact against it.

`selection` implements F6's priority chain over the releases F4 has approved.
`diff` implements F7, comparing one artifact against the chosen baseline and
reporting only what the baseline did not already carry. `release_lookup` and
`artifact_source` are the concrete adapters behind F6's two injected
protocols: F4's verdict store and an HTTP fetch of the baseline bytes.
"""

from .artifact_source import (
    ArtifactDigestMismatch,
    ArtifactDownloadError,
    HttpArtifactBytesSource,
    OriginUrlResolver,
)
from .diff import (
    DIFF_RULES,
    BaselineComparison,
    BaselineDiff,
    CarriedEvidence,
    CarriedFlow,
    FileDiff,
    NewSurface,
    Origin,
    compare_release_to_baseline,
    compare_to_baseline,
    diff_against_baseline,
    findings_only,
)
from .release_lookup import (
    AllowedReleaseSource,
    UnknownArtifactOrigin,
    VerdictReaderReleaseLookup,
)
from .selection import (
    ArtifactBytesSource,
    BaselineSelection,
    BaselineTier,
    ReleaseLookup,
    ReleaseRecord,
    WheelTag,
    artifact_kind,
    canonical_project_name,
    eligible_candidates,
    parse_wheel_tag,
    select_baseline,
)

__all__ = [
    "DIFF_RULES",
    "AllowedReleaseSource",
    "ArtifactBytesSource",
    "ArtifactDigestMismatch",
    "ArtifactDownloadError",
    "BaselineComparison",
    "BaselineDiff",
    "BaselineSelection",
    "BaselineTier",
    "CarriedEvidence",
    "CarriedFlow",
    "FileDiff",
    "HttpArtifactBytesSource",
    "NewSurface",
    "Origin",
    "OriginUrlResolver",
    "ReleaseLookup",
    "ReleaseRecord",
    "UnknownArtifactOrigin",
    "VerdictReaderReleaseLookup",
    "WheelTag",
    "artifact_kind",
    "canonical_project_name",
    "compare_release_to_baseline",
    "compare_to_baseline",
    "diff_against_baseline",
    "eligible_candidates",
    "findings_only",
    "parse_wheel_tag",
    "select_baseline",
]
