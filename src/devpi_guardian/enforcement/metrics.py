"""Internal metrics contract for blocked direct Artifact downloads."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from threading import Lock
from typing import Protocol

from devpi_guardian.verdicts.errors import InvalidSha256
from devpi_guardian.verdicts.models import Decision, validate_sha256

BLOCK_METRIC_REGISTRY_KEY = "devpi_guardian.direct_download_block_metrics"
DEFAULT_MAX_BLOCK_METRIC_SERIES = 4_096
_UNKNOWN = "unknown"
_ALLOWED_ROUTES = frozenset({"+f", "+e", _UNKNOWN})
_DECISION_VALUES = {decision.value for decision in Decision}
_ALLOWED_EFFECTIVE_DECISIONS = frozenset({_UNKNOWN, *_DECISION_VALUES})
_BLOCK_CATEGORIES = (
    "identity_unavailable",
    "store_unavailable",
    "not_allowed",
)
_ALLOWED_BLOCK_CATEGORIES = frozenset(_BLOCK_CATEGORIES)


@dataclass(frozen=True, slots=True)
class BlockMetricDimensions:
    """Bounded, credential-free dimensions for one blocked request."""

    route: str
    sha256: str
    effective_decision: str
    block_category: str


CARDINALITY_OVERFLOW_DIMENSIONS = BlockMetricDimensions(
    route=_UNKNOWN,
    sha256=_UNKNOWN,
    effective_decision=_UNKNOWN,
    block_category="cardinality_overflow",
)


class BlockMetricRecorder(Protocol):
    """Adapter accepted by the enforcement tween."""

    def record_block(self, dimensions: BlockMetricDimensions) -> None:
        """Record one blocked request without changing request behavior."""


class InMemoryBlockMetricRecorder:
    """Thread-safe in-process block counter installed by the plugin."""

    def __init__(
        self,
        max_series: int = DEFAULT_MAX_BLOCK_METRIC_SERIES,
    ) -> None:
        if type(max_series) is not int or max_series <= 0:
            raise ValueError("max_series must be a positive integer")
        self._max_series = max_series
        self._series_count = 0
        self._counts: Counter[BlockMetricDimensions] = Counter()
        self._lock = Lock()

    def record_block(self, dimensions: BlockMetricDimensions) -> None:
        if not _valid_dimensions(dimensions):
            raise ValueError("valid block metric dimensions are required")
        with self._lock:
            if dimensions in self._counts:
                self._counts[dimensions] += 1
            elif self._series_count < self._max_series:
                self._counts[dimensions] = 1
                self._series_count += 1
            else:
                self._counts[CARDINALITY_OVERFLOW_DIMENSIONS] += 1

    def snapshot(self) -> Mapping[BlockMetricDimensions, int]:
        """Return a stable copy suitable for an internal metrics adapter."""
        with self._lock:
            return dict(self._counts)


def _valid_dimensions(dimensions: object) -> bool:
    if type(dimensions) is not BlockMetricDimensions:
        return False
    if any(
        type(value) is not str
        for value in (
            dimensions.route,
            dimensions.sha256,
            dimensions.effective_decision,
            dimensions.block_category,
        )
    ):
        return False
    if dimensions.route not in _ALLOWED_ROUTES:
        return False
    if dimensions.effective_decision not in _ALLOWED_EFFECTIVE_DECISIONS:
        return False
    if dimensions.block_category not in _ALLOWED_BLOCK_CATEGORIES:
        return False
    if dimensions.sha256 == _UNKNOWN:
        return True
    try:
        validate_sha256(dimensions.sha256)
    except InvalidSha256:
        return False
    return True
