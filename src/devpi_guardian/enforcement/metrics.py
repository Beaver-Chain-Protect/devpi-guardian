"""Internal metrics contract for blocked direct Artifact downloads."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from threading import Lock
from typing import Protocol

BLOCK_METRIC_REGISTRY_KEY = "devpi_guardian.direct_download_block_metrics"


@dataclass(frozen=True, slots=True)
class BlockMetricDimensions:
    """Bounded, credential-free dimensions for one blocked request."""

    route: str
    sha256: str
    effective_decision: str
    block_category: str


class BlockMetricRecorder(Protocol):
    """Adapter accepted by the enforcement tween."""

    def record_block(self, dimensions: BlockMetricDimensions) -> None:
        """Record one blocked request without changing request behavior."""


class InMemoryBlockMetricRecorder:
    """Thread-safe in-process block counter installed by the plugin."""

    def __init__(self) -> None:
        self._counts: Counter[BlockMetricDimensions] = Counter()
        self._lock = Lock()

    def record_block(self, dimensions: BlockMetricDimensions) -> None:
        with self._lock:
            self._counts[dimensions] += 1

    def snapshot(self) -> Mapping[BlockMetricDimensions, int]:
        """Return a stable copy suitable for an internal metrics adapter."""
        with self._lock:
            return dict(self._counts)
