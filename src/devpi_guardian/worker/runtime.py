"""Runtime composition for discovery and analysis worker cycles."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from threading import Lock

from .adapters import VerdictReaderCandidateSource
from .analysis import build_analysis_engine
from .devpi_source import DevpiArtifactBytesSource
from .discovery import FileDiscoverySink, get_discovery_sink
from .discovery_consumer import DiscoveryConsumer, DiscoveryCycleStatus, SimpleLinkResolver
from .pipeline import QuarantineWorker, WorkerCycleStatus
from .preparer import QuarantineArtifactPreparer
from .quarantine import QuarantineStore


class CoordinatorStatus(StrEnum):
    IDLE = "IDLE"
    DISCOVERY = "DISCOVERY"
    ANALYSIS = "ANALYSIS"


@dataclass(frozen=True, slots=True)
class CoordinatorCycle:
    status: CoordinatorStatus
    sha256: str | None


class WorkerCoordinator:
    """Drain discovery first so same-release files reach F4 before analysis."""

    def __init__(self, *, discovery, analysis) -> None:
        self._discovery = discovery
        self._analysis = analysis

    def recover_expired_claims(self) -> int:
        return self._discovery.recover_expired_claims() + self._analysis.recover_expired_claims()

    def run_once(self) -> CoordinatorCycle:
        discovery = self._discovery.run_once()
        if discovery.status is not DiscoveryCycleStatus.IDLE:
            return CoordinatorCycle(CoordinatorStatus.DISCOVERY, discovery.sha256)
        analysis = self._analysis.run_once()
        if analysis.status is not WorkerCycleStatus.IDLE:
            return CoordinatorCycle(CoordinatorStatus.ANALYSIS, analysis.sha256)
        return CoordinatorCycle(CoordinatorStatus.IDLE, None)


class GuardianWorkerThread:
    """devpi ThreadPool-compatible polling runner."""

    def __init__(
        self,
        coordinator: WorkerCoordinator,
        *,
        poll_interval: float = 0.25,
        shutdown: Callable[[], None] | None = None,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        self._coordinator = coordinator
        self._poll_interval = poll_interval
        self._shutdown = shutdown
        self._health_lock = Lock()
        self._started_at: datetime | None = None
        self._last_cycle_at: datetime | None = None
        self._last_error: str | None = None
        self._cycles = 0
        self._completed = 0

    def worker_health(self) -> dict[str, object]:
        with self._health_lock:
            thread = getattr(self, "thread", None)
            alive = bool(thread is not None and getattr(thread, "is_alive", lambda: False)())
            return {
                "status": "running" if alive else "registered",
                "started_at": self._started_at,
                "last_cycle_at": self._last_cycle_at,
                "last_error": self._last_error,
                "cycles": self._cycles,
                "completed": self._completed,
            }

    def thread_run(self) -> None:
        with self._health_lock:
            self._started_at = datetime.now(UTC)
        self._coordinator.recover_expired_claims()
        while True:
            try:
                cycle = self._coordinator.run_once()
            except Exception as exc:
                with self._health_lock:
                    self._last_cycle_at = datetime.now(UTC)
                    self._last_error = f"{type(exc).__name__}: {str(exc)[:512]}"
                    self._cycles += 1
                self.thread.sleep(self._poll_interval)
                continue
            with self._health_lock:
                self._last_cycle_at = datetime.now(UTC)
                self._last_error = None
                self._cycles += 1
                if cycle.status is not CoordinatorStatus.IDLE:
                    self._completed += 1
            if cycle.status is CoordinatorStatus.IDLE:
                self.thread.sleep(self._poll_interval)

    def thread_shutdown(self) -> None:
        if self._shutdown is not None:
            self._shutdown()


def build_worker_thread(
    *,
    xom,
    store,
    reader,
    policy_engine,
    baseline_http_session,
    base_url: str,
    quarantine_root: Path,
    analyzer_version: str,
    worker_id: str,
    max_artifact_size: int = 1_000_000_000,
    cooldown_duration: timedelta = timedelta(hours=24),
    poll_interval: float = 0.25,
) -> GuardianWorkerThread:
    """Build the complete F5 runtime from F4/F10 production implementations.

    F4's concrete store requires the real F12 audit writer, so callers inject
    that already-composed store.  This function never substitutes a no-op
    audit writer.
    """

    queue = get_discovery_sink(xom)
    if not isinstance(queue, FileDiscoverySink):
        raise TypeError("registered discovery sink must be a FileDiscoverySink")
    quarantine = QuarantineStore(
        Path(quarantine_root),
        max_size_bytes=max_artifact_size,
    )
    discovery = DiscoveryConsumer(
        queue=queue,
        resolver=SimpleLinkResolver(base_url),
        bytes_source=DevpiArtifactBytesSource(xom),
        quarantine=quarantine,
        store=store,
        worker_id=f"{worker_id}-discovery",
    )
    source = VerdictReaderCandidateSource(reader)
    analysis = QuarantineWorker(
        store=store,
        preparer=QuarantineArtifactPreparer(source=source, quarantine=quarantine),
        analysis_engine=build_analysis_engine(
            reader=reader,
            session=baseline_http_session,
            analyzer_version=analyzer_version,
        ),
        policy_engine=policy_engine,
        worker_id=f"{worker_id}-analysis",
        cooldown_duration=cooldown_duration,
    )
    return GuardianWorkerThread(
        WorkerCoordinator(discovery=discovery, analysis=analysis),
        poll_interval=poll_interval,
        shutdown=getattr(baseline_http_session, "close", None),
    )
