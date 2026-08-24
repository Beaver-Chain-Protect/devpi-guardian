from __future__ import annotations

import contextlib
from types import SimpleNamespace

from devpi_guardian.worker.discovery_consumer import DiscoveryCycle, DiscoveryCycleStatus
from devpi_guardian.worker.pipeline import WorkerCycle, WorkerCycleStatus
from devpi_guardian.worker.runtime import CoordinatorStatus, WorkerCoordinator


class Cycles:
    def __init__(self, *cycles) -> None:
        self.cycles = list(cycles)
        self.calls = 0

    def run_once(self):
        self.calls += 1
        return self.cycles.pop(0)

    def recover_expired_claims(self):
        return 0


def test_coordinator_drains_discovery_before_analysis() -> None:
    discovery = Cycles(
        DiscoveryCycle(DiscoveryCycleStatus.COMPLETED, "a" * 64),
        DiscoveryCycle(DiscoveryCycleStatus.IDLE, None),
    )
    analysis = Cycles(WorkerCycle(WorkerCycleStatus.COMPLETED, "a" * 64))
    coordinator = WorkerCoordinator(discovery=discovery, analysis=analysis)

    first = coordinator.run_once()
    second = coordinator.run_once()

    assert first.status is CoordinatorStatus.DISCOVERY
    assert second.status is CoordinatorStatus.ANALYSIS
    assert discovery.calls == 2
    assert analysis.calls == 1


def test_coordinator_is_idle_only_when_both_workers_are_idle() -> None:
    discovery = Cycles(DiscoveryCycle(DiscoveryCycleStatus.IDLE, None))
    analysis = Cycles(WorkerCycle(WorkerCycleStatus.IDLE, None))

    cycle = WorkerCoordinator(discovery=discovery, analysis=analysis).run_once()

    assert cycle.status is CoordinatorStatus.IDLE
    assert cycle.sha256 is None


def test_thread_runner_sleeps_only_when_no_work_is_available() -> None:
    from devpi_guardian.worker.runtime import GuardianWorkerThread

    coordinator = Cycles(SimpleNamespace(status=CoordinatorStatus.IDLE))
    runner = GuardianWorkerThread(coordinator, poll_interval=0.25)

    class StopAfterSleep:
        def __init__(self) -> None:
            self.sleeps = []

        def sleep(self, seconds):
            self.sleeps.append(seconds)
            raise KeyboardInterrupt

    runner.thread = StopAfterSleep()

    with contextlib.suppress(KeyboardInterrupt):
        runner.thread_run()

    assert runner.thread.sleeps == [0.25]


def test_thread_runner_reports_health_and_closes_session() -> None:
    from devpi_guardian.worker.runtime import GuardianWorkerThread

    coordinator = Cycles(SimpleNamespace(status=CoordinatorStatus.IDLE))
    closed = []
    runner = GuardianWorkerThread(
        coordinator,
        poll_interval=0.25,
        shutdown=lambda: closed.append(True),
    )

    class RegisteredThread:
        def is_alive(self):
            return False

    runner.thread = RegisteredThread()

    assert runner.worker_health()["status"] == "registered"
    runner.thread_shutdown()
    assert closed == [True]
