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

        def exit_if_shutdown(self):
            return None

        def sleep(self, seconds):
            self.sleeps.append(seconds)
            raise KeyboardInterrupt

    runner.thread = StopAfterSleep()

    with contextlib.suppress(KeyboardInterrupt):
        runner.thread_run()

    assert runner.thread.sleeps == [0.25]


def test_thread_runner_reports_health_and_closes_session_from_worker_finally() -> None:
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

        def exit_if_shutdown(self):
            raise KeyboardInterrupt

    runner.thread = RegisteredThread()

    assert runner.worker_health()["status"] == "registered"
    with contextlib.suppress(KeyboardInterrupt):
        runner.thread_run()
    assert closed == [True]


def test_thread_runner_retries_recovery_and_redacts_error_details() -> None:
    from devpi_guardian.worker.runtime import GuardianWorkerThread

    class RecoveringCoordinator:
        def __init__(self):
            self.recoveries = 0

        def recover_expired_claims(self):
            self.recoveries += 1
            if self.recoveries == 1:
                raise RuntimeError("credential=/secret/path sha256=" + "a" * 64)
            return 0

        def run_once(self):
            raise RuntimeError("origin=https://user:password@example.invalid")

    class StopAfterTwoSleeps:
        def __init__(self):
            self.sleeps = 0

        def sleep(self, _seconds):
            self.sleeps += 1
            if self.sleeps == 2:
                raise KeyboardInterrupt

        def exit_if_shutdown(self):
            return None

    coordinator = RecoveringCoordinator()
    runner = GuardianWorkerThread(coordinator, poll_interval=0.01)
    runner.thread = StopAfterTwoSleeps()

    with contextlib.suppress(KeyboardInterrupt):
        runner.thread_run()

    assert coordinator.recoveries == 2
    assert runner.worker_health()["last_error"] == "RuntimeError"


def test_real_thread_pool_shutdown_closes_resources_in_worker_finally() -> None:
    from devpi_server.mythread import ThreadPool

    from devpi_guardian.worker.runtime import GuardianWorkerThread

    closed = []
    coordinator = Cycles(SimpleNamespace(status=CoordinatorStatus.IDLE))
    runner = GuardianWorkerThread(
        coordinator,
        poll_interval=0.01,
        shutdown=lambda: closed.append(True),
    )
    pool = ThreadPool()
    pool.register(runner)
    pool.start()
    pool.shutdown()
    runner.thread.join(timeout=2)

    assert not runner.thread.is_alive()
    assert closed == [True]
