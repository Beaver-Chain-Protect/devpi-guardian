"""Optional cross-platform process isolation for the pure analyzer functions."""

from __future__ import annotations

import multiprocessing
import os
from dataclasses import dataclass
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Literal

from .install_surface import scan_install_surface
from .rules import rule
from .sdist_wheel import compare_sdist_wheel
from .types import Finding, make_finding, sort_findings

_Analyzer = Literal["F8", "F9"]


@dataclass(frozen=True)
class AnalysisLimits:
    """Limits for an analyzer child process and its wall-clock execution.

    Isolated APIs always use a child process and timeout on every operating
    system. ``memory_limit_mb`` is POSIX best-effort only; it is not a hard
    guarantee on Windows or unsupported POSIX platforms. Deployments that
    require hard memory enforcement must provide OS- or container-level limits.
    """

    timeout_seconds: float = 30.0
    memory_limit_mb: int | None = 512

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds는 0보다 커야 합니다")
        if self.memory_limit_mb is not None and self.memory_limit_mb < 64:
            raise ValueError("memory_limit_mb는 null 또는 64 이상이어야 합니다")


_DEFAULT_LIMITS = AnalysisLimits()


def _error(file: str, snippet: str) -> Finding:
    definition = rule("analyzer_error")
    return make_finding(
        rule="analyzer_error",
        action=definition.action,
        file=file,
        line=None,
        snippet=snippet,
        message=definition.message,
    )


def _apply_memory_limit(memory_limit_mb: int | None) -> None:
    if memory_limit_mb is None or os.name == "nt":
        return
    try:
        import resource

        limit = memory_limit_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except (ImportError, AttributeError, OSError, ValueError):
        # Timeout isolation still works on platforms without RLIMIT_AS.
        return


def _worker(
    connection: Connection,
    analyzer: _Analyzer,
    paths: tuple[str, ...],
    memory_limit_mb: int | None,
) -> None:
    try:
        _apply_memory_limit(memory_limit_mb)
        if analyzer == "F8":
            findings = scan_install_surface(paths[0])
        else:
            findings = compare_sdist_wheel(paths[0], paths[1])
        connection.send(("ok", findings))
    except BaseException as exc:
        connection.send(("error", f"{type(exc).__name__}: {exc}"))
    finally:
        connection.close()


def _isolated(
    analyzer: _Analyzer,
    paths: tuple[str, ...],
    limits: AnalysisLimits,
) -> list[Finding]:
    label = Path(paths[-1]).name or "<artifact>"
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_worker,
        args=(sender, analyzer, paths, limits.memory_limit_mb),
        daemon=True,
    )
    try:
        process.start()
        sender.close()
        if not receiver.poll(limits.timeout_seconds):
            process.terminate()
            process.join(timeout=1.0)
            if process.is_alive():
                process.kill()
                process.join(timeout=1.0)
            return sort_findings(
                [
                    _error(
                        label,
                        f"analysis timeout after {limits.timeout_seconds:.3f}s",
                    )
                ]
            )
        try:
            status, payload = receiver.recv()
        except EOFError:
            return sort_findings(
                [
                    _error(
                        label,
                        f"analysis worker exited with code {process.exitcode}",
                    )
                ]
            )
        process.join(timeout=1.0)
        if process.is_alive():
            process.terminate()
            process.join(timeout=1.0)
        if status == "ok" and isinstance(payload, list):
            return sort_findings(payload)
        return sort_findings([_error(label, str(payload))])
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        if process.is_alive():
            process.terminate()
            process.join(timeout=1.0)
        return sort_findings([_error(label, f"{type(exc).__name__}: {exc}")])
    finally:
        receiver.close()
        sender.close()


def scan_install_surface_isolated(
    artifact_path: str,
    *,
    limits: AnalysisLimits = _DEFAULT_LIMITS,
) -> list[Finding]:
    """Run F8 in a child process with a wall-clock timeout for untrusted input."""

    return _isolated("F8", (artifact_path,), limits)


def compare_sdist_wheel_isolated(
    sdist_path: str,
    wheel_path: str,
    *,
    limits: AnalysisLimits = _DEFAULT_LIMITS,
) -> list[Finding]:
    """Run F9 in a child process with a wall-clock timeout for untrusted input."""

    return _isolated("F9", (sdist_path, wheel_path), limits)
