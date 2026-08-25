"""Resolve Simple links, quarantine bytes, and fence durable discovery jobs."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol
from urllib.parse import urlsplit

from devpi_common.metadata import normalize_name, splitbasename

from devpi_guardian.verdicts.errors import TransitionConflict
from devpi_guardian.verdicts.interfaces import ArtifactStore
from devpi_guardian.verdicts.models import ArtifactInput, ReleaseInput

from .devpi_paths import DevpiBase, DevpiRouteError, validate_artifact_relpath
from .discovery import DiscoveryCandidate, FileDiscoverySink
from .models import ArtifactCandidate
from .quarantine import QuarantineError, QuarantineStore, close_owned


@dataclass(frozen=True, slots=True)
class ResolvedDiscovery:
    observer_stage: str
    source_stage: str
    project: str
    version: str
    filename: str
    sha256: str
    relpath: str
    origin_url: str


class ArtifactBytesSource(Protocol):
    def iter_chunks(self, resolved: ResolvedDiscovery) -> Iterable[bytes]: ...


class SimpleLinkResolver:
    def __init__(self, base_url: str) -> None:
        try:
            self._base = DevpiBase.parse(base_url)
        except DevpiRouteError as error:
            raise ValueError("base_url must be an absolute canonical HTTP(S) URL") from error

    def resolve(self, candidate: DiscoveryCandidate) -> ResolvedDiscovery:
        raw = candidate.link_href
        raw_parts = urlsplit(raw)
        if raw_parts.fragment != f"sha256={candidate.sha256}":
            raise ValueError("artifact link must contain one exact SHA-256 fragment")
        try:
            relpath, canonical_origin = self._base.resolve_link(raw)
            parts = validate_artifact_relpath(
                relpath, filename=candidate.filename, sha256=candidate.sha256
            )
        except DevpiRouteError as error:
            raise ValueError("artifact link is not a canonical devpi file path") from error
        parsed_project, version, _extension = splitbasename(candidate.filename)
        if normalize_name(parsed_project) != normalize_name(candidate.project):
            raise ValueError("artifact filename does not match project")
        source_stage = f"{parts[0]}/{parts[1]}"
        return ResolvedDiscovery(
            observer_stage=candidate.stage,
            source_stage=source_stage,
            project=normalize_name(candidate.project),
            version=version,
            filename=candidate.filename,
            sha256=candidate.sha256,
            relpath=relpath,
            origin_url=canonical_origin,
        )


class DiscoveryCycleStatus(StrEnum):
    IDLE = "IDLE"
    COMPLETED = "COMPLETED"
    RETRY = "RETRY"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class DiscoveryCycle:
    status: DiscoveryCycleStatus
    sha256: str | None


class DiscoveryConsumer:
    def __init__(
        self,
        *,
        queue: FileDiscoverySink,
        resolver: SimpleLinkResolver,
        bytes_source: ArtifactBytesSource,
        quarantine: QuarantineStore,
        store: ArtifactStore,
        worker_id: str,
        lease_duration: timedelta = timedelta(minutes=5),
        retry_delay: timedelta = timedelta(seconds=5),
        max_attempts: int = 5,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(worker_id, str) or not worker_id.strip():
            raise ValueError("worker_id must not be blank")
        if lease_duration <= timedelta(0) or retry_delay < timedelta(0):
            raise ValueError("invalid discovery timing")
        if type(max_attempts) is not int or max_attempts <= 0:
            raise ValueError("max_attempts must be a positive integer")
        self._queue = queue
        self._resolver = resolver
        self._bytes_source = bytes_source
        self._quarantine = quarantine
        self._store = store
        self._worker_id = worker_id
        self._lease_duration = lease_duration
        self._retry_delay = retry_delay
        self._max_attempts = max_attempts
        self._now = now if now is not None else lambda: datetime.now(UTC)

    def recover_expired_claims(self) -> int:
        return self._queue.recover_expired_claims()

    def run_once(self) -> DiscoveryCycle:
        claim = self._queue.claim_next(self._worker_id, self._now() + self._lease_duration)
        if claim is None:
            return DiscoveryCycle(DiscoveryCycleStatus.IDLE, None)
        verified = None
        try:
            resolved = self._resolver.resolve(claim.candidate)
            candidate = ArtifactCandidate(
                stage=resolved.source_stage,
                project=resolved.project,
                version=resolved.version,
                filename=resolved.filename,
                sha256=resolved.sha256,
                origin_url=resolved.origin_url,
            )
            verified = self._quarantine.get_verified(candidate)
            if verified is None:
                verified = self._quarantine.persist(
                    candidate, self._bytes_source.iter_chunks(resolved)
                )
            close_owned(verified._stream, "verified discovery descriptor")
            discovered_at = self._now()
            self._store.discover_artifact(
                ArtifactInput(verified.sha256, verified.size_bytes, discovered_at),
                ReleaseInput(
                    stage=verified.stage,
                    project=verified.project,
                    version=verified.version,
                    filename=verified.filename,
                    sha256=verified.sha256,
                    origin_url=resolved.origin_url,
                    discovered_at=discovered_at,
                ),
            )
        except (TransitionConflict, QuarantineError, ValueError) as exc:
            self._queue.fail(claim, self._error_message(exc))
            return DiscoveryCycle(DiscoveryCycleStatus.FAILED, claim.candidate.sha256)
        except Exception as exc:
            self._queue.retry(
                claim,
                self._error_message(exc),
                delay=self._retry_delay,
                max_attempts=self._max_attempts,
            )
            status = (
                DiscoveryCycleStatus.FAILED
                if claim.attempt_count >= self._max_attempts
                else DiscoveryCycleStatus.RETRY
            )
            return DiscoveryCycle(status, claim.candidate.sha256)
        self._queue.complete(claim)
        return DiscoveryCycle(DiscoveryCycleStatus.COMPLETED, claim.candidate.sha256)

    @staticmethod
    def _error_message(exc: Exception) -> str:
        return f"{type(exc).__name__}: {str(exc)[:512]}"
