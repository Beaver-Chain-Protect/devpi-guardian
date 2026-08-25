"""Application service for audited F11 administrator operations."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Protocol

from devpi_guardian.verdicts.models import (
    ArtifactAdminDetails,
    ArtifactState,
    Decision,
    ManualOverrideInput,
    QuarantinePage,
)


class AdminMutationsUnavailable(RuntimeError):
    """F12's transactional audit writer has not been connected yet."""


class AdminRequestError(ValueError):
    """A validated administrator request cannot be represented by the domain DTO."""


class AdminFeatureUnavailable(RuntimeError):
    """A feature-owning component has not connected its F11 provider yet."""

    def __init__(self, feature: str) -> None:
        super().__init__(f"{feature} provider is unavailable")
        self.feature = feature


class AdminProviderError(RuntimeError):
    """A provider explicitly reports a sanitized, retryable failure."""


class AdminReader(Protocol):
    def list_quarantine(
        self,
        *,
        states: tuple[ArtifactState, ...],
        limit: int,
        offset: int,
    ) -> QuarantinePage: ...

    def get_artifact_details(self, sha256: str) -> ArtifactAdminDetails: ...

    def health(self) -> dict[str, object]: ...


class AdminStore(Protocol):
    def set_manual_override(self, override: ManualOverrideInput) -> None: ...

    def request_rescan(self, sha256: str, actor: str, reason: str) -> None: ...

    def revoke_manual_override(self, sha256: str, actor: str, reason: str) -> None: ...


class WorkerHealthReader(Protocol):
    def worker_health(self) -> Mapping[str, object]: ...


class AuditReader(Protocol):
    def list_audit(
        self,
        *,
        sha256: str | None,
        actor: str | None,
        action: str | None,
        limit: int,
        offset: int,
    ) -> Mapping[str, object]: ...


class ArtifactDiffReader(Protocol):
    def artifact_diff(self, sha256: str) -> Mapping[str, object]: ...


class BaselineManager(Protocol):
    def list_baselines(self, project: str) -> Sequence[Mapping[str, object]]: ...

    def add_baseline(self, sha256: str, *, actor: str, reason: str) -> None: ...

    def remove_baseline(self, sha256: str, *, actor: str, reason: str) -> None: ...

    def import_baselines(
        self,
        records: Sequence[Mapping[str, object]],
        *,
        actor: str,
        reason: str,
    ) -> Mapping[str, object]: ...


class PolicyManager(Protocol):
    def validate_policy(self, policy: Mapping[str, object]) -> Mapping[str, object]: ...

    def simulate_policy(
        self,
        policy: Mapping[str, object],
        *,
        sha256: str,
    ) -> Mapping[str, object]: ...


class GuardianAdminService:
    def __init__(
        self,
        *,
        reader: AdminReader,
        store: AdminStore | None,
        worker_health_reader: WorkerHealthReader | None = None,
        audit_reader: AuditReader | None = None,
        diff_reader: ArtifactDiffReader | None = None,
        baseline_manager: BaselineManager | None = None,
        policy_manager: PolicyManager | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._reader = reader
        self._store = store
        self._worker_health_reader = worker_health_reader
        self._audit_reader = audit_reader
        self._diff_reader = diff_reader
        self._baseline_manager = baseline_manager
        self._policy_manager = policy_manager
        self._now = now if now is not None else lambda: datetime.now(UTC)
        self._require_capabilities(reader, ("list_quarantine", "get_artifact_details", "health"))
        if store is not None:
            self._require_capabilities(
                store, ("set_manual_override", "request_rescan", "revoke_manual_override")
            )
        for provider, capabilities in (
            (worker_health_reader, ("worker_health",)),
            (audit_reader, ("list_audit",)),
            (diff_reader, ("artifact_diff",)),
            (
                baseline_manager,
                ("list_baselines", "add_baseline", "remove_baseline", "import_baselines"),
            ),
            (policy_manager, ("validate_policy", "simulate_policy")),
        ):
            if provider is not None:
                self._require_capabilities(provider, capabilities)

    def list_quarantine(
        self,
        *,
        states: tuple[ArtifactState, ...],
        limit: int,
        offset: int,
    ) -> QuarantinePage:
        result = self._reader.list_quarantine(states=states, limit=limit, offset=offset)
        if not isinstance(result, QuarantinePage):
            raise AdminFeatureUnavailable("reader")
        return result

    def inspect(self, sha256: str) -> ArtifactAdminDetails:
        result = self._reader.get_artifact_details(sha256)
        if not isinstance(result, ArtifactAdminDetails):
            raise AdminFeatureUnavailable("reader")
        return result

    def approve(self, sha256: str, *, actor: str, reason: str) -> None:
        self._override(sha256, Decision.ALLOW, actor, reason, None)

    def block(self, sha256: str, *, actor: str, reason: str) -> None:
        self._override(sha256, Decision.DENY, actor, reason, None)

    def add_exception(
        self,
        sha256: str,
        *,
        actor: str,
        reason: str,
        expires_at: datetime,
    ) -> None:
        self._override(sha256, Decision.ALLOW, actor, reason, expires_at)

    def _override(
        self,
        sha256: str,
        decision: Decision,
        actor: str,
        reason: str,
        expires_at: datetime | None,
    ) -> None:
        store = self._require_store()
        try:
            override = ManualOverrideInput(
                sha256=sha256,
                decision=decision,
                actor=actor,
                reason=reason,
                created_at=self._checked_now(),
                expires_at=expires_at,
            )
        except (TypeError, ValueError) as exc:
            raise AdminRequestError("invalid administrator mutation") from exc
        self._require_none(store.set_manual_override(override))

    def rescan(self, sha256: str, *, actor: str, reason: str) -> None:
        self._require_none(self._require_store().request_rescan(sha256, actor, reason))

    def revoke(self, sha256: str, *, actor: str, reason: str) -> None:
        self._require_none(self._require_store().revoke_manual_override(sha256, actor, reason))

    def health(self) -> dict[str, object]:
        result = self._reader.health()
        if not isinstance(result, Mapping):
            raise AdminMutationsUnavailable("guardian health provider is malformed")
        result = dict(result)
        result["mutations_ready"] = self._store is not None
        result["worker"] = (
            self._mapping_result(self._worker_health_reader.worker_health(), "worker")
            if self._worker_health_reader is not None
            else {"status": "unavailable"}
        )
        result["features"] = {
            "audit": self._audit_reader is not None,
            "artifact_diff": self._diff_reader is not None,
            "baseline": self._baseline_manager is not None,
            "policy": self._policy_manager is not None,
        }
        return result

    def list_audit(
        self,
        *,
        sha256: str | None,
        actor: str | None,
        action: str | None,
        limit: int,
        offset: int,
    ) -> Mapping[str, object]:
        return self._mapping_result(
            self._require_provider(self._audit_reader, "audit").list_audit(
                sha256=sha256,
                actor=actor,
                action=action,
                limit=limit,
                offset=offset,
            ),
            "audit",
        )

    def artifact_diff(self, sha256: str) -> Mapping[str, object]:
        return self._mapping_result(
            self._require_provider(self._diff_reader, "artifact_diff").artifact_diff(sha256),
            "artifact_diff",
        )

    def list_baselines(self, project: str) -> Sequence[Mapping[str, object]]:
        result = self._require_provider(self._baseline_manager, "baseline").list_baselines(project)
        if isinstance(result, (str, bytes, bytearray)) or not isinstance(result, Sequence):
            raise AdminFeatureUnavailable("baseline")
        return result

    def add_baseline(self, sha256: str, *, actor: str, reason: str) -> None:
        result = self._require_provider(self._baseline_manager, "baseline").add_baseline(
            sha256,
            actor=actor,
            reason=reason,
        )
        self._require_none(result)

    def remove_baseline(self, sha256: str, *, actor: str, reason: str) -> None:
        result = self._require_provider(self._baseline_manager, "baseline").remove_baseline(
            sha256,
            actor=actor,
            reason=reason,
        )
        self._require_none(result)

    def import_baselines(
        self,
        records: Sequence[Mapping[str, object]],
        *,
        actor: str,
        reason: str,
    ) -> Mapping[str, object]:
        return self._mapping_result(
            self._require_provider(self._baseline_manager, "baseline").import_baselines(
                records,
                actor=actor,
                reason=reason,
            ),
            "baseline",
        )

    def validate_policy(self, policy: Mapping[str, object]) -> Mapping[str, object]:
        return self._mapping_result(
            self._require_provider(self._policy_manager, "policy").validate_policy(policy), "policy"
        )

    def simulate_policy(
        self,
        policy: Mapping[str, object],
        *,
        sha256: str,
    ) -> Mapping[str, object]:
        return self._mapping_result(
            self._require_provider(self._policy_manager, "policy").simulate_policy(
                policy,
                sha256=sha256,
            ),
            "policy",
        )

    def _require_store(self) -> AdminStore:
        if self._store is None:
            raise AdminMutationsUnavailable("transactional audit writer is unavailable")
        return self._store

    @staticmethod
    def _require_capabilities(provider: object, names: tuple[str, ...]) -> None:
        if not all(callable(getattr(provider, name, None)) for name in names):
            raise TypeError("administrator provider is missing required capabilities")

    @staticmethod
    def _require_none(result: object) -> None:
        if result is not None:
            raise AdminMutationsUnavailable("guardian mutation did not complete safely")

    def _checked_now(self) -> datetime:
        value = self._now()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise AdminRequestError("administrator clock must be timezone-aware")
        return value

    @staticmethod
    def _mapping_result(value: object, feature: str) -> Mapping[str, object]:
        if not isinstance(value, Mapping):
            raise AdminFeatureUnavailable(feature)
        return value

    @staticmethod
    def _require_provider(provider, feature: str):
        if provider is None:
            raise AdminFeatureUnavailable(feature)
        return provider
