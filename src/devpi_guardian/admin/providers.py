"""Production adapters for the extended F11 administrator operations."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import closing

from devpi_guardian.admin.service import AdminProviderError, AdminRequestError
from devpi_guardian.analyzers import Finding
from devpi_guardian.audit import verify_audit_chain
from devpi_guardian.baseline import artifact_kind
from devpi_guardian.policy import PolicyConfig, PolicyEngine, PolicyInputError
from devpi_guardian.verdicts.db import ConnectionFactory
from devpi_guardian.verdicts.errors import StoreUnavailable
from devpi_guardian.verdicts.models import Decision, validate_sha256
from devpi_guardian.verdicts.reader import SQLiteVerdictReader
from devpi_guardian.verdicts.store import SQLiteArtifactStore
from devpi_guardian.worker.discovery import DiscoveryUnavailable, FileDiscoverySink
from devpi_guardian.worker.models import AnalysisEvidence, AnalysisReport, AnalysisStep

_POLICY_FIELDS = frozenset(
    {
        "name",
        "revision",
        "algorithm_version",
        "require_baseline",
        "require_f9_pair",
        "score_allow",
        "score_review",
        "score_no_pair",
        "score_no_baseline",
        "score_analyzer_error",
        "score_deny",
        "f7_tier_scores",
        "rule_escalations",
    }
)


def _policy_config(value: Mapping[str, object]) -> PolicyConfig:
    if not isinstance(value, Mapping):
        raise ValueError("policy must be an object")
    data = dict(value)
    coverage = data.pop("coverage", None)
    if coverage is not None:
        if not isinstance(coverage, Mapping):
            raise ValueError("policy coverage must be an object")
        data.setdefault("require_baseline", coverage.get("require_baseline"))
        data.setdefault("require_f9_pair", coverage.get("require_f9_pair"))
    scores = data.pop("scores", None)
    if scores is not None:
        if not isinstance(scores, Mapping):
            raise ValueError("policy scores must be an object")
        for key in ("allow", "review", "no_pair", "no_baseline", "analyzer_error", "deny"):
            if key in scores:
                data.setdefault(f"score_{key}", scores[key])
    unknown = set(data).difference(_POLICY_FIELDS)
    if unknown:
        raise ValueError(f"unknown policy fields: {', '.join(sorted(unknown))}")
    try:
        return PolicyConfig(**data)
    except TypeError as exc:
        raise ValueError(str(exc)) from exc


class ProductionAdminProviders:
    """SQLite/F5/F10 backed implementation of all optional F11 ports."""

    def __init__(
        self,
        *,
        factory: ConnectionFactory,
        reader: SQLiteVerdictReader,
        store: SQLiteArtifactStore,
        discovery: FileDiscoverySink,
        policy_engine: PolicyEngine,
        worker: object | None,
    ) -> None:
        self._factory = factory
        self._reader = reader
        self._store = store
        self._discovery = discovery
        self._policy_engine = policy_engine
        self._worker = worker

    def worker_health(self) -> Mapping[str, object]:
        try:
            queue = {
                state.lower(): self._discovery.count(state)
                for state in ("PENDING", "PROCESSING", "COMPLETED", "FAILED")
            }
            with closing(self._factory.connect()) as connection:
                rows = connection.execute(
                    "SELECT state, COUNT(*) AS count FROM artifacts GROUP BY state"
                ).fetchall()
            artifacts = {str(row["state"]).lower(): row["count"] for row in rows}
        except DiscoveryUnavailable as exc:
            raise AdminProviderError("worker health is unavailable") from exc
        except (OSError, sqlite3.Error) as exc:
            raise StoreUnavailable("guardian database unavailable") from exc
        runtime = {"status": "not_registered"}
        health = getattr(self._worker, "worker_health", None)
        if callable(health):
            runtime = dict(health())
        return {
            **runtime,
            "queue": queue,
            "artifacts": artifacts,
            "audit_chain": self.audit_health(),
        }

    def audit_health(self) -> Mapping[str, object]:
        """Return bounded audit-chain status for the F11 health endpoint."""
        try:
            verification = verify_audit_chain(self._factory)
        except (StoreUnavailable, OSError, sqlite3.Error) as exc:
            raise AdminProviderError("audit verification is unavailable") from exc
        reason = None if verification.valid else "audit_chain_invalid"
        return {
            "valid": verification.valid,
            "count": verification.count,
            "head": verification.head,
            "reason": reason,
        }

    def list_audit(
        self,
        *,
        sha256: str | None,
        actor: str | None,
        action: str | None,
        limit: int,
        offset: int,
    ) -> Mapping[str, object]:
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        if type(offset) is not int or offset < 0:
            raise ValueError("offset must be non-negative")
        conditions: list[str] = []
        parameters: list[object] = []
        if sha256 is not None:
            conditions.append("sha256 = ?")
            parameters.append(validate_sha256(sha256))
        for name, value in (("actor", actor), ("action", action)):
            if value is None:
                continue
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must not be blank")
            conditions.append(f"{name} = ?")
            parameters.append(value)
        where = "" if not conditions else " WHERE " + " AND ".join(conditions)
        try:
            with closing(self._factory.connect()) as connection:
                # A deferred SQLite transaction otherwise permits COUNT and
                # page reads to observe different commits.
                connection.execute("BEGIN")
                total = connection.execute(
                    f"SELECT COUNT(*) FROM audit_events{where}", parameters
                ).fetchone()[0]
                rows = connection.execute(
                    f"""
                    SELECT id, occurred_at, actor, action, sha256,
                           previous_decision, new_decision, reason,
                           policy_version, analyzer_version, previous_hash,
                           event_hash
                    FROM audit_events{where}
                    ORDER BY id DESC LIMIT ? OFFSET ?
                    """,
                    (*parameters, limit, offset),
                ).fetchall()
        except sqlite3.Error as exc:
            raise StoreUnavailable("guardian database unavailable") from exc
        return {"items": [dict(row) for row in rows], "total": total}

    def artifact_diff(self, sha256: str) -> Mapping[str, object]:
        digest = validate_sha256(sha256)
        try:
            return self._artifact_diff(digest)
        except ValueError as exc:
            raise AdminProviderError("artifact diff is unavailable") from exc

    def _artifact_diff(self, sha256: str) -> Mapping[str, object]:
        details = self._reader.get_artifact_details(sha256)
        findings = []
        changed_files: set[str] = set()
        files = {"added": [], "changed": [], "removed": []}
        for evidence in details.evidence:
            if evidence.details.get("analyzer") != "F7":
                continue
            if evidence.details.get("kind") == "file_diff":
                for key in files:
                    value = evidence.details.get(key, [])
                    if not isinstance(value, (list, tuple)) or not all(
                        isinstance(item, str) for item in value
                    ):
                        raise ValueError("stored baseline file diff is invalid")
                    files[key] = list(value)
                changed_files.update((*files["added"], *files["changed"], *files["removed"]))
                continue
            if evidence.file_path is not None:
                changed_files.add(evidence.file_path)
            findings.append(
                {
                    "rule": evidence.rule_id,
                    "action": evidence.action.value,
                    "file": evidence.file_path,
                    "line": evidence.line,
                    "message": evidence.message,
                    "origin": evidence.details.get("origin"),
                    "snippet": evidence.details.get("snippet"),
                }
            )
        return {
            "sha256": details.summary.sha256,
            "has_baseline": details.baseline_sha256 is not None,
            "baseline_sha256": details.baseline_sha256,
            "baseline_tier": details.baseline_tier,
            "files": files,
            "changed_files": sorted(changed_files),
            "findings": findings,
        }

    def list_baselines(self, project: str) -> Sequence[Mapping[str, object]]:
        if not isinstance(project, str) or not project.strip():
            raise AdminRequestError("invalid project")
        return tuple(
            {
                "stage": release.stage,
                "project": release.project,
                "version": release.version,
                "filename": release.filename,
                "sha256": release.sha256,
                "origin_url": release.origin_url,
            }
            for release in self._reader.list_allowed_releases(project)
        )

    def add_baseline(self, sha256: str, *, actor: str, reason: str) -> None:
        self._store.set_baseline_eligibility(sha256, enabled=True, actor=actor, reason=reason)

    def remove_baseline(self, sha256: str, *, actor: str, reason: str) -> None:
        self._store.set_baseline_eligibility(sha256, enabled=False, actor=actor, reason=reason)

    def import_baselines(
        self,
        records: Sequence[Mapping[str, object]],
        *,
        actor: str,
        reason: str,
    ) -> Mapping[str, object]:
        digests = []
        try:
            for record in records:
                if set(record) != {"sha256"}:
                    raise ValueError("baseline records must contain only sha256")
                digests.append(validate_sha256(record["sha256"]))
        except (TypeError, ValueError) as exc:
            raise AdminRequestError("invalid baseline records") from exc
        for digest in dict.fromkeys(digests):
            self.add_baseline(digest, actor=actor, reason=reason)
        return {"imported": len(dict.fromkeys(digests))}

    def validate_policy(self, policy: Mapping[str, object]) -> Mapping[str, object]:
        try:
            engine = PolicyEngine(_policy_config(policy))
        except (TypeError, ValueError) as exc:
            raise AdminRequestError("invalid policy") from exc
        return {
            "valid": True,
            "policy_version": engine.policy_version,
            "policy": engine.config.canonical_dict(),
        }

    def simulate_policy(
        self,
        policy: Mapping[str, object],
        *,
        sha256: str,
    ) -> Mapping[str, object]:
        try:
            engine = PolicyEngine(_policy_config(policy))
        except (TypeError, ValueError) as exc:
            raise AdminRequestError("invalid policy") from exc
        digest = validate_sha256(sha256)
        try:
            report = self._stored_report(digest)
        except ValueError as exc:
            raise AdminProviderError("stored analysis report is unavailable") from exc
        try:
            result = engine.assess(report)
        except (PolicyInputError, TypeError, ValueError) as exc:
            raise AdminProviderError("stored analysis report is unavailable") from exc
        return {
            "sha256": sha256,
            "decision": result.decision.value,
            "score": result.score,
            "reasons": list(result.reason_codes),
            "policy_version": result.policy_version,
            "analyzer_version": result.analyzer_version,
            "baseline_sha256": result.baseline_sha256,
            "baseline_tier": result.baseline_tier,
        }

    def _stored_report(self, sha256: str) -> AnalysisReport:
        details = self._reader.get_artifact_details(sha256)
        evidence = []
        analyzer_errors: set[str] = set()
        for record in details.evidence:
            if record.details.get("kind") == "file_diff":
                continue
            analyzer = record.details.get("analyzer")
            if analyzer not in ("F7", "F8", "F9"):
                raise ValueError("stored evidence has no valid analyzer attribution")
            if record.action is Decision.ALLOW:
                raise ValueError("stored analysis evidence cannot have ALLOW action")
            finding = Finding(
                rule=record.rule_id,
                action=record.action.value,
                file=record.file_path or "<artifact>",
                line=record.line,
                snippet=str(record.details.get("snippet", "")),
                message=record.message,
                source=record.details.get("source"),
                sink=record.details.get("sink"),
            )
            if finding.rule == "analyzer_error":
                analyzer_errors.add(analyzer)
            evidence.append(
                AnalysisEvidence(
                    analyzer=analyzer,
                    finding=finding,
                    origin=record.details.get("origin"),
                    baseline_tier=(details.baseline_tier if analyzer == "F7" else None),
                )
            )

        has_pair = False
        for release in details.releases:
            siblings = self._reader.list_release_artifacts(release.project, release.version)
            kinds = {artifact_kind(item.filename) for item in siblings}
            if {"sdist", "wheel"}.issubset(kinds):
                has_pair = True
                break
        steps = (
            AnalysisStep(
                "F7",
                "error"
                if "F7" in analyzer_errors
                else "completed"
                if details.baseline_sha256 is not None
                else "skipped",
                None if details.baseline_sha256 is not None else "no approved baseline",
            ),
            AnalysisStep("F8", "error" if "F8" in analyzer_errors else "completed"),
            AnalysisStep(
                "F9",
                "error" if "F9" in analyzer_errors else "completed" if has_pair else "skipped",
                None if has_pair else "same-release pair unavailable",
            ),
        )
        analyzer_version = details.analyzer_version
        if analyzer_version is None:
            raise ValueError("artifact has no stored analysis report")
        return AnalysisReport(
            analyzer_version=analyzer_version,
            has_baseline=details.baseline_sha256 is not None,
            baseline_sha256=details.baseline_sha256,
            baseline_tier=details.baseline_tier,
            evidence=tuple(evidence),
            steps=steps,
        )
