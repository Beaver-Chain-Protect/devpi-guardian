from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from devpi_guardian.admin.providers import ProductionAdminProviders
from devpi_guardian.admin.service import AdminProviderError, AdminRequestError
from devpi_guardian.audit import SQLiteAuditWriter
from devpi_guardian.policy import PolicyEngine
from devpi_guardian.verdicts.db import ConnectionFactory, migrate
from devpi_guardian.verdicts.errors import TransitionConflict
from devpi_guardian.verdicts.models import (
    ArtifactInput,
    Decision,
    EvidenceInput,
    EvidenceRecord,
    ReleaseInput,
    VerdictInput,
)
from devpi_guardian.verdicts.reader import SQLiteVerdictReader
from devpi_guardian.verdicts.store import SQLiteArtifactStore
from devpi_guardian.worker.discovery import FileDiscoverySink

NOW = datetime(2026, 8, 25, tzinfo=UTC)
ALLOW_SHA = "a" * 64
REVIEW_SHA = "b" * 64


def _record(
    store: SQLiteArtifactStore,
    *,
    sha256: str,
    version: str,
    decision: Decision,
    evidence: tuple[EvidenceInput, ...] = (),
) -> None:
    filename = f"demo-{version}-py3-none-any.whl"
    store.discover_artifact(
        ArtifactInput(sha256=sha256, size_bytes=12, discovered_at=NOW),
        ReleaseInput(
            stage="root/pypi",
            project="demo",
            version=version,
            filename=filename,
            sha256=sha256,
            origin_url=f"https://devpi.test/root/pypi/+f/{sha256[:3]}/{filename}",
            discovered_at=NOW,
        ),
    )
    claim = store.claim_next("worker", NOW + timedelta(minutes=5))
    assert claim is not None and claim.sha256 == sha256
    store.record_verdict(
        claim,
        VerdictInput(
            sha256=sha256,
            decision=decision,
            score=0 if decision is Decision.ALLOW else 70,
            policy_version="policy-1",
            analyzer_version="analyzer-1",
            baseline_sha256=None,
            baseline_tier=None,
            created_at=NOW,
        ),
        evidence,
    )


def _providers(tmp_path):
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    store = SQLiteArtifactStore(factory, SQLiteAuditWriter(), now=lambda: NOW)
    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    discovery = FileDiscoverySink(tmp_path / "discovery", now=lambda: NOW)
    providers = ProductionAdminProviders(
        factory=factory,
        reader=reader,
        store=store,
        discovery=discovery,
        policy_engine=PolicyEngine(now=lambda: NOW),
        worker=None,
    )
    return providers, store, reader


def test_providers_expose_audit_diff_policy_and_worker_health(tmp_path) -> None:
    providers, store, _reader = _providers(tmp_path)
    _record(
        store,
        sha256=REVIEW_SHA,
        version="2.0",
        decision=Decision.REVIEW,
        evidence=(
            EvidenceInput(
                rule_id="baseline_file_diff",
                action=Decision.ALLOW,
                file_path=None,
                line=None,
                message="baseline file delta",
                details={
                    "analyzer": "F7",
                    "kind": "file_diff",
                    "added": ["demo/new.py"],
                    "changed": ["demo/update.py"],
                    "removed": [],
                },
            ),
        ),
    )

    audit = providers.list_audit(
        sha256=REVIEW_SHA,
        actor=None,
        action=None,
        limit=50,
        offset=0,
    )
    diff = providers.artifact_diff(REVIEW_SHA)
    validation = providers.validate_policy({})
    simulation = providers.simulate_policy({}, sha256=REVIEW_SHA)
    health = providers.worker_health()

    assert audit["total"] == 3
    assert diff == {
        "sha256": REVIEW_SHA,
        "has_baseline": False,
        "baseline_sha256": None,
        "baseline_tier": None,
        "files": {
            "added": ["demo/new.py"],
            "changed": ["demo/update.py"],
            "removed": [],
        },
        "changed_files": ["demo/new.py", "demo/update.py"],
        "findings": [],
    }
    assert validation["valid"] is True
    assert simulation["decision"] == "REVIEW"
    assert "coverage.no_baseline" in simulation["reasons"]
    assert health["status"] == "not_registered"
    assert health["queue"]["pending"] == 0
    assert health["artifacts"]["review"] == 1
    assert health["audit_chain"]["valid"] is True
    assert health["audit_chain"]["count"] == 3
    assert health["audit_chain"]["reason"] is None


def test_policy_input_is_client_error_but_corrupt_report_is_provider_error(tmp_path, monkeypatch):
    providers, store, reader = _providers(tmp_path)
    _record(store, sha256=REVIEW_SHA, version="2.0", decision=Decision.REVIEW)

    with pytest.raises(AdminRequestError, match="invalid policy"):
        providers.validate_policy({"unexpected": "field"})

    details = reader.get_artifact_details(REVIEW_SHA)
    corrupt = replace(
        details,
        evidence=(
            replace(
                details.evidence[0]
                if details.evidence
                else EvidenceRecord("corrupt", Decision.DENY, None, None, "corrupt", {}),
                details={"analyzer": "F10"},
            ),
        ),
    )
    monkeypatch.setattr(reader, "get_artifact_details", lambda _sha256: corrupt)
    with pytest.raises(AdminProviderError, match="stored analysis report"):
        providers.simulate_policy({}, sha256=REVIEW_SHA)

    with pytest.raises(AdminRequestError, match="baseline records"):
        providers.import_baselines(
            ({"sha256": "not-a-digest", "extra": True},), actor="root", reason="bad"
        )
    with pytest.raises(AdminRequestError, match="invalid project"):
        providers.list_baselines("")


def test_baseline_management_is_separate_from_install_decision_and_audited(tmp_path) -> None:
    providers, store, reader = _providers(tmp_path)
    _record(store, sha256=ALLOW_SHA, version="1.0", decision=Decision.ALLOW)
    _record(store, sha256=REVIEW_SHA, version="2.0", decision=Decision.REVIEW)

    assert [item["sha256"] for item in providers.list_baselines("demo")] == [ALLOW_SHA]
    providers.remove_baseline(ALLOW_SHA, actor="root", reason="retire baseline")
    assert providers.list_baselines("demo") == ()
    assert reader.get_effective_decision(ALLOW_SHA).allowed is True

    providers.add_baseline(ALLOW_SHA, actor="root", reason="restore baseline")
    assert [item["sha256"] for item in providers.list_baselines("demo")] == [ALLOW_SHA]
    with pytest.raises(TransitionConflict):
        providers.add_baseline(REVIEW_SHA, actor="root", reason="unsafe baseline")

    audit = providers.list_audit(
        sha256=ALLOW_SHA,
        actor="root",
        action=None,
        limit=50,
        offset=0,
    )
    assert [item["action"] for item in audit["items"]] == [
        "baseline.added",
        "baseline.removed",
    ]
