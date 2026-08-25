from __future__ import annotations

from types import SimpleNamespace

from devpi_guardian.admin.service import AdminFeatureUnavailable
from devpi_guardian.admin.views import (
    ADMIN_SERVICE_REGISTRY_KEY,
    add_baseline,
    approve_artifact,
    artifact_diff,
    import_baselines,
    inspect_artifact,
    list_audit,
    list_baselines,
    list_quarantine,
    policy_simulate,
    policy_validate,
    remove_baseline,
    revoke_artifact,
)
from devpi_guardian.verdicts.errors import ArtifactNotFound, TransitionConflict
from devpi_guardian.verdicts.models import ArtifactState

SHA256 = "a" * 64


class Service:
    def list_quarantine(self, *, states, limit, offset):
        self.list_call = states, limit, offset
        return SimpleNamespace(items=(), total=0, limit=limit, offset=offset)

    def inspect(self, sha256):
        self.inspect_call = sha256
        if sha256 == "b" * 64:
            raise ArtifactNotFound(sha256)
        return SimpleNamespace(summary=SimpleNamespace(sha256=sha256))

    def approve(self, sha256, *, actor, reason):
        self.approve_call = sha256, actor, reason
        if reason == "conflict":
            raise TransitionConflict(sha256)

    def revoke(self, sha256, *, actor, reason):
        self.revoke_call = sha256, actor, reason

    def artifact_diff(self, sha256):
        return {"sha256": sha256, "files": {"added": ["pkg/new.py"]}}

    def list_audit(self, *, sha256, actor, action, limit, offset):
        self.audit_call = sha256, actor, action, limit, offset
        return {"items": [], "total": 0}

    def list_baselines(self, project):
        self.baseline_list_call = project
        return ({"project": project, "sha256": SHA256},)

    def add_baseline(self, sha256, *, actor, reason):
        self.baseline_add_call = sha256, actor, reason

    def remove_baseline(self, sha256, *, actor, reason):
        self.baseline_remove_call = sha256, actor, reason

    def import_baselines(self, records, *, actor, reason):
        self.baseline_import_call = records, actor, reason
        return {"imported": len(records)}

    def validate_policy(self, policy):
        self.policy_validate_call = policy
        return {"valid": True}

    def simulate_policy(self, policy, *, sha256):
        self.policy_simulate_call = policy, sha256
        return {"decision": "REVIEW", "sha256": sha256}


def request(service, *, sha256=SHA256, params=None, body=None, actor="root"):
    return SimpleNamespace(
        registry={ADMIN_SERVICE_REGISTRY_KEY: service},
        matchdict={"sha256": sha256},
        params=params or {},
        json_body=body or {},
        authenticated_userid=actor,
    )


def test_list_quarantine_validates_filters_and_serializes_page() -> None:
    service = Service()
    response = list_quarantine(
        request(service, params={"state": "REVIEW,DENY", "limit": "20", "offset": "5"})
    )

    assert response.status_code == 200
    assert response.json_body == {"items": [], "total": 0, "limit": 20, "offset": 5}
    assert service.list_call == ((ArtifactState.REVIEW, ArtifactState.DENY), 20, 5)


def test_inspect_maps_missing_artifact_to_stable_404() -> None:
    response = inspect_artifact(request(Service(), sha256="b" * 64))
    assert response.status_code == 404
    assert response.json_body["error"]["code"] == "artifact_not_found"


def test_approve_uses_authenticated_actor_and_requires_reason() -> None:
    service = Service()
    response = approve_artifact(
        request(service, body={"reason": "reviewed"}, actor="guardian-admin")
    )
    assert response.status_code == 200
    assert service.approve_call == (SHA256, "guardian-admin", "reviewed")

    invalid = approve_artifact(request(service, body={"reason": ""}))
    assert invalid.status_code == 400
    assert invalid.json_body["error"]["code"] == "invalid_request"


def test_approve_maps_state_conflict_to_409() -> None:
    response = approve_artifact(request(Service(), body={"reason": "conflict"}))
    assert response.status_code == 409
    assert response.json_body["error"]["code"] == "transition_conflict"


def test_revoke_uses_authenticated_actor_and_reason() -> None:
    service = Service()

    response = revoke_artifact(
        request(service, body={"reason": "withdrawn"}, actor="guardian-admin")
    )

    assert response.status_code == 200
    assert response.json_body["status"] == "override_revoked"
    assert service.revoke_call == (SHA256, "guardian-admin", "withdrawn")


def test_diff_audit_and_baseline_reads_have_stable_responses() -> None:
    service = Service()
    diff = artifact_diff(request(service))
    audit = list_audit(
        request(
            service,
            params={
                "sha256": SHA256,
                "actor": "root",
                "action": "artifact.approve",
                "limit": "20",
                "offset": "5",
            },
        )
    )
    baselines = list_baselines(request(service, params={"project": "Demo_Pkg"}))
    assert diff.json_body["diff"]["sha256"] == SHA256
    assert audit.json_body == {"items": [], "total": 0, "limit": 20, "offset": 5}
    assert service.audit_call == (SHA256, "root", "artifact.approve", 20, 5)
    assert baselines.json_body["items"][0]["project"] == "Demo_Pkg"


def test_baseline_mutations_use_authenticated_actor_and_reason() -> None:
    service = Service()
    add = add_baseline(request(service, body={"sha256": SHA256, "reason": "trusted"}))
    remove = remove_baseline(request(service, body={"reason": "revoked"}))
    imported = import_baselines(
        request(service, body={"records": [{"sha256": SHA256}], "reason": "bootstrap"})
    )
    assert add.status_code == 200
    assert remove.status_code == 200
    assert imported.json_body["imported"] == 1
    assert service.baseline_add_call == (SHA256, "root", "trusted")
    assert service.baseline_remove_call == (SHA256, "root", "revoked")
    assert service.baseline_import_call == (({"sha256": SHA256},), "root", "bootstrap")


def test_policy_validate_and_simulate_require_policy_object() -> None:
    service = Service()
    valid = policy_validate(request(service, body={"policy": {"revision": "2"}}))
    simulated = policy_simulate(
        request(service, body={"policy": {"revision": "2"}, "sha256": SHA256})
    )
    assert valid.json_body == {"valid": True}
    assert simulated.json_body["decision"] == "REVIEW"
    assert service.policy_validate_call == {"revision": "2"}
    assert service.policy_simulate_call == ({"revision": "2"}, SHA256)


def test_unconnected_feature_returns_specific_retryable_503() -> None:
    class UnavailableService(Service):
        def artifact_diff(self, sha256):
            raise AdminFeatureUnavailable("artifact_diff")

    response = artifact_diff(request(UnavailableService()))
    assert response.status_code == 503
    assert response.json_body == {
        "error": {
            "code": "artifact_diff_unavailable",
            "message": "artifact_diff provider is unavailable",
        }
    }
