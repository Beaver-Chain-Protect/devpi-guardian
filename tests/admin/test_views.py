from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from devpi_guardian.admin.service import AdminFeatureUnavailable, AdminProviderError
from devpi_guardian.admin.views import (
    ADMIN_SERVICE_REGISTRY_KEY,
    _response,
    add_baseline,
    approve_artifact,
    artifact_diff,
    configure_admin_routes,
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
from devpi_guardian.verdicts.models import (
    ArtifactAdminDetails,
    ArtifactAdminSummary,
    ArtifactState,
    Decision,
    DecisionSource,
    EvidenceRecord,
    QuarantinePage,
)

SHA256 = "a" * 64


def test_response_defense_in_depth_sanitizes_diagnostic_fields() -> None:
    response = _response(
        {
            "worker": {
                "last_error": "RuntimeError: token=secret path=/Users/alice/private/file",
            }
        }
    )

    rendered = response.json_body["worker"]["last_error"]
    assert "secret" not in rendered
    assert "/Users/alice/private/file" not in rendered
    assert rendered.startswith("RuntimeError: token=[REDACTED]")


def test_response_defense_in_depth_sanitizes_legacy_evidence_without_redacting_sha() -> None:
    digest = "a" * 64
    secret_url = "https://user-secret@example.invalid/pkg.whl?token=query-secret"
    response = _response(
        {
            "artifact": {
                "summary": {"sha256": digest},
                "evidence": [
                    {
                        "message": f"GET {secret_url}",
                        "file_path": "/Users/alice/My Secret/file.whl",
                        "details": {
                            "snippet": "{'auth_token': 'dict-auth-secret'}",
                            "source": secret_url,
                        },
                    }
                ],
            },
            "diff": {
                "sha256": digest,
                "findings": [{"file": "/Users/alice/My Secret/file.whl"}],
            },
        }
    )

    rendered = str(response.json_body)
    for secret in (
        "user-secret",
        "query-secret",
        "dict-auth-secret",
        "/Users/alice/My Secret/file.whl",
    ):
        assert secret not in rendered
    assert response.json_body["artifact"]["summary"]["sha256"] == digest
    assert response.json_body["diff"]["sha256"] == digest


def test_response_defense_in_depth_sanitizes_structured_escaped_credentials_and_paths() -> None:
    digest = "a" * 64
    response = _response(
        {
            "artifact": {
                "summary": {"sha256": digest, "baseline_sha256": digest},
                "evidence": [
                    {
                        "details": {
                            "message": {
                                "client_secret": r"abc\"def",
                                "Authorization": r"Bearer abc\"def",
                                "posix_path": "/tmp/My Secret/cache dir",
                                "windows_path": r"C:\My Secret\cache dir",
                                "sha256": digest,
                            },
                            "sha256": {"value": "https://user:secret@example.invalid/a.whl"},
                            "baseline_sha256": ["https://user:secret@example.invalid/a.whl"],
                        }
                    }
                ],
            }
        }
    )

    details = response.json_body["artifact"]["evidence"][0]["details"]
    rendered = str(response.json_body)

    assert details["message"]["client_secret"] == "[REDACTED]"
    assert details["message"]["Authorization"] == "[REDACTED]"
    assert "abc" not in rendered
    assert "def" not in rendered
    assert "/tmp/My Secret/cache dir" not in rendered
    assert r"C:\My Secret\cache dir" not in rendered
    assert details["message"]["sha256"] == digest
    assert details["sha256"] == {"value": "[URL]"}
    assert details["baseline_sha256"] == ["[URL]"]
    assert response.json_body["artifact"]["summary"]["sha256"] == digest
    assert response.json_body["artifact"]["summary"]["baseline_sha256"] == digest


class Service:
    def health(self):
        return {"database": "ok"}

    def list_quarantine(self, *, states, limit, offset):
        self.list_call = states, limit, offset
        return QuarantinePage((), offset, limit, offset)

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
        json_body={} if body is None else body,
        authenticated_userid=actor,
    )


def test_list_quarantine_validates_filters_and_serializes_page() -> None:
    service = Service()
    response = list_quarantine(
        request(service, params={"state": "REVIEW,DENY", "limit": "20", "offset": "5"})
    )

    assert response.status_code == 200
    assert response.json_body == {"items": [], "total": 5, "limit": 20, "offset": 5}
    assert service.list_call == ((ArtifactState.REVIEW, ArtifactState.DENY), 20, 5)


def test_inspect_maps_missing_artifact_to_stable_404() -> None:
    response = inspect_artifact(request(Service(), sha256="b" * 64))
    assert response.status_code == 404
    assert response.json_body["error"]["code"] == "artifact_not_found"


def test_inspect_allows_allow_details_and_large_nested_evidence_text() -> None:
    now = datetime(2026, 8, 25, tzinfo=UTC)
    summary = ArtifactAdminSummary(
        sha256=SHA256,
        size_bytes=1,
        state=ArtifactState.ALLOW,
        discovered_at=now,
        updated_at=now,
        cooldown_until=None,
        last_error=None,
    )
    details = ArtifactAdminDetails(
        summary=summary,
        allowed=True,
        effective_decision=Decision.ALLOW,
        decision_source=DecisionSource.MANUAL_OVERRIDE,
        policy_version="policy-1",
        analyzer_version="analyzer-1",
        baseline_sha256=None,
        baseline_tier=None,
        releases=(),
        evidence=(
            EvidenceRecord(
                rule_id="manual",
                action=Decision.ALLOW,
                file_path=None,
                line=None,
                message="trusted",
                details={"note": "x" * 5000},
            ),
        ),
    )

    class DetailsService(Service):
        def inspect(self, sha256):
            return details

    response = inspect_artifact(request(DetailsService()))
    assert response.status_code == 200
    assert response.json_body["artifact"]["allowed"] is True
    assert response.json_body["artifact"]["evidence"][0]["details"]["note"] == "x" * 5000


def test_inspect_rejects_baseline_tier_without_sha() -> None:
    now = datetime(2026, 8, 25, tzinfo=UTC)
    summary = ArtifactAdminSummary(
        sha256=SHA256,
        size_bytes=1,
        state=ArtifactState.REVIEW,
        discovered_at=now,
        updated_at=now,
        cooldown_until=None,
        last_error=None,
    )
    details = ArtifactAdminDetails(
        summary=summary,
        allowed=False,
        effective_decision=Decision.REVIEW,
        decision_source=DecisionSource.AUTOMATED,
        policy_version="policy-1",
        analyzer_version="analyzer-1",
        baseline_sha256=None,
        baseline_tier="same_tag",
        releases=(),
        evidence=(),
    )

    class DetailsService(Service):
        def inspect(self, sha256):
            return details

    response = inspect_artifact(request(DetailsService()))
    assert response.status_code == 503
    assert response.json_body["error"]["code"] == "serialization_unavailable"


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


def test_reason_allows_json_safe_newlines_and_unicode_character_limit() -> None:
    service = Service()
    reason = "검토 완료\n추가 근거\t승인"
    response = approve_artifact(request(service, body={"reason": reason}))
    assert response.status_code == 200
    assert service.approve_call == (SHA256, "root", reason)


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


def test_missing_or_wrong_registry_service_is_sanitized_503() -> None:
    missing = SimpleNamespace(registry={}, matchdict={"sha256": SHA256}, params={}, json_body={})
    missing_response = list_quarantine(missing)
    assert missing_response.status_code == 503
    assert missing_response.json_body["error"]["code"] == "admin_service_unavailable"
    wrong = request(object())
    assert list_quarantine(wrong).status_code == 503


def test_provider_value_errors_are_not_client_400s() -> None:
    class BadService(Service):
        def artifact_diff(self, sha256):
            raise AdminProviderError("secret provider internals")

    response = artifact_diff(request(BadService()))
    assert response.status_code == 503
    assert response.json_body["error"]["code"] == "provider_unavailable"
    assert "secret" not in response.text


def test_unknown_provider_errors_are_reraised() -> None:
    class BrokenService(Service):
        def artifact_diff(self, sha256):
            raise RuntimeError("programming failure")

    with pytest.raises(RuntimeError, match="programming failure"):
        artifact_diff(request(BrokenService()))


def test_request_json_parse_errors_are_constant_400s() -> None:
    class BadRequest:
        def __init__(self):
            self.registry = {ADMIN_SERVICE_REGISTRY_KEY: Service()}
            self.matchdict = {"sha256": SHA256}
            self.params = {}
            self.authenticated_userid = "root"

        @property
        def json_body(self):
            raise ValueError("secret parser details")

    response = approve_artifact(BadRequest())
    assert response.status_code == 400
    assert response.json_body == {
        "error": {"code": "invalid_request", "message": "invalid JSON request"}
    }


def test_invalid_sha_is_constant_400_without_reflection() -> None:
    response = inspect_artifact(request(Service(), sha256="x" * 64 + "\n"))
    assert response.status_code == 400
    assert response.json_body == {
        "error": {
            "code": "invalid_request",
            "message": "sha256 must be a lowercase 64-character hexadecimal digest",
        }
    }


def test_quarantine_page_fields_are_validated_before_200() -> None:
    class BadPageService(Service):
        def list_quarantine(self, *, states, limit, offset):
            return QuarantinePage(("not-an-item",), -1, 0, -1)

    response = list_quarantine(request(BadPageService()))
    assert response.status_code == 503
    assert response.json_body["error"]["code"] == "serialization_unavailable"


def test_baseline_inner_records_are_mappings() -> None:
    class BadBaselineService(Service):
        def list_baselines(self, project):
            return ("not-a-record",)

    response = list_baselines(request(BadBaselineService(), params={"project": "demo"}))
    assert response.status_code == 503
    assert response.json_body["error"]["code"] == "serialization_unavailable"


def test_serialization_rejects_cycles_without_leaking_exception() -> None:
    class CyclicService(Service):
        def artifact_diff(self, sha256):
            value = {}
            value["self"] = value
            return value

    response = artifact_diff(request(CyclicService()))
    assert response.status_code == 503
    assert response.json_body["error"]["code"] == "serialization_unavailable"


@pytest.mark.parametrize("key", ["bad\x00key", "bad\ud800key"])
def test_serialization_rejects_invalid_nested_mapping_keys(key) -> None:
    class BadKeyService(Service):
        def artifact_diff(self, sha256):
            return {"nested": {key: "value"}}

    response = artifact_diff(request(BadKeyService()))
    assert response.status_code == 503
    assert response.json_body["error"]["code"] == "serialization_unavailable"


def test_inspect_rejects_missing_artifact_state() -> None:
    now = datetime(2026, 8, 25, tzinfo=UTC)
    summary = ArtifactAdminSummary(
        sha256=SHA256,
        size_bytes=1,
        state=ArtifactState.MISSING,
        discovered_at=now,
        updated_at=now,
        cooldown_until=None,
        last_error=None,
    )
    details = ArtifactAdminDetails(
        summary=summary,
        allowed=False,
        effective_decision=Decision.REVIEW,
        decision_source=DecisionSource.MISSING,
        policy_version=None,
        analyzer_version=None,
        baseline_sha256=None,
        baseline_tier=None,
        releases=(),
        evidence=(),
    )

    class DetailsService(Service):
        def inspect(self, sha256):
            return details

    response = inspect_artifact(request(DetailsService()))
    assert response.status_code == 503
    assert response.json_body["error"]["code"] == "serialization_unavailable"


def test_falsey_body_is_not_replaced_by_an_empty_object() -> None:
    response = approve_artifact(request(Service(), body=[]))
    assert response.status_code == 400


def test_admin_routes_register_expected_methods_and_permission() -> None:
    class Pyramid:
        def __init__(self):
            self.routes = []
            self.views = []

        def add_route(self, name, path):
            self.routes.append((name, path))

        def add_view(self, view, **kwargs):
            self.views.append((view, kwargs))

    pyramid = Pyramid()
    configure_admin_routes(pyramid)
    assert len(pyramid.routes) == 15
    assert len(pyramid.views) == 16
    assert {(name, path) for name, path in pyramid.routes} == {
        ("guardian_quarantine", "/+guardian/api/v1/quarantine"),
        ("guardian_artifact", "/+guardian/api/v1/artifacts/{sha256}"),
        ("guardian_artifact_diff", "/+guardian/api/v1/artifacts/{sha256}/diff"),
        ("guardian_artifact_approve", "/+guardian/api/v1/artifacts/{sha256}/approve"),
        ("guardian_artifact_block", "/+guardian/api/v1/artifacts/{sha256}/block"),
        ("guardian_artifact_rescan", "/+guardian/api/v1/artifacts/{sha256}/rescan"),
        ("guardian_artifact_revoke", "/+guardian/api/v1/artifacts/{sha256}/revoke"),
        ("guardian_artifact_exception", "/+guardian/api/v1/artifacts/{sha256}/exceptions"),
        ("guardian_health", "/+guardian/api/v1/health"),
        ("guardian_audit", "/+guardian/api/v1/audit"),
        ("guardian_baselines", "/+guardian/api/v1/baselines"),
        ("guardian_baseline_import", "/+guardian/api/v1/baselines/import"),
        ("guardian_baseline_remove", "/+guardian/api/v1/baselines/{sha256}"),
        ("guardian_policy_validate", "/+guardian/api/v1/policy/validate"),
        ("guardian_policy_simulate", "/+guardian/api/v1/policy/simulate"),
    }
    assert {(kwargs["route_name"], kwargs["request_method"]) for _, kwargs in pyramid.views} == {
        ("guardian_quarantine", "GET"),
        ("guardian_artifact", "GET"),
        ("guardian_artifact_diff", "GET"),
        ("guardian_artifact_approve", "POST"),
        ("guardian_artifact_block", "POST"),
        ("guardian_artifact_rescan", "POST"),
        ("guardian_artifact_revoke", "POST"),
        ("guardian_artifact_exception", "POST"),
        ("guardian_health", "GET"),
        ("guardian_audit", "GET"),
        ("guardian_baselines", "GET"),
        ("guardian_baselines", "POST"),
        ("guardian_baseline_remove", "DELETE"),
        ("guardian_baseline_import", "POST"),
        ("guardian_policy_validate", "POST"),
        ("guardian_policy_simulate", "POST"),
    }
    assert all(kwargs["permission"] == "user_modify" for _, kwargs in pyramid.views)
