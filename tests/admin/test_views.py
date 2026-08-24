from __future__ import annotations

from types import SimpleNamespace

from devpi_guardian.admin.views import (
    ADMIN_SERVICE_REGISTRY_KEY,
    approve_artifact,
    inspect_artifact,
    list_quarantine,
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
        request(
            service,
            params={"state": "REVIEW,DENY", "limit": "20", "offset": "5"},
        )
    )

    assert response.status_code == 200
    assert response.json_body == {"items": [], "total": 0, "limit": 20, "offset": 5}
    assert service.list_call == (
        (ArtifactState.REVIEW, ArtifactState.DENY),
        20,
        5,
    )


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
