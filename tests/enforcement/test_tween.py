from __future__ import annotations

from types import SimpleNamespace

import pytest
from pyramid.httpexceptions import HTTPNotFound, HTTPServiceUnavailable

from devpi_guardian.enforcement.resolve import ArtifactIdentityUnavailable
from devpi_guardian.enforcement.tween import (
    VERDICT_READER_REGISTRY_KEY,
    guardian_enforcement_tween_factory,
)
from devpi_guardian.verdicts.errors import StoreUnavailable
from devpi_guardian.verdicts.models import (
    ArtifactState,
    Decision,
    DecisionSource,
    EnforcementDecision,
)

SHA256 = "a" * 64
OTHER_SHA256 = "b" * 64
MISSING = object()


class Reader:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def get_effective_decision(self, sha256):
        self.calls.append(sha256)
        if self.error is not None:
            raise self.error
        return self.result


def decision(
    *,
    allowed=False,
    effective_decision=Decision.DENY,
    source=DecisionSource.AUTOMATED,
    artifact_state=ArtifactState.REVIEW,
    sha256=SHA256,
):
    return EnforcementDecision(
        sha256=sha256,
        allowed=allowed,
        effective_decision=effective_decision,
        source=source,
        artifact_state=artifact_state,
        policy_version="policy-1",
    )


class Log:
    def __init__(self, error=None):
        self.error = error
        self.calls = []

    def info(self, *args):
        self.calls.append(args)
        if self.error is not None:
            raise self.error


def make_request(log=MISSING):
    if log is MISSING:
        return SimpleNamespace()
    return SimpleNamespace(log=log)


def make_tween(reader, calls, registry=None):
    if registry is None:
        registry = {VERDICT_READER_REGISTRY_KEY: reader}

    def handler(request):
        calls.append(request)
        return SimpleNamespace(status_code=200)

    return guardian_enforcement_tween_factory(handler, registry)


@pytest.fixture
def protected_request(monkeypatch):
    monkeypatch.setattr(
        "devpi_guardian.enforcement.tween.resolve_release_sha256",
        lambda request: SHA256,
    )
    return make_request(Log())


def test_exact_allow_calls_downstream_handler(protected_request):
    calls = []
    reader = Reader(
        result=decision(allowed=True, effective_decision=Decision.ALLOW),
    )

    response = make_tween(reader, calls)(protected_request)

    assert response.status_code == 200
    assert calls == [protected_request]
    assert reader.calls == [SHA256]


@pytest.mark.parametrize("artifact_state", list(ArtifactState))
@pytest.mark.parametrize("effective_decision", list(Decision))
@pytest.mark.parametrize("source", list(DecisionSource))
def test_every_non_allow_shape_returns_sanitized_404(
    protected_request,
    artifact_state,
    effective_decision,
    source,
):
    calls = []
    reader = Reader(
        result=decision(
            allowed=False,
            effective_decision=effective_decision,
            source=source,
            artifact_state=artifact_state,
        )
    )

    response = make_tween(reader, calls)(protected_request)

    assert isinstance(response, HTTPNotFound)
    assert response.status_code == 404
    assert calls == []
    assert SHA256 not in response.text
    assert "REVIEW" not in response.text
    assert "DENY" not in response.text


@pytest.mark.parametrize(
    "malformed",
    [
        decision(allowed=1, effective_decision=Decision.ALLOW),
        decision(allowed="true", effective_decision=Decision.ALLOW),
        decision(allowed=True, effective_decision=Decision.DENY),
        decision(allowed=True, effective_decision=Decision.REVIEW),
        decision(
            allowed=True,
            effective_decision=Decision.ALLOW,
            source=DecisionSource.MISSING,
        ),
        decision(
            allowed=True,
            effective_decision=Decision.ALLOW,
            sha256=OTHER_SHA256,
        ),
        SimpleNamespace(allowed=True),
    ],
)
def test_malformed_allow_shape_fails_closed(protected_request, malformed):
    calls = []

    response = make_tween(Reader(result=malformed), calls)(protected_request)

    assert response.status_code == 404
    assert calls == []


def test_missing_artifact_decision_is_sanitized_404(protected_request):
    calls = []
    reader = Reader(
        result=decision(
            artifact_state=ArtifactState.MISSING,
            source=DecisionSource.MISSING,
        )
    )

    response = make_tween(reader, calls)(protected_request)

    assert response.status_code == 404
    assert calls == []
    assert SHA256 not in response.text


def test_resolver_none_passes_through_without_reader(monkeypatch):
    monkeypatch.setattr(
        "devpi_guardian.enforcement.tween.resolve_release_sha256",
        lambda request: None,
    )
    calls = []
    reader = Reader(result=decision(allowed=False))
    request = make_request(Log())

    response = make_tween(reader, calls)(request)

    assert response.status_code == 200
    assert calls == [request]
    assert reader.calls == []


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize("suffix", ["", ".metadata"])
def test_get_head_metadata_use_same_resolver_and_reader_flow(
    monkeypatch,
    method,
    suffix,
):
    observed = []
    monkeypatch.setattr(
        "devpi_guardian.enforcement.tween.resolve_release_sha256",
        lambda request: observed.append(request) or SHA256,
    )
    calls = []
    reader = Reader(
        result=decision(allowed=True, effective_decision=Decision.ALLOW),
    )
    request = make_request(Log())
    request.method = method
    request.path_info = f"/root/pypi/+f/demo.whl{suffix}"

    response = make_tween(reader, calls)(request)

    assert response.status_code == 200
    assert observed == [request]
    assert reader.calls == [SHA256]
    assert calls == [request]


def test_unresolved_identity_returns_sanitized_503_without_handler(
    monkeypatch,
    protected_request,
):
    def fail(request):
        raise ArtifactIdentityUnavailable("secret/path")

    monkeypatch.setattr(
        "devpi_guardian.enforcement.tween.resolve_release_sha256",
        fail,
    )
    calls = []
    response = make_tween(Reader(result=decision(allowed=True)), calls)(
        protected_request,
    )

    assert isinstance(response, HTTPServiceUnavailable)
    assert response.status_code == 503
    assert response.headers.get("Retry-After") is None
    assert calls == []
    assert "secret/path" not in response.text
    assert SHA256 not in response.text


def test_store_failure_returns_sanitized_503_with_retry_after(
    protected_request,
):
    calls = []
    response = make_tween(
        Reader(error=StoreUnavailable("secret database details")),
        calls,
    )(protected_request)

    assert isinstance(response, HTTPServiceUnavailable)
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "5"
    assert "secret database details" not in response.text
    assert SHA256 not in response.text
    assert calls == []


def test_reader_is_called_on_every_request_without_decision_cache(
    protected_request,
):
    calls = []
    reader = Reader(
        result=decision(allowed=True, effective_decision=Decision.ALLOW),
    )
    tween = make_tween(reader, calls)

    assert tween(protected_request).status_code == 200
    reader.result = decision(allowed=False)
    assert tween(protected_request).status_code == 404

    assert reader.calls == [SHA256, SHA256]
    assert calls == [protected_request]


def test_logging_failure_cannot_turn_block_into_pass_through(
    protected_request,
):
    protected_request.log = Log(error=RuntimeError("logger failed"))
    calls = []

    response = make_tween(Reader(result=decision(allowed=False)), calls)(
        protected_request,
    )

    assert response.status_code == 404
    assert calls == []


def test_request_log_absence_cannot_turn_block_into_pass_through(monkeypatch):
    monkeypatch.setattr(
        "devpi_guardian.enforcement.tween.resolve_release_sha256",
        lambda request: SHA256,
    )
    calls = []
    response = make_tween(Reader(result=decision(allowed=False)), calls)(
        make_request(),
    )

    assert response.status_code == 404
    assert calls == []


def test_missing_reader_registry_key_fails_at_factory_startup():
    with pytest.raises(KeyError):
        make_tween(Reader(), [], registry={})


def test_malformed_reader_does_not_call_handler(monkeypatch):
    monkeypatch.setattr(
        "devpi_guardian.enforcement.tween.resolve_release_sha256",
        lambda request: SHA256,
    )
    calls = []
    reader = object()

    tween = make_tween(reader, calls)
    with pytest.raises(AttributeError):
        tween(make_request(Log()))

    assert calls == []


def test_unexpected_reader_exception_propagates_without_handler(
    protected_request,
):
    calls = []
    error = RuntimeError("unexpected reader failure")

    with pytest.raises(RuntimeError, match="unexpected reader failure"):
        make_tween(Reader(error=error), calls)(protected_request)

    assert calls == []


def test_base_exception_from_resolver_propagates(
    monkeypatch,
    protected_request,
):
    class StopNow(BaseException):
        pass

    monkeypatch.setattr(
        "devpi_guardian.enforcement.tween.resolve_release_sha256",
        lambda request: (_ for _ in ()).throw(StopNow()),
    )
    calls = []

    with pytest.raises(StopNow):
        make_tween(Reader(result=decision(allowed=True)), calls)(
            protected_request,
        )

    assert calls == []


def test_base_exception_from_reader_propagates(protected_request):
    class StopNow(BaseException):
        pass

    calls = []
    with pytest.raises(StopNow):
        make_tween(Reader(error=StopNow()), calls)(protected_request)

    assert calls == []
