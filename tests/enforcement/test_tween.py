from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest
from devpi_server.log import TagLogger
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


class HostileSha256(str):
    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False


class ExplodingDecision(EnforcementDecision):
    def __getattribute__(self, name):
        if name in {
            "sha256",
            "allowed",
            "effective_decision",
            "source",
            "artifact_state",
            "policy_version",
        }:
            raise RuntimeError("malformed decision")
        return super().__getattribute__(name)


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


class StructuredLog:
    def __init__(self, error=None):
        self.error = error
        self.calls = []

    def info(self, message, *args):
        self.calls.append((message, args))
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
        result=decision(
            allowed=True,
            effective_decision=Decision.ALLOW,
            artifact_state=ArtifactState.ALLOW,
        ),
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


@pytest.mark.parametrize(
    ("source", "artifact_state", "allowed_downstream"),
    [
        (DecisionSource.AUTOMATED, ArtifactState.ALLOW, True),
        (DecisionSource.AUTOMATED, ArtifactState.MISSING, False),
        (DecisionSource.AUTOMATED, ArtifactState.REVIEW, False),
        (DecisionSource.MANUAL_OVERRIDE, ArtifactState.ALLOW, True),
        (DecisionSource.MANUAL_OVERRIDE, ArtifactState.REVIEW, True),
        (DecisionSource.MANUAL_OVERRIDE, ArtifactState.DENY, True),
        (DecisionSource.MANUAL_OVERRIDE, ArtifactState.ERROR, True),
        (DecisionSource.MANUAL_OVERRIDE, ArtifactState.MISSING, False),
        (DecisionSource.MANUAL_OVERRIDE, "REVIEW", False),
        (DecisionSource.MANUAL_OVERRIDE, [], False),
        (DecisionSource.MISSING, ArtifactState.ALLOW, False),
        ([], ArtifactState.ALLOW, False),
    ],
)
def test_only_valid_allow_source_state_pairs_reach_handler(
    protected_request,
    source,
    artifact_state,
    allowed_downstream,
):
    calls = []
    reader = Reader(
        result=decision(
            allowed=True,
            effective_decision=Decision.ALLOW,
            source=source,
            artifact_state=artifact_state,
        )
    )

    response = make_tween(reader, calls)(protected_request)

    assert response.status_code == (200 if allowed_downstream else 404)
    assert calls == ([protected_request] if allowed_downstream else [])


@pytest.mark.parametrize("resolved", [HostileSha256("b" * 64), "not-a-sha256"])
def test_invalid_resolver_result_returns_503_without_reader_or_handler(
    monkeypatch,
    resolved,
):
    monkeypatch.setattr(
        "devpi_guardian.enforcement.tween.resolve_release_sha256",
        lambda request: resolved,
    )
    calls = []
    reader = Reader(
        result=decision(
            allowed=True,
            effective_decision=Decision.ALLOW,
            artifact_state=ArtifactState.ALLOW,
        )
    )

    response = make_tween(reader, calls)(make_request(Log()))

    assert response.status_code == 503
    assert calls == []
    assert reader.calls == []


def test_exploding_decision_subclass_returns_sanitized_404_without_handler(
    protected_request,
):
    calls = []
    malformed = ExplodingDecision(
        sha256=SHA256,
        allowed=True,
        effective_decision=Decision.ALLOW,
        source=DecisionSource.AUTOMATED,
        artifact_state=ArtifactState.ALLOW,
        policy_version="policy-1",
    )

    response = make_tween(Reader(result=malformed), calls)(protected_request)

    assert response.status_code == 404
    assert calls == []


class PolicySubclass(str):
    pass


@pytest.mark.parametrize(
    ("source", "artifact_state", "policy_version", "allowed_downstream"),
    [
        (DecisionSource.AUTOMATED, ArtifactState.ALLOW, None, False),
        (DecisionSource.AUTOMATED, ArtifactState.ALLOW, "", False),
        (
            DecisionSource.AUTOMATED,
            ArtifactState.ALLOW,
            PolicySubclass("v1"),
            False,
        ),
        (DecisionSource.MANUAL_OVERRIDE, ArtifactState.REVIEW, None, False),
        (DecisionSource.MANUAL_OVERRIDE, ArtifactState.DENY, "", False),
        (DecisionSource.MANUAL_OVERRIDE, ArtifactState.ERROR, None, True),
        (DecisionSource.MANUAL_OVERRIDE, ArtifactState.ERROR, "v1", True),
        (
            DecisionSource.MANUAL_OVERRIDE,
            ArtifactState.ERROR,
            PolicySubclass("v1"),
            False,
        ),
    ],
)
def test_allow_requires_valid_policy_version_for_source_and_state(
    protected_request,
    source,
    artifact_state,
    policy_version,
    allowed_downstream,
):
    calls = []
    result = EnforcementDecision(
        sha256=SHA256,
        allowed=True,
        effective_decision=Decision.ALLOW,
        source=source,
        artifact_state=artifact_state,
        policy_version=policy_version,
    )

    response = make_tween(Reader(result=result), calls)(protected_request)

    assert response.status_code == (200 if allowed_downstream else 404)
    assert calls == ([protected_request] if allowed_downstream else [])


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


@pytest.mark.parametrize(
    "error",
    [
        ArtifactIdentityUnavailable("downstream identity error"),
        StoreUnavailable("downstream store error"),
    ],
)
def test_resolver_none_does_not_swallow_downstream_domain_errors(
    monkeypatch,
    error,
):
    monkeypatch.setattr(
        "devpi_guardian.enforcement.tween.resolve_release_sha256",
        lambda request: None,
    )
    calls = []

    def handler(request):
        calls.append(request)
        raise error

    reader = Reader(result=decision(allowed=False))
    tween = guardian_enforcement_tween_factory(
        handler,
        {VERDICT_READER_REGISTRY_KEY: reader},
    )

    with pytest.raises(type(error)):
        tween(make_request(Log()))

    assert len(calls) == 1
    assert reader.calls == []


def test_not_allowed_logging_contains_only_safe_structured_fields(
    protected_request,
):
    log = StructuredLog()
    protected_request.log = log
    protected_request.path_info = "/root/pypi/+f/public.whl?token=secret"
    calls = []

    response = make_tween(
        Reader(result=decision(artifact_state=ArtifactState.REVIEW)),
        calls,
    )(protected_request)

    assert response.status_code == 404
    assert calls == []
    assert len(log.calls) == 1
    message, args = log.calls[0]
    assert message == (
        "guardian direct download blocked route=%s sha256=%s "
        "effective=%s state=%s source=%s category=%s"
    )
    assert args == (
        "+f",
        SHA256,
        "DENY",
        "REVIEW",
        "AUTOMATED",
        "not_allowed",
    )
    assert "secret" not in repr(log.calls)


def test_identity_failure_logging_uses_unknown_fields_without_details(
    monkeypatch,
):
    protected_request = make_request(StructuredLog())
    protected_request.path_info = "/root/pypi/+e/private.whl?token=secret"

    def fail(request):
        raise ArtifactIdentityUnavailable("private/path")

    monkeypatch.setattr(
        "devpi_guardian.enforcement.tween.resolve_release_sha256",
        fail,
    )
    calls = []
    response = make_tween(Reader(result=decision(allowed=True)), calls)(
        protected_request,
    )

    assert response.status_code == 503
    assert calls == []
    _, args = protected_request.log.calls[0]
    assert args == (
        "+e",
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        "identity_unavailable",
    )
    assert "secret" not in repr(protected_request.log.calls)


def test_store_failure_logging_has_no_exception_details(protected_request):
    log = StructuredLog()
    protected_request.log = log
    protected_request.path_info = "/root/pypi/+f/public.whl"
    calls = []

    response = make_tween(
        Reader(error=StoreUnavailable("secret database details")),
        calls,
    )(protected_request)

    assert response.status_code == 503
    assert calls == []
    _, args = log.calls[0]
    assert args == (
        "+f",
        SHA256,
        "unknown",
        "unknown",
        "unknown",
        "store_unavailable",
    )
    assert "secret database details" not in repr(log.calls)


def test_pinned_tag_logger_emits_safe_record_without_raw_request_details(
    monkeypatch,
):
    logger = logging.getLogger("devpi-guardian-test-tween")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record)

    capture = Capture()
    logger.addHandler(capture)
    try:
        monkeypatch.setattr(
            "devpi_guardian.enforcement.tween.resolve_release_sha256",
            lambda request: SHA256,
        )
        request = make_request(TagLogger(logger))
        request.path_info = "/root/pypi/+f/private.whl?token=secret"
        calls = []

        response = make_tween(Reader(result=decision()), calls)(request)

        assert response.status_code == 404
        assert calls == []
        assert len(records) == 1
        record = records[0]
        assert record.getMessage() == (
            "guardian direct download blocked route=+f "
            f"sha256={SHA256} effective=DENY state=REVIEW "
            "source=AUTOMATED category=not_allowed"
        )
        assert "private.whl" not in record.getMessage()
        assert "token=secret" not in record.getMessage()
    finally:
        logger.removeHandler(capture)


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
        result=decision(
            allowed=True,
            effective_decision=Decision.ALLOW,
            artifact_state=ArtifactState.ALLOW,
        ),
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
        result=decision(
            allowed=True,
            effective_decision=Decision.ALLOW,
            artifact_state=ArtifactState.ALLOW,
        ),
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
