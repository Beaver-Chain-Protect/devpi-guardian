# Project Ruff and upstream devpi intentionally use conflicting import layouts.
# Keep devpi's no-section, from-first style in this integration-facing test.
# ruff: noqa: I001
from devpi_guardian.verdicts.errors import StoreUnavailable
from devpi_guardian.verdicts.models import ArtifactState
from devpi_guardian.verdicts.models import Decision
from devpi_guardian.verdicts.models import DecisionSource
from devpi_guardian.verdicts.models import EnforcementDecision
from devpi_server.config import get_pluginmanager
from devpi_server.model import get_stage_customizer_class
from devpi_server.model import SimplelinkMeta
from pyramid.httpexceptions import HTTPServiceUnavailable
from types import SimpleNamespace
import pytest


_READER_ATTRIBUTE = "_devpi_guardian_verdict_reader"


class RecordingReader:
    def __init__(self, decisions=None, error=None):
        self.calls = []
        self.decisions = decisions or {}
        self.error = error

    def get_effective_decisions(self, sha256s):
        self.calls.append(tuple(sha256s))
        if self.error is not None:
            raise self.error
        return self.decisions


class SinglePassLinks:
    def __init__(self, links):
        self.links = links
        self.iterations = 0
        self.yielded = 0

    def __iter__(self):
        self.iterations += 1
        if self.iterations > 1:
            raise AssertionError("links iterable was consumed more than once")
        for link in self.links:
            self.yielded += 1
            yield link


class UnusableProject:
    def __str__(self):
        raise AssertionError("project must not participate in F2 policy")

    def __hash__(self):
        raise AssertionError("project must not participate in F2 policy")


def make_stage(reader=None, *, initialized=True):
    plugin_manager = get_pluginmanager()
    xom = SimpleNamespace(config=SimpleNamespace(hook=plugin_manager.hook))
    if initialized:
        setattr(xom, _READER_ATTRIBUTE, reader)
    customizer_class = get_stage_customizer_class(xom, "guardian")
    return customizer_class(SimpleNamespace(xom=xom))


def make_link(name, fragment=""):
    href = f"/root/pypi/+f/abc123/{name}{fragment}"
    return SimplelinkMeta((name, href, ">=3.11", "not yanked"))


def make_decision(
    sha256,
    *,
    allowed,
    decision,
    source,
    state,
):
    return EnforcementDecision(
        sha256=sha256,
        allowed=allowed,
        effective_decision=decision,
        source=source,
        artifact_state=state,
        policy_version="policy-v1",
    )


def snapshot(link):
    return (
        link.key,
        link.href,
        link.require_python,
        link.yanked,
        link.core_metadata,
        dict(link.hashes),
    )


def run_filter(stage, project, links):
    filter_iter = stage.get_simple_links_filter_iter(project, links)
    assert filter_iter is not None
    return list(filter_iter)


def test_filter_is_single_pass_batched_ordered_and_fail_closed() -> None:
    pairs = zip("abcdefgh", "12345678", strict=True)
    digests = {name: character * 64 for name, character in pairs}
    links = [
        make_link("allow.whl", f"#sha256={digests['a']}"),
        make_link("review.whl", f"#sha256={digests['b']}"),
        make_link("allow-second.whl", f"#sha256={digests['h']}"),
        make_link("deny.whl", f"#sha256={digests['c']}"),
        make_link("missing-state.whl", f"#sha256={digests['d']}"),
        make_link("error-state.whl", f"#sha256={digests['e']}"),
        make_link("missing-mapping.whl", f"#sha256={digests['f']}"),
        make_link("truthy-non-bool.whl", f"#sha256={digests['g']}"),
        make_link("no-hash.whl"),
        make_link("other-hash.whl", f"#md5={'8' * 32}"),
        make_link("uppercase.whl", f"#sha256={'A' * 64}"),
        make_link("malformed.whl", "#sha256=not-a-sha256"),
    ]
    before = [snapshot(link) for link in links]
    reader = RecordingReader(
        {
            digests["a"]: make_decision(
                digests["a"],
                allowed=True,
                decision=Decision.ALLOW,
                source=DecisionSource.AUTOMATED,
                state=ArtifactState.ALLOW,
            ),
            digests["b"]: make_decision(
                digests["b"],
                allowed=False,
                decision=Decision.REVIEW,
                source=DecisionSource.AUTOMATED,
                state=ArtifactState.REVIEW,
            ),
            digests["c"]: make_decision(
                digests["c"],
                allowed=False,
                decision=Decision.DENY,
                source=DecisionSource.AUTOMATED,
                state=ArtifactState.DENY,
            ),
            digests["d"]: make_decision(
                digests["d"],
                allowed=False,
                decision=Decision.DENY,
                source=DecisionSource.MISSING,
                state=ArtifactState.MISSING,
            ),
            digests["e"]: make_decision(
                digests["e"],
                allowed=False,
                decision=Decision.DENY,
                source=DecisionSource.AUTOMATED,
                state=ArtifactState.ERROR,
            ),
            digests["g"]: SimpleNamespace(allowed=1),
            digests["h"]: make_decision(
                digests["h"],
                allowed=True,
                decision=Decision.ALLOW,
                source=DecisionSource.AUTOMATED,
                state=ArtifactState.ALLOW,
            ),
        }
    )
    source = SinglePassLinks(links)

    decisions = run_filter(
        make_stage(reader),
        UnusableProject(),
        source,
    )

    assert decisions == [
        True,
        False,
        True,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
    ]
    assert source.iterations == 1
    assert source.yielded == len(links)
    assert len(decisions) == len(links)
    link_decisions = zip(links, decisions, strict=True)
    allowed_links = [link for link, allowed in link_decisions if allowed]
    assert allowed_links == [links[0], links[2]]
    assert [link.key for link in allowed_links] == [
        "allow.whl",
        "allow-second.whl",
    ]
    assert [snapshot(link) for link in links] == before
    assert len(reader.calls) == 1
    assert len(reader.calls[0]) == 8
    assert set(reader.calls[0]) == set(digests.values())


def test_filter_skips_reader_when_no_link_has_a_valid_sha256() -> None:
    links = [
        make_link("no-hash.whl"),
        make_link("md5.whl", f"#md5={'a' * 32}"),
        make_link("uppercase.whl", f"#sha256={'B' * 64}"),
        make_link("short.whl", "#sha256=abcd"),
    ]
    reader = RecordingReader(error=AssertionError("reader must not be called"))

    decisions = run_filter(make_stage(reader), "demo", links)

    assert decisions == [False, False, False, False]
    assert reader.calls == []


@pytest.mark.parametrize("failure_source", ["bootstrap", "batch"])
def test_store_unavailable_aborts_with_retryable_503(failure_source) -> None:
    digest = "a" * 64
    link = make_link("demo.whl", f"#sha256={digest}")
    if failure_source == "bootstrap":
        stage = make_stage(initialized=False)
    else:
        error = StoreUnavailable("database unavailable")
        stage = make_stage(RecordingReader(error=error))

    with pytest.raises(HTTPServiceUnavailable) as caught:
        run_filter(stage, "demo", [link])

    assert caught.value.status_code == 503
    assert caught.value.headers["Retry-After"] == "5"


def test_unexpected_reader_error_is_not_converted_to_a_filter_result() -> None:
    digest = "a" * 64
    link = make_link("demo.whl", f"#sha256={digest}")
    reader = RecordingReader(error=RuntimeError("unexpected"))

    with pytest.raises(RuntimeError, match="unexpected"):
        run_filter(make_stage(reader), "demo", [link])
