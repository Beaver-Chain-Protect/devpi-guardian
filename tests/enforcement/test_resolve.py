from __future__ import annotations

import ast
import inspect
import textwrap
from types import SimpleNamespace

import pytest
from devpi_server.main import XOM
from devpi_server.views import PyPIView

from devpi_guardian.enforcement.resolve import (
    ArtifactIdentityUnavailable,
    resolve_release_sha256,
)

SHA256 = "a" * 64
F_ROUTE = "/{user}/{index}/+f/{relpath:.*}"
E_ROUTE = "/{user}/{index}/+e/{relpath:.*}"
DEFAULT_RELPATH = "root/pypi/+f/abc/demo-1.0-py3-none-any.whl"
DEFAULT_KEY = object()
NON_DOWNLOAD_METHODS = ("POST", "PUT", "PATCH", "DELETE", "get", None, [])
NON_RELEASE_RELATIONS = ("toxresult", "doczip", "other", "releaseFile", "")
INVALID_SHA256S = (None, "", "A" * 64, "g" * 64, "a" * 63, "a" * 65)
RAW_PATH_KEYS = ("RAW_URI", "REQUEST_URI", "RAW_PATH_INFO")
ENCODED_ARTIFACT_PATH = "/root/pypi/+f/abc%2Fdemo-1.0-py3-none-any.whl"
ENCODED_ARTIFACT_URI = ENCODED_ARTIFACT_PATH + "?token=secret"


class FakeEntry:
    def __init__(
        self,
        relpath: str,
        *,
        hashes: object | None = None,
        user: str = "root",
        index: str = "pypi",
        project: str = "demo",
        version: str = "1.0",
    ) -> None:
        self.relpath = relpath
        self.hashes = {"sha256": SHA256} if hashes is None else hashes
        self.user = user
        self.index = index
        self.project = project
        self.version = version

    def file_exists(self):
        raise AssertionError("resolver must not access file content")

    def file_open_read(self):
        raise AssertionError("resolver must not access file content")


class FailingHashesEntry(FakeEntry):
    @property
    def hashes(self):
        raise RuntimeError("/private/artifacts?token=secret")

    @hashes.setter
    def hashes(self, value):
        pass


class FakeLink:
    def __init__(
        self,
        relpath: str,
        *,
        relation: object = "releasefile",
        project: str = "demo",
        version: str = "1.0",
        for_entrypath: str | None = None,
        hashes: object | None = None,
    ) -> None:
        self.rel = relation
        self.relpath = relpath
        self.project = project
        self.version = version
        self.for_entrypath = for_entrypath
        self.hashes = {"sha256": SHA256} if hashes is None else hashes


class FakeStage:
    def __init__(
        self,
        link: object,
        *,
        username: str = "root",
        index: str = "pypi",
        error: Exception | None = None,
    ) -> None:
        self.username = username
        self.index = index
        self.name = f"{username}/{index}"
        self.link = link
        self.error = error
        self.calls: list[str] = []

    def get_link_from_entrypath(self, relpath: str):
        self.calls.append(relpath)
        if self.error is not None:
            raise self.error
        return self.link


class FakeKey:
    def __init__(
        self,
        *,
        exists: bool = True,
        error: Exception | None = None,
    ) -> None:
        self._exists = exists
        self.error = error
        self.exists_calls = 0

    def exists(self) -> bool:
        self.exists_calls += 1
        if self.error is not None:
            raise self.error
        return self._exists


class FakeFileStore:
    def __init__(
        self,
        entry: object | None,
        *,
        key: object | None = DEFAULT_KEY,
        error_at: str | None = None,
    ) -> None:
        self.entry = entry
        self.key = FakeKey() if key is DEFAULT_KEY else key
        self.error_at = error_at
        self.calls: list[tuple[str, object]] = []

    def _record(self, method: str, argument: object) -> None:
        self.calls.append((method, argument))
        if self.error_at == method:
            raise RuntimeError("/private/filestore?token=secret")

    def get_file_entry(self, relpath: str):
        self._record("get_file_entry", relpath)
        return self.entry

    def get_key_from_relpath(self, relpath: str):
        self._record("get_key_from_relpath", relpath)
        return self.key

    def get_file_entry_from_key(self, key: object):
        self._record("get_file_entry_from_key", key)
        return self.entry


def make_request(
    *,
    method: object = "GET",
    route_name: object = F_ROUTE,
    marker: str = "+f",
    tail: str = "abc/demo-1.0-py3-none-any.whl",
    path_info: str | None = None,
    matchdict: object | None = None,
    entry: object | None = None,
    link: object | None = None,
    relation: object = "releasefile",
    stage: object | None = None,
    filestore: object | None = None,
    environ: object | None = None,
):
    full_relpath = f"root/pypi/{marker}/{tail}"
    if entry is None:
        entry = FakeEntry(full_relpath)
    if link is None:
        link = FakeLink(full_relpath, relation=relation)
    if stage is None:
        stage = FakeStage(link)
    if filestore is None:
        filestore = FakeFileStore(entry)
    if matchdict is None:
        matchdict = {"user": "root", "index": "pypi", "relpath": tail}
    if path_info is None:
        path_info = f"/{full_relpath}"
    if environ is None:
        environ = {}
    return SimpleNamespace(
        method=method,
        matched_route=SimpleNamespace(name=route_name),
        matchdict=matchdict,
        path_info=path_info,
        registry={"xom": SimpleNamespace(filestore=filestore)},
        context=SimpleNamespace(stage=stage),
        environ=environ,
        headers={"X-Artifact-SHA256": "b" * 64},
        query_string=f"sha256={'c' * 64}&token=secret",
    )


def _registered_route_pairs() -> set[tuple[str, str]]:
    tree = ast.parse(textwrap.dedent(inspect.getsource(XOM.create_app)))
    pairs = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "add_route":
            continue
        if len(node.args) < 2:
            continue
        string_args = map(_is_string_constant, node.args[:2])
        if all(string_args):
            pairs.add((node.args[0].value, node.args[1].value))
    return pairs


def _is_string_constant(value: ast.expr) -> bool:
    return isinstance(value, ast.Constant) and isinstance(value.value, str)


def test_pinned_devpi_registers_the_exact_protected_routes() -> None:
    assert {
        (F_ROUTE, "/{user:[^+/]+}/{index:[^+/]+}/+f/{relpath:.*}"),
        (E_ROUTE, "/{user:[^+/]+}/{index:[^+/]+}/+e/{relpath:.*}"),
    } <= _registered_route_pairs()


def test_pinned_devpi_views_use_full_path_info_as_filestore_relpath() -> None:
    for view in (PyPIView.stage_pkgserv, PyPIView.mirror_pkgserv):
        source = inspect.getsource(view)
        assert "self._relpath_from_request()" in source
    source = inspect.getsource(PyPIView._relpath_from_request)
    assert 'self.request.path_info.strip("/")' in source


@pytest.mark.parametrize(
    ("route_name", "marker", "expected_calls"),
    [
        (F_ROUTE, "+f", ["get_file_entry"]),
        (
            E_ROUTE,
            "+e",
            ["get_key_from_relpath", "get_file_entry_from_key"],
        ),
    ],
)
@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_release_routes_resolve_persisted_entry_sha256(
    route_name: str,
    marker: str,
    expected_calls: list[str],
    method: str,
) -> None:
    candidate = make_request(
        method=method,
        route_name=route_name,
        marker=marker,
    )

    assert resolve_release_sha256(candidate) == SHA256
    calls = candidate.registry["xom"].filestore.calls
    assert [call[0] for call in calls] == expected_calls
    expected_relpath = f"root/pypi/{marker}/abc/demo-1.0-py3-none-any.whl"
    assert candidate.context.stage.calls == [expected_relpath]


def test_metadata_request_resolves_only_the_original_wheel_entry() -> None:
    original = "root/pypi/+f/abc/demo-1.0-py3-none-any.whl"
    candidate = make_request(tail="abc/demo-1.0-py3-none-any.whl.metadata")
    candidate.registry["xom"].filestore.entry = FakeEntry(original)
    candidate.context.stage.link = FakeLink(original)

    assert resolve_release_sha256(candidate) == SHA256
    filestore_calls = candidate.registry["xom"].filestore.calls
    assert filestore_calls == [("get_file_entry", original)]
    assert candidate.context.stage.calls == [original]


@pytest.mark.parametrize(
    "tail",
    [
        "abc/demo-1.0.tar.gz.metadata",
        "abc/demo-1.0-py3-none-any.whl.metadata.metadata",
        ".metadata",
    ],
)
def test_non_pep658_metadata_suffixes_fail_closed(tail: str) -> None:
    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(make_request(tail=tail))


@pytest.mark.parametrize("method", NON_DOWNLOAD_METHODS)
def test_non_download_methods_pass_through_without_devpi_access(
    method: object,
) -> None:
    candidate = make_request(method=method)

    assert resolve_release_sha256(candidate) is None
    assert candidate.registry["xom"].filestore.calls == []
    assert candidate.context.stage.calls == []


@pytest.mark.parametrize(
    "route_name",
    [
        None,
        "/+api",
        "/{user}/{index}/+api",
        "/{user}/{index}/+simple/{project}",
        "/{user}/{index}/+f/{relpath}",
        "installer_simple",
    ],
)
def test_non_artifact_routes_pass_through_without_devpi_access(
    route_name: object,
) -> None:
    candidate = make_request(route_name=route_name)

    assert resolve_release_sha256(candidate) is None
    assert candidate.registry["xom"].filestore.calls == []
    assert candidate.context.stage.calls == []


@pytest.mark.parametrize("relation", NON_RELEASE_RELATIONS)
def test_non_release_relations_pass_through(relation: str) -> None:
    assert resolve_release_sha256(make_request(relation=relation)) is None


@pytest.mark.parametrize("sha256", INVALID_SHA256S)
def test_release_without_canonical_sha256_fails_closed(sha256: object) -> None:
    candidate = make_request()
    candidate.registry["xom"].filestore.entry.hashes = {"sha256": sha256}

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)


@pytest.mark.parametrize(
    "hashes",
    [
        {},
        {"md5": "a" * 32},
        {"SHA256": SHA256},
        f"sha256={SHA256}",
        [("sha256", SHA256)],
        None,
    ],
)
def test_release_without_verified_sha256_entry_metadata_fails_closed(
    hashes: object,
) -> None:
    candidate = make_request()
    candidate.registry["xom"].filestore.entry.hashes = hashes

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)


def test_untrusted_digest_sources_are_ignored() -> None:
    candidate = make_request()
    candidate.registry["xom"].filestore.entry.hashes = {"md5": "d" * 32}
    candidate.context.stage.link.hashes = {"sha256": SHA256}
    candidate.path_info = candidate.path_info.replace("abc", SHA256)
    tail = candidate.matchdict["relpath"]
    candidate.matchdict["relpath"] = tail.replace("abc", SHA256)
    candidate.registry["xom"].filestore.entry.relpath = candidate.registry[
        "xom"
    ].filestore.entry.relpath.replace("abc", SHA256)
    link_relpath = candidate.context.stage.link.relpath
    candidate.context.stage.link.relpath = link_relpath.replace("abc", SHA256)

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)


@pytest.mark.parametrize(
    ("tail", "path_info"),
    [
        ("", "/root/pypi/+f/"),
        ("/demo.whl", "/root/pypi/+f//demo.whl"),
        ("abc//demo.whl", "/root/pypi/+f/abc//demo.whl"),
        ("abc/", "/root/pypi/+f/abc/"),
        ("../demo.whl", "/root/pypi/+f/../demo.whl"),
        ("abc/./demo.whl", "/root/pypi/+f/abc/./demo.whl"),
        ("abc/%2e%2e/demo.whl", "/root/pypi/+f/abc/%2e%2e/demo.whl"),
        ("abc%2Fdemo.whl", "/root/pypi/+f/abc%2Fdemo.whl"),
        ("abc\\demo.whl", "/root/pypi/+f/abc\\demo.whl"),
        (
            "abc/demo.whl#sha256=secret",
            "/root/pypi/+f/abc/demo.whl#sha256=secret",
        ),
        ("abc/\x00demo.whl", "/root/pypi/+f/abc/\x00demo.whl"),
        ("abc/\x1fdemo.whl", "/root/pypi/+f/abc/\x1fdemo.whl"),
        ("abc/\x7fdemo.whl", "/root/pypi/+f/abc/\x7fdemo.whl"),
    ],
)
def test_ambiguous_or_unsafe_relpaths_fail_closed(
    tail: str,
    path_info: str,
) -> None:
    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(make_request(tail=tail, path_info=path_info))


@pytest.mark.parametrize("raw_key", RAW_PATH_KEYS)
def test_percent_encoded_raw_artifact_path_fails_closed(raw_key: str) -> None:
    candidate = make_request(environ={raw_key: ENCODED_ARTIFACT_URI})

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)


@pytest.mark.parametrize(
    ("matchdict", "path_info"),
    [
        ({}, "/root/pypi/+f/abc/demo.whl"),
        ({"user": "root", "index": "pypi"}, "/root/pypi/+f/abc/demo.whl"),
        (
            {"user": "root", "index": "pypi", "relpath": "abc/demo.whl"},
            "/other/pypi/+f/abc/demo.whl",
        ),
        (
            {"user": "root", "index": "pypi", "relpath": "abc/demo.whl"},
            "/root/pypi/+e/abc/demo.whl",
        ),
    ],
)
def test_missing_or_inconsistent_route_path_data_fails_closed(
    matchdict: object, path_info: str
) -> None:
    with pytest.raises(ArtifactIdentityUnavailable):
        candidate = make_request(matchdict=matchdict, path_info=path_info)
        resolve_release_sha256(candidate)


@pytest.mark.parametrize(
    "stage",
    [
        SimpleNamespace(username="other", index="pypi"),
        SimpleNamespace(username="root", index="other"),
        SimpleNamespace(),
        None,
    ],
)
def test_missing_or_inconsistent_stage_context_fails_closed(
    stage: object | None,
) -> None:
    candidate = make_request()
    candidate.context = SimpleNamespace(stage=stage)

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)


@pytest.mark.parametrize(
    "change",
    [
        "entry_relpath",
        "entry_user",
        "entry_index",
        "link_relpath",
        "project",
        "version",
    ],
)
def test_inconsistent_entry_or_link_identity_fails_closed(change: str) -> None:
    candidate = make_request()
    entry = candidate.registry["xom"].filestore.entry
    link = candidate.context.stage.link
    if change == "entry_relpath":
        entry.relpath = "root/pypi/+f/other/demo.whl"
    elif change == "entry_user":
        entry.user = "other"
    elif change == "entry_index":
        entry.index = "other"
    elif change == "link_relpath":
        link.relpath = "root/pypi/+f/other/demo.whl"
    elif change == "project":
        link.project = "other"
    else:
        link.version = "2.0"

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)


def test_releasefile_reflink_shape_fails_closed() -> None:
    candidate = make_request()
    candidate.context.stage.link.for_entrypath = "root/pypi/+f/base/demo.whl"

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)


@pytest.mark.parametrize(
    "candidate",
    [
        make_request(entry=None, filestore=FakeFileStore(None)),
        make_request(link=None, stage=FakeStage(None)),
        make_request(
            route_name=E_ROUTE,
            marker="+e",
            filestore=FakeFileStore(None, key=FakeKey(exists=False)),
        ),
        make_request(
            route_name=E_ROUTE,
            marker="+e",
            filestore=FakeFileStore(None, key=None),
        ),
    ],
)
def test_missing_entry_key_or_link_fails_closed(candidate) -> None:
    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)


@pytest.mark.parametrize(
    "candidate",
    [
        make_request(filestore=FakeFileStore(None, error_at="get_file_entry")),
        make_request(
            stage=FakeStage(None, error=AssertionError("multiple links")),
        ),
        make_request(
            entry=FailingHashesEntry(DEFAULT_RELPATH),
        ),
        make_request(
            route_name=E_ROUTE,
            marker="+e",
            filestore=FakeFileStore(
                None,
                key=FakeKey(error=RuntimeError("secret")),
            ),
        ),
    ],
)
def test_devpi_api_exceptions_are_sanitized(candidate) -> None:
    with pytest.raises(ArtifactIdentityUnavailable) as raised:
        resolve_release_sha256(candidate)

    assert str(raised.value) == "protected artifact identity unavailable"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert "secret" not in repr(raised.value)
    assert "/private" not in repr(raised.value)


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(3)])
def test_process_control_errors_propagate(error: BaseException) -> None:
    candidate = make_request(
        filestore=FakeFileStore(None, error_at="get_file_entry"),
    )

    def raise_control(_relpath):
        raise error

    candidate.registry["xom"].filestore.get_file_entry = raise_control
    with pytest.raises(type(error)):
        resolve_release_sha256(candidate)
