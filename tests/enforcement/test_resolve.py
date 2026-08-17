from __future__ import annotations

import ast
import inspect
import textwrap
from types import SimpleNamespace
from urllib.parse import quote

import pytest
from devpi_server.main import XOM
from devpi_server.markers import unknown
from devpi_server.views import PyPIView
from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.tweens import EXCVIEW

from devpi_guardian.enforcement.resolve import (
    ArtifactIdentityUnavailable,
    resolve_release_sha256,
)

SHA256 = "a" * 64
F_ROUTE = "/{user}/{index}/+f/{relpath:.*}"
E_ROUTE = "/{user}/{index}/+e/{relpath:.*}"
DEFAULT_RELPATH = "root/pypi/+f/abc/demo-1.0-py3-none-any.whl"
DEFAULT_PATH_INFO = f"/{DEFAULT_RELPATH}"
DEFAULT_KEY = object()
NON_DOWNLOAD_METHODS = ("POST", "PUT", "PATCH", "DELETE", "get", None, [])
NON_RELEASE_RELATIONS = ("toxresult", "doczip", "other", "releaseFile", "")
INVALID_SHA256S = (None, "", "A" * 64, "g" * 64, "a" * 63, "a" * 65)
RAW_PATH_KEYS = ("RAW_URI", "REQUEST_URI", "RAW_PATH_INFO")
ROUTED_ATTRIBUTES = ("matched_route", "matchdict", "context")
ENCODED_ARTIFACT_PATH = "/root/pypi/+f/abc%2Fdemo-1.0-py3-none-any.whl"
ENCODED_ARTIFACT_URI = ENCODED_ARTIFACT_PATH + "?token=secret"
RFC3986_PATH_SAFE = "/:@-._~!$&'()*+,;="
UNICODE_USER = "사용자"
UNICODE_INDEX = "인덱스"
UNICODE_TAIL = "경로/데모-1.0-py3-none-any.whl"
UNICODE_PATH_INFO = f"/{UNICODE_USER}/{UNICODE_INDEX}/+f/{UNICODE_TAIL}"
UNICODE_RAW_PATH = quote(UNICODE_PATH_INFO, safe=RFC3986_PATH_SAFE)


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


class HostileSha256(str):
    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False


class FailingPathInfoRequest:
    def __init__(self, candidate: object) -> None:
        self.__dict__.update(candidate.__dict__)

    @property
    def path_info(self):
        raise UnicodeDecodeError(
            "utf-8",
            b"\xff",
            0,
            1,
            "/private/request-target?token=secret",
        )


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


class FakeRefreshStage(FakeStage):
    def __init__(
        self,
        link: object,
        project_states: list[object],
        *,
        filestore: FakeFileStore | None = None,
        refreshed_entry: object | None = None,
        no_project_list: object = False,
        error_at: str | None = None,
        username: str = "root",
        index: str = "pypi",
    ) -> None:
        super().__init__(link, username=username, index=index)
        self.project_states = list(project_states)
        self.filestore = filestore
        self.refreshed_entry = refreshed_entry
        self.no_project_list = no_project_list
        self.error_at = error_at
        self.project_calls: list[str] = []
        self.refresh_calls: list[str] = []

    def has_project_perstage(self, project: str):
        self.project_calls.append(project)
        if self.error_at == "has_project_perstage":
            raise RuntimeError("/private/project-list?token=secret")
        if not self.project_states:
            raise AssertionError("unexpected project existence check")
        return self.project_states.pop(0)

    def list_versions_perstage(self, project: str):
        self.refresh_calls.append(project)
        if self.error_at == "list_versions_perstage":
            raise RuntimeError("/private/simple?token=secret")
        if self.filestore is not None:
            self.filestore.entry = self.refreshed_entry
        return {"1.0"}


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


class FakeModel:
    def __init__(
        self,
        stage: object | None,
        *,
        error: Exception | None = None,
    ) -> None:
        self.stage = stage
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def getstage(self, user: str, index: str):
        self.calls.append((user, index))
        if self.error is not None:
            raise self.error
        return self.stage


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
    model: object | None = None,
    environ: object | None = None,
    user: str = "root",
    index: str = "pypi",
):
    full_relpath = f"{user}/{index}/{marker}/{tail}"
    if entry is None:
        entry = FakeEntry(full_relpath, user=user, index=index)
    if link is None:
        link = FakeLink(full_relpath, relation=relation)
    if stage is None:
        stage = FakeStage(link, username=user, index=index)
    if filestore is None:
        filestore = FakeFileStore(entry)
    if model is None:
        model = FakeModel(stage)
    if matchdict is None:
        matchdict = {"user": user, "index": index, "relpath": tail}
    if path_info is None:
        path_info = f"/{full_relpath}"
    if environ is None:
        environ = {}
    return SimpleNamespace(
        method=method,
        matched_route=SimpleNamespace(name=route_name),
        matchdict=matchdict,
        path_info=path_info,
        registry={"xom": SimpleNamespace(filestore=filestore, model=model)},
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


def resolver_probe_tween_factory(handler, registry):
    def probe(request):
        routed_attributes = {}
        for name in ROUTED_ATTRIBUTES:
            routed_attributes[name] = name in request.__dict__
        try:
            resolved = resolve_release_sha256(request)
        except ArtifactIdentityUnavailable:
            probe_result = (routed_attributes, "identity-unavailable")
            registry["resolver_probe"].append(probe_result)
            raise
        registry["resolver_probe"].append((routed_attributes, resolved))
        return Response("probe")

    return probe


def passthrough_resolver_probe_tween_factory(handler, registry):
    def probe(request):
        try:
            resolved = resolve_release_sha256(request)
        except ArtifactIdentityUnavailable:
            registry["resolver_probe"].append("identity-unavailable")
            raise
        registry["resolver_probe"].append(resolved)
        registry["downstream_calls"] += 1
        return handler(request)

    return probe


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


def test_pinned_devpi_f_view_refresh_order() -> None:
    source = inspect.getsource(PyPIView.stage_pkgserv)
    first_lookup = source.index("self.xom.filestore.get_file_entry(relpath)")
    project_parse = source.index("splitbasename(Path(relpath).name)[0]")
    refresh = source.index("stage.list_versions_perstage(project)")
    second_lookup = source.rindex("self.xom.filestore.get_file_entry(relpath)")

    assert first_lookup < project_parse < refresh < second_lookup


@pytest.mark.parametrize(
    ("marker", "route_name"),
    [("+f", F_ROUTE), ("+e", E_ROUTE)],
)
@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_real_pyramid_tween_resolves_before_router_populates_attributes(
    marker: str,
    route_name: str,
    method: str,
) -> None:
    relpath = f"root/pypi/{marker}/abc/demo-1.0-py3-none-any.whl"
    entry = FakeEntry(relpath)
    stage = FakeStage(FakeLink(relpath))
    model = FakeModel(stage)
    filestore = FakeFileStore(entry)
    config = Configurator()
    config.registry["xom"] = SimpleNamespace(
        filestore=filestore,
        model=model,
    )
    config.registry["resolver_probe"] = []
    config.add_route(
        route_name,
        f"/{{user:[^+/]+}}/{{index:[^+/]+}}/{marker}/{{relpath:.*}}",
    )
    config.add_tween(
        "tests.enforcement.test_resolve.resolver_probe_tween_factory",
        over=EXCVIEW,
    )
    application = config.make_wsgi_app()

    request = application.request_factory.blank(f"/{relpath}", method=method)
    response = request.get_response(application)

    assert response.status_code == 200
    assert config.registry["resolver_probe"] == [
        (
            {
                "matched_route": False,
                "matchdict": False,
                "context": False,
            },
            SHA256,
        )
    ]
    assert model.calls == [("root", "pypi")]


def test_real_pyramid_tween_passes_unrelated_path_before_routing() -> None:
    config = Configurator()
    model = FakeModel(None)
    config.registry["xom"] = SimpleNamespace(
        filestore=FakeFileStore(None),
        model=model,
    )
    config.registry["resolver_probe"] = []
    config.add_route("/+api", "/+api")
    config.add_tween(
        "tests.enforcement.test_resolve.resolver_probe_tween_factory",
        over=EXCVIEW,
    )
    application = config.make_wsgi_app()

    request = application.request_factory.blank("/+api")
    response = request.get_response(application)

    assert response.status_code == 200
    assert config.registry["resolver_probe"] == [
        (
            {
                "matched_route": False,
                "matchdict": False,
                "context": False,
            },
            None,
        )
    ]
    assert model.calls == []


@pytest.mark.parametrize(
    ("raw_key", "raw_value"),
    [
        ("REQUEST_URI", "/unrelated"),
        ("RAW_URI", "/unrelated"),
        ("RAW_PATH_INFO", "/unrelated"),
    ],
)
def test_real_pyramid_tween_rejects_inconsistent_raw_artifact_path(
    raw_key: str,
    raw_value: str,
) -> None:
    relpath = DEFAULT_RELPATH
    stage = FakeStage(FakeLink(relpath))
    model = FakeModel(stage)
    config = Configurator()
    config.registry["xom"] = SimpleNamespace(
        filestore=FakeFileStore(FakeEntry(relpath)),
        model=model,
    )
    config.registry["resolver_probe"] = []
    config.add_route(F_ROUTE, "/{user}/{index}/+f/{relpath:.*}")
    config.add_tween(
        "tests.enforcement.test_resolve.resolver_probe_tween_factory",
        over=EXCVIEW,
    )
    application = config.make_wsgi_app()

    request = application.request_factory.blank(DEFAULT_PATH_INFO)
    request.environ[raw_key] = raw_value

    with pytest.raises(ArtifactIdentityUnavailable) as raised:
        request.get_response(application)

    assert str(raised.value) == "protected artifact identity unavailable"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert config.registry["resolver_probe"] == [
        (
            {
                "matched_route": False,
                "matchdict": False,
                "context": False,
            },
            "identity-unavailable",
        )
    ]
    assert model.calls == []


@pytest.mark.parametrize("marker", ["+f", "+e"])
@pytest.mark.parametrize("malformed", ["%FF", "%C0%AF", "%ED%A0%80"])
def test_real_pyramid_tween_fails_closed_on_malformed_utf8_path(
    marker: str,
    malformed: str,
) -> None:
    route_name = F_ROUTE if marker == "+f" else E_ROUTE
    config = Configurator()
    model = FakeModel(None)
    config.registry["xom"] = SimpleNamespace(
        filestore=FakeFileStore(None),
        model=model,
    )
    config.registry["resolver_probe"] = []
    config.registry["downstream_calls"] = 0
    config.add_route(
        route_name,
        f"/{{user}}/{{index}}/{marker}/{{relpath:.*}}",
    )
    tween_module = "tests.enforcement.test_resolve"
    tween_name = "passthrough_resolver_probe_tween_factory"
    tween_factory = f"{tween_module}.{tween_name}"
    config.add_tween(tween_factory, over=EXCVIEW)
    application = config.make_wsgi_app()
    filename = f"demo-1.0-{malformed}-py3-none-any.whl"
    raw_target = f"/root/pypi/{marker}/abc/{filename}"
    request = application.request_factory.blank(raw_target)

    with pytest.raises(UnicodeDecodeError):
        _ = request.path_info
    with pytest.raises(ArtifactIdentityUnavailable) as raised:
        request.get_response(application)

    assert str(raised.value) == "protected artifact identity unavailable"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert "secret" not in repr(raised.value)
    assert "/private" not in repr(raised.value)
    assert config.registry["resolver_probe"] == ["identity-unavailable"]
    assert config.registry["downstream_calls"] == 0
    assert model.calls == []


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_real_pyramid_tween_accepts_canonical_unicode_raw_path(
    method: str,
) -> None:
    relpath = UNICODE_PATH_INFO.removeprefix("/")
    entry = FakeEntry(
        relpath,
        user=UNICODE_USER,
        index=UNICODE_INDEX,
    )
    stage = FakeStage(
        FakeLink(relpath),
        username=UNICODE_USER,
        index=UNICODE_INDEX,
    )
    model = FakeModel(stage)
    config = Configurator()
    config.registry["xom"] = SimpleNamespace(
        filestore=FakeFileStore(entry),
        model=model,
    )
    config.registry["resolver_probe"] = []
    config.add_route(F_ROUTE, "/{user}/{index}/+f/{relpath:.*}")
    config.add_tween(
        "tests.enforcement.test_resolve.resolver_probe_tween_factory",
        over=EXCVIEW,
    )
    application = config.make_wsgi_app()

    request_factory = application.request_factory
    request = request_factory.blank(UNICODE_RAW_PATH, method=method)
    request.environ["REQUEST_URI"] = f"{UNICODE_RAW_PATH}?token=%2Fsecret"
    response = request.get_response(application)

    assert response.status_code == 200
    assert request.path_info == UNICODE_PATH_INFO
    assert config.registry["resolver_probe"] == [
        (
            {
                "matched_route": False,
                "matchdict": False,
                "context": False,
            },
            SHA256,
        )
    ]
    assert model.calls == [(UNICODE_USER, UNICODE_INDEX)]


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
    assert candidate.registry["xom"].model.calls == [("root", "pypi")]


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_real_pyramid_tween_refreshes_f_project_metadata_after_entry_miss(
    method: str,
) -> None:
    relpath = DEFAULT_RELPATH
    entry = FakeEntry(relpath)
    filestore = FakeFileStore(None)
    stage = FakeRefreshStage(
        FakeLink(relpath),
        [True, True],
        filestore=filestore,
        refreshed_entry=entry,
    )
    model = FakeModel(stage)
    config = Configurator()
    config.registry["xom"] = SimpleNamespace(
        filestore=filestore,
        model=model,
    )
    config.registry["resolver_probe"] = []
    config.add_route(F_ROUTE, "/{user}/{index}/+f/{relpath:.*}")
    config.add_tween(
        "tests.enforcement.test_resolve.resolver_probe_tween_factory",
        over=EXCVIEW,
    )
    application = config.make_wsgi_app()

    request_factory = application.request_factory
    request = request_factory.blank(DEFAULT_PATH_INFO, method=method)
    response = request.get_response(application)

    assert response.status_code == 200
    assert config.registry["resolver_probe"] == [
        (
            {
                "matched_route": False,
                "matchdict": False,
                "context": False,
            },
            SHA256,
        )
    ]
    assert filestore.calls == [
        ("get_file_entry", relpath),
        ("get_file_entry", relpath),
    ]
    assert stage.project_calls == ["demo", "demo"]
    assert stage.refresh_calls == ["demo"]
    assert stage.calls == [relpath]


def test_f_metadata_request_refreshes_for_the_underlying_wheel() -> None:
    relpath = DEFAULT_RELPATH
    filestore = FakeFileStore(None)
    stage = FakeRefreshStage(
        FakeLink(relpath),
        [True, True],
        filestore=filestore,
        refreshed_entry=FakeEntry(relpath),
    )
    candidate = make_request(
        tail="abc/demo-1.0-py3-none-any.whl.metadata",
        filestore=filestore,
        stage=stage,
        model=FakeModel(stage),
    )

    assert resolve_release_sha256(candidate) == SHA256
    assert filestore.calls == [
        ("get_file_entry", relpath),
        ("get_file_entry", relpath),
    ]
    assert stage.project_calls == ["demo", "demo"]
    assert stage.refresh_calls == ["demo"]


def test_f_unknown_project_refresh_without_list() -> None:
    relpath = DEFAULT_RELPATH
    filestore = FakeFileStore(None)
    stage = FakeRefreshStage(
        FakeLink(relpath),
        [unknown, True],
        filestore=filestore,
        refreshed_entry=FakeEntry(relpath),
        no_project_list=True,
    )
    candidate = make_request(
        filestore=filestore,
        stage=stage,
        model=FakeModel(stage),
    )

    assert resolve_release_sha256(candidate) == SHA256
    assert stage.project_calls == ["demo", "demo"]
    assert stage.refresh_calls == ["demo"]


@pytest.mark.parametrize(
    ("project_states", "no_project_list", "expected_project_calls"),
    [
        ([False], False, ["demo"]),
        ([unknown], False, ["demo"]),
        ([True, False], False, ["demo", "demo"]),
    ],
)
def test_f_missing_entry_only_retries_after_confirmed_project_refresh(
    project_states: list[object],
    no_project_list: bool,
    expected_project_calls: list[str],
) -> None:
    filestore = FakeFileStore(None)
    stage = FakeRefreshStage(
        FakeLink(DEFAULT_RELPATH),
        project_states,
        filestore=filestore,
        refreshed_entry=FakeEntry(DEFAULT_RELPATH),
        no_project_list=no_project_list,
    )
    candidate = make_request(
        filestore=filestore,
        stage=stage,
        model=FakeModel(stage),
    )

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)

    assert stage.project_calls == expected_project_calls
    if len(project_states) == 1:
        assert stage.refresh_calls == []
        assert filestore.calls == [("get_file_entry", DEFAULT_RELPATH)]
    else:
        assert stage.refresh_calls == ["demo"]
        assert filestore.calls == [("get_file_entry", DEFAULT_RELPATH)]


def test_f_project_refresh_retries_entry_lookup_only_once() -> None:
    filestore = FakeFileStore(None)
    stage = FakeRefreshStage(
        FakeLink(DEFAULT_RELPATH),
        [True, True],
        filestore=filestore,
    )
    candidate = make_request(
        filestore=filestore,
        stage=stage,
        model=FakeModel(stage),
    )

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)

    assert filestore.calls == [
        ("get_file_entry", DEFAULT_RELPATH),
        ("get_file_entry", DEFAULT_RELPATH),
    ]
    assert stage.refresh_calls == ["demo"]


@pytest.mark.parametrize(
    ("error_at", "expected_project_calls", "expected_refresh_calls"),
    [
        ("has_project_perstage", ["demo"], []),
        ("list_versions_perstage", ["demo"], ["demo"]),
    ],
)
def test_f_project_refresh_api_failures_are_sanitized(
    error_at: str,
    expected_project_calls: list[str],
    expected_refresh_calls: list[str],
) -> None:
    filestore = FakeFileStore(None)
    stage = FakeRefreshStage(
        FakeLink(DEFAULT_RELPATH),
        [True, True],
        filestore=filestore,
        refreshed_entry=FakeEntry(DEFAULT_RELPATH),
        error_at=error_at,
    )
    candidate = make_request(
        filestore=filestore,
        stage=stage,
        model=FakeModel(stage),
    )

    with pytest.raises(ArtifactIdentityUnavailable) as raised:
        resolve_release_sha256(candidate)

    assert str(raised.value) == "protected artifact identity unavailable"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert "secret" not in repr(raised.value)
    assert "/private" not in repr(raised.value)
    assert stage.project_calls == expected_project_calls
    assert stage.refresh_calls == expected_refresh_calls
    assert filestore.calls == [("get_file_entry", DEFAULT_RELPATH)]


@pytest.mark.parametrize("project_state", [None, 1, "yes", object()])
def test_f_project_refresh_rejects_non_devpi_project_states(
    project_state: object,
) -> None:
    filestore = FakeFileStore(None)
    stage = FakeRefreshStage(
        FakeLink(DEFAULT_RELPATH),
        [project_state],
    )
    candidate = make_request(
        filestore=filestore,
        stage=stage,
        model=FakeModel(stage),
    )

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)

    assert stage.project_calls == ["demo"]
    assert stage.refresh_calls == []


def test_f_nonarchive_miss_does_not_refresh() -> None:
    relpath = "root/pypi/+f/abc/not-an-archive.txt"
    filestore = FakeFileStore(None)
    stage = FakeRefreshStage(FakeLink(relpath), [True])
    candidate = make_request(
        tail="abc/not-an-archive.txt",
        filestore=filestore,
        stage=stage,
        model=FakeModel(stage),
    )

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)

    assert filestore.calls == [("get_file_entry", relpath)]
    assert stage.project_calls == []
    assert stage.refresh_calls == []


def test_e_missing_key_never_refreshes_project_metadata() -> None:
    relpath = "root/pypi/+e/abc/demo-1.0-py3-none-any.whl"
    filestore = FakeFileStore(None, key=FakeKey(exists=False))
    stage = FakeRefreshStage(FakeLink(relpath), [True, True])
    candidate = make_request(
        route_name=E_ROUTE,
        marker="+e",
        filestore=filestore,
        stage=stage,
        model=FakeModel(stage),
    )

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)

    assert filestore.calls == [("get_key_from_relpath", relpath)]
    assert stage.project_calls == []
    assert stage.refresh_calls == []


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
    candidate.path_info = "/+api"

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


def test_release_with_hostile_sha256_subclass_fails_closed() -> None:
    candidate = make_request()
    candidate.registry["xom"].filestore.entry.hashes = {
        "sha256": HostileSha256(SHA256),
    }

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
        ("demo.whl", "/root//+f/demo.whl"),
        ("demo.whl", "//root/pypi/+f/demo.whl"),
        ("demo.whl", "/root/pypi//+f/demo.whl"),
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
    candidate = make_request(tail=tail, path_info=path_info)
    del candidate.matched_route
    del candidate.matchdict
    del candidate.context

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)


@pytest.mark.parametrize("raw_key", RAW_PATH_KEYS)
def test_percent_encoded_raw_artifact_path_fails_closed(raw_key: str) -> None:
    candidate = make_request(environ={raw_key: ENCODED_ARTIFACT_URI})

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)


@pytest.mark.parametrize(
    "environ",
    [
        {"REQUEST_URI": "/unrelated"},
        {"RAW_URI": "/unrelated"},
        {"RAW_PATH_INFO": "/unrelated"},
        {
            "REQUEST_URI": DEFAULT_PATH_INFO,
            "RAW_URI": "/root/pypi/+f/other.whl",
        },
        {"SCRIPT_NAME": "/prefix", "REQUEST_URI": DEFAULT_PATH_INFO},
        {
            "SCRIPT_NAME": "/other",
            "REQUEST_URI": f"/prefix{DEFAULT_PATH_INFO}",
        },
        {"SCRIPT_NAME": "prefix", "REQUEST_URI": DEFAULT_PATH_INFO},
        {"SCRIPT_NAME": "/prefix/", "REQUEST_URI": DEFAULT_PATH_INFO},
        {"SCRIPT_NAME": None, "REQUEST_URI": DEFAULT_PATH_INFO},
        {"REQUEST_URI": ""},
        {"REQUEST_URI": f"https://devpi.invalid{DEFAULT_PATH_INFO}"},
    ],
)
def test_inconsistent_raw_artifact_paths_fail_closed(environ: object) -> None:
    candidate = make_request(environ=environ)

    with pytest.raises(ArtifactIdentityUnavailable) as raised:
        resolve_release_sha256(candidate)

    assert str(raised.value) == "protected artifact identity unavailable"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert candidate.registry["xom"].model.calls == []


@pytest.mark.parametrize(
    "environ",
    [
        {},
        {
            "SCRIPT_NAME": "",
            "REQUEST_URI": DEFAULT_PATH_INFO,
            "RAW_URI": f"{DEFAULT_PATH_INFO}?token=secret",
            "RAW_PATH_INFO": DEFAULT_PATH_INFO,
        },
        {
            "SCRIPT_NAME": "/prefix",
            "REQUEST_URI": f"/prefix{DEFAULT_PATH_INFO}?sha256={'b' * 64}",
            "RAW_URI": f"/prefix{DEFAULT_PATH_INFO}?encoded=%2F",
            "RAW_PATH_INFO": DEFAULT_PATH_INFO,
        },
    ],
)
def test_consistent_raw_artifact_paths_resolve(environ: object) -> None:
    candidate = make_request(environ=environ)

    assert resolve_release_sha256(candidate) == SHA256


def test_canonical_unicode_raw_paths_resolve_with_unicode_mount() -> None:
    script_name = "/접두"
    relpath = UNICODE_PATH_INFO.removeprefix("/")
    candidate = make_request(
        user=UNICODE_USER,
        index=UNICODE_INDEX,
        tail=UNICODE_TAIL,
        environ={
            "SCRIPT_NAME": script_name,
            "REQUEST_URI": (
                quote(
                    f"{script_name}{UNICODE_PATH_INFO}",
                    safe=RFC3986_PATH_SAFE,
                )
                + "?token=%2Fsecret"
            ),
            "RAW_URI": quote(
                f"{script_name}{UNICODE_PATH_INFO}",
                safe=RFC3986_PATH_SAFE,
            ),
            "RAW_PATH_INFO": UNICODE_RAW_PATH,
        },
    )
    candidate.registry["xom"].filestore.entry = FakeEntry(
        relpath,
        user=UNICODE_USER,
        index=UNICODE_INDEX,
    )

    assert resolve_release_sha256(candidate) == SHA256


@pytest.mark.parametrize("encoded", [False, True])
def test_ascii_raw_path_accepts_decoded_and_canonical_forms(
    encoded: bool,
) -> None:
    tail = "abc/demo 1.0-py3-none-any.whl"
    path_info = f"/root/pypi/+f/{tail}"
    canonical_path = quote(path_info, safe=RFC3986_PATH_SAFE)
    raw_path = canonical_path if encoded else path_info
    candidate = make_request(
        tail=tail,
        environ={
            "REQUEST_URI": raw_path,
            "RAW_URI": raw_path,
            "RAW_PATH_INFO": raw_path,
        },
    )

    assert resolve_release_sha256(candidate) == SHA256


@pytest.mark.parametrize(
    "raw_path",
    [
        UNICODE_PATH_INFO,
        UNICODE_RAW_PATH.replace("%EC", "%ec", 1),
        UNICODE_RAW_PATH.replace("%EC", "%25EC", 1),
        UNICODE_RAW_PATH.replace("%EC", "%GG", 1),
        UNICODE_RAW_PATH.replace("/+f/", "/%2Bf/"),
        UNICODE_RAW_PATH.replace("%EC", "%FF", 1),
    ],
)
def test_noncanonical_unicode_raw_paths_fail_closed(raw_path: str) -> None:
    candidate = make_request(
        user=UNICODE_USER,
        index=UNICODE_INDEX,
        tail=UNICODE_TAIL,
        environ={"REQUEST_URI": raw_path},
    )

    with pytest.raises(ArtifactIdentityUnavailable) as raised:
        resolve_release_sha256(candidate)

    assert str(raised.value) == "protected artifact identity unavailable"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert candidate.registry["xom"].model.calls == []


def test_unicode_raw_path_keys_must_all_match_the_decoded_identity() -> None:
    candidate = make_request(
        user=UNICODE_USER,
        index=UNICODE_INDEX,
        tail=UNICODE_TAIL,
        environ={
            "REQUEST_URI": UNICODE_RAW_PATH,
            "RAW_URI": UNICODE_RAW_PATH,
            "RAW_PATH_INFO": UNICODE_RAW_PATH.replace("%EB", "%EC", 1),
        },
    )

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)

    assert candidate.registry["xom"].model.calls == []


def test_nonprotected_path_ignores_inconsistent_raw_environment() -> None:
    model = FakeModel(None)
    candidate = make_request(
        path_info="/+api",
        model=model,
        environ={
            "SCRIPT_NAME": None,
            "REQUEST_URI": "/unrelated",
            "RAW_URI": object(),
            "RAW_PATH_INFO": "/other",
        },
    )

    assert resolve_release_sha256(candidate) is None
    assert model.calls == []


def test_path_info_decode_failure_is_sanitized_and_fails_closed() -> None:
    candidate = make_request()
    model = candidate.registry["xom"].model
    failing_request = FailingPathInfoRequest(candidate)

    with pytest.raises(ArtifactIdentityUnavailable) as raised:
        resolve_release_sha256(failing_request)

    assert str(raised.value) == "protected artifact identity unavailable"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert "secret" not in repr(raised.value)
    assert "/private" not in repr(raised.value)
    assert model.calls == []


@pytest.mark.parametrize("path_info", [None, object(), [], 42])
def test_invalid_path_info_type_fails_closed(path_info: object) -> None:
    candidate = make_request()
    candidate.path_info = path_info

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)

    assert candidate.registry["xom"].model.calls == []


def test_missing_path_info_fails_closed() -> None:
    candidate = make_request()
    del candidate.path_info

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)

    assert candidate.registry["xom"].model.calls == []


def test_non_get_request_does_not_require_path_info() -> None:
    candidate = make_request(method="POST")
    del candidate.path_info

    assert resolve_release_sha256(candidate) is None
    assert candidate.registry["xom"].model.calls == []


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
    "model",
    [
        FakeModel(None),
        FakeModel(None, error=RuntimeError("/private?token=secret")),
        SimpleNamespace(),
        None,
    ],
)
def test_missing_or_failing_stage_model_lookup_is_sanitized(
    model: object | None,
) -> None:
    candidate = make_request()
    candidate.registry["xom"].model = model

    with pytest.raises(ArtifactIdentityUnavailable) as raised:
        resolve_release_sha256(candidate)

    assert str(raised.value) == "protected artifact identity unavailable"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize(
    "model_stage",
    [
        FakeStage(FakeLink(DEFAULT_RELPATH), username="other"),
        FakeStage(FakeLink(DEFAULT_RELPATH), index="other"),
        SimpleNamespace(username="root", index="pypi"),
    ],
)
def test_model_stage_must_match_path_and_support_link_lookup(
    model_stage: object,
) -> None:
    candidate = make_request(model=FakeModel(model_stage))

    with pytest.raises(ArtifactIdentityUnavailable):
        resolve_release_sha256(candidate)


@pytest.mark.parametrize("attribute", ROUTED_ATTRIBUTES)
def test_contradictory_routed_attributes_fail_closed(attribute: str) -> None:
    candidate = make_request()
    if attribute == "matched_route":
        candidate.matched_route = SimpleNamespace(name=E_ROUTE)
    elif attribute == "matchdict":
        candidate.matchdict = {
            "user": "other",
            "index": "pypi",
            "relpath": "abc/demo-1.0-py3-none-any.whl",
        }
    else:
        context_stage = SimpleNamespace(username="other", index="pypi")
        candidate.context = SimpleNamespace(stage=context_stage)

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
