from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import quote

from devpi_common.metadata import splitbasename
from devpi_server.markers import Unknown

from devpi_guardian.verdicts.errors import InvalidSha256
from devpi_guardian.verdicts.models import validate_sha256

_F_ROUTE = "/{user}/{index}/+f/{relpath:.*}"
_E_ROUTE = "/{user}/{index}/+e/{relpath:.*}"
_METADATA_SUFFIX = ".metadata"
_RELEASE_RELATION = "releasefile"
_RFC3986_PATH_SAFE = "/:@-._~!$&'()*+,;="
_UNAVAILABLE_MESSAGE = "protected artifact identity unavailable"
_FAILED = object()
_MISSING = object()


class ArtifactIdentityUnavailable(Exception):
    """A protected release request cannot be tied to a verified SHA-256."""


def _fail() -> None:
    raise ArtifactIdentityUnavailable(_UNAVAILABLE_MESSAGE) from None


def _safe_getattr(value: object, name: str) -> Any:
    try:
        return getattr(value, name)
    except Exception:
        return _FAILED


def _safe_optional_getattr(value: object, name: str) -> Any:
    try:
        return getattr(value, name)
    except AttributeError:
        return _MISSING
    except Exception:
        return _FAILED


def _safe_getitem(value: object, key: str) -> Any:
    try:
        return value[key]  # type: ignore[index]
    except Exception:
        return _FAILED


def _safe_optional_getitem(value: object, key: str) -> Any:
    try:
        return value[key]  # type: ignore[index]
    except KeyError:
        return _MISSING
    except Exception:
        return _FAILED


def _safe_call(callable_value: object, *args: object) -> Any:
    if not callable(callable_value):
        return _FAILED
    try:
        return callable_value(*args)
    except Exception:
        return _FAILED


def _has_unsafe_character(value: str) -> bool:
    for character in value:
        if character in {"%", "#", "\\"}:
            return True
        if unicodedata.category(character).startswith("C"):
            return True
    return False


def _valid_route_segment(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value not in {".", ".."}
        and "/" not in value
        and "+" not in value
        and not _has_unsafe_character(value)
    )


def _valid_relpath_tail(value: object) -> bool:
    if not isinstance(value, str) or not value or _has_unsafe_character(value):
        return False
    parts = value.split("/")
    return all(part and part not in {".", ".."} for part in parts)


def _valid_script_name(value: object) -> bool:
    if not isinstance(value, str):
        return False
    if value == "":
        return True
    if (
        not value.startswith("/")
        or value.endswith("/")
        or "?" in value
        or _has_unsafe_character(value)
    ):
        return False
    parts = value[1:].split("/")
    return all(part and part not in {".", ".."} for part in parts)


def _raw_paths_are_unambiguous(
    request: object,
    canonical_path_info: str,
) -> bool:
    environ = _safe_getattr(request, "environ")
    if not isinstance(environ, Mapping):
        return False

    script_name = _safe_optional_getitem(environ, "SCRIPT_NAME")
    if script_name is _MISSING:
        script_name = ""
    if script_name is _FAILED or not _valid_script_name(script_name):
        return False
    external_path = f"{script_name}{canonical_path_info}"
    external_raw_paths = _valid_raw_forms(external_path)
    path_info_raw_paths = _valid_raw_forms(canonical_path_info)

    for key in ("RAW_URI", "REQUEST_URI"):
        raw_target = _safe_optional_getitem(environ, key)
        if raw_target is _MISSING:
            continue
        if raw_target is _FAILED or not isinstance(raw_target, str):
            return False
        raw_path = raw_target.partition("?")[0]
        if raw_path not in external_raw_paths:
            return False

    raw_path_info = _safe_optional_getitem(environ, "RAW_PATH_INFO")
    if raw_path_info is _MISSING:
        return True
    if raw_path_info is _FAILED or not isinstance(raw_path_info, str):
        return False
    return raw_path_info in path_info_raw_paths


def _valid_raw_forms(decoded_path: str) -> frozenset[str]:
    canonical = quote(
        decoded_path,
        safe=_RFC3986_PATH_SAFE,
        encoding="utf-8",
        errors="strict",
    )
    if decoded_path.isascii():
        return frozenset((decoded_path, canonical))
    return frozenset((canonical,))


def _classify_path(
    request: object,
) -> tuple[str, str, str, str, str] | None:
    path_info = _safe_getattr(request, "path_info")
    if not isinstance(path_info, str):
        _fail()

    path_parts = path_info.split("/")
    nonempty_parts = [part for part in path_parts if part]
    marker = path_parts[3] if len(path_parts) > 3 else None
    if marker not in {"+f", "+e"}:
        marker = nonempty_parts[2] if len(nonempty_parts) > 2 else None
    if marker not in {"+f", "+e"}:
        return None

    if len(path_parts) < 5 or path_parts[0] or path_parts[3] != marker:
        _fail()
    user = path_parts[1]
    index = path_parts[2]
    tail = "/".join(path_parts[4:])
    if not _valid_route_segment(user) or not _valid_route_segment(index):
        _fail()
    if not _valid_relpath_tail(tail):
        _fail()

    requested_relpath = f"{user}/{index}/{marker}/{tail}"
    canonical_path_info = f"/{requested_relpath}"
    if path_info != canonical_path_info:
        _fail()
    if not _raw_paths_are_unambiguous(request, canonical_path_info):
        _fail()

    artifact_tail = tail
    if artifact_tail.endswith(_METADATA_SUFFIX):
        artifact_tail = artifact_tail.removesuffix(_METADATA_SUFFIX)
        basename = artifact_tail.rsplit("/", 1)[-1]
        nested_metadata = artifact_tail.endswith(_METADATA_SUFFIX)
        if nested_metadata or not basename.endswith(".whl"):
            _fail()
    artifact_relpath = f"{user}/{index}/{marker}/{artifact_tail}"
    return user, index, marker, tail, artifact_relpath


def _get_xom(request: object) -> object:
    registry = _safe_getattr(request, "registry")
    xom = _safe_getitem(registry, "xom")
    if xom is _FAILED or xom is None:
        _fail()
    return xom


def _get_stage(xom: object, user: str, index: str) -> object:
    model = _safe_getattr(xom, "model")
    getstage = _safe_getattr(model, "getstage")
    stage = _safe_call(getstage, user, index)
    if stage is _FAILED or stage is None:
        _fail()
    stage_user = _safe_getattr(stage, "username")
    stage_index = _safe_getattr(stage, "index")
    if stage_user != user or stage_index != index:
        _fail()
    return stage


def _get_filestore(xom: object) -> object:
    filestore = _safe_getattr(xom, "filestore")
    if filestore is _FAILED or filestore is None:
        _fail()
    return filestore


def _crosscheck_routed_attributes(
    request: object,
    *,
    user: str,
    index: str,
    marker: str,
    tail: str,
) -> None:
    matched_route = _safe_optional_getattr(request, "matched_route")
    if matched_route is _FAILED:
        _fail()
    if matched_route is not _MISSING and matched_route is not None:
        expected_route = _F_ROUTE if marker == "+f" else _E_ROUTE
        if _safe_getattr(matched_route, "name") != expected_route:
            _fail()

    matchdict = _safe_optional_getattr(request, "matchdict")
    if matchdict is _FAILED:
        _fail()
    if matchdict is not _MISSING and matchdict is not None:
        if not isinstance(matchdict, Mapping):
            _fail()
        expected_match = {"user": user, "index": index, "relpath": tail}
        for key, expected in expected_match.items():
            if _safe_getitem(matchdict, key) != expected:
                _fail()

    context = _safe_optional_getattr(request, "context")
    if context is _FAILED:
        _fail()
    if context is not _MISSING and context is not None:
        context_stage = _safe_getattr(context, "stage")
        if context_stage is _FAILED or context_stage is None:
            _fail()
        context_user = _safe_getattr(context_stage, "username")
        context_index = _safe_getattr(context_stage, "index")
        if context_user != user or context_index != index:
            _fail()


def _project_exists_perstage(stage: object, project: str) -> object:
    method = _safe_getattr(stage, "has_project_perstage")
    project_exists = _safe_call(method, project)
    if project_exists is _FAILED:
        _fail()
    if project_exists is True or project_exists is False:
        return project_exists
    if isinstance(project_exists, Unknown):
        return project_exists
    _fail()


def _refresh_f_entry(
    filestore: object,
    stage: object,
    relpath: str,
) -> object | None:
    parsed = _safe_call(splitbasename, Path(relpath).name)
    if (
        parsed is _FAILED
        or not isinstance(parsed, tuple)
        or not parsed
        or not isinstance(parsed[0], str)
        or not parsed[0]
    ):
        _fail()
    project = parsed[0]

    project_exists = _project_exists_perstage(stage, project)
    refresh = project_exists is True
    if isinstance(project_exists, Unknown):
        no_project_list = _safe_getattr(stage, "no_project_list")
        if no_project_list is _FAILED or not isinstance(no_project_list, bool):
            _fail()
        refresh = no_project_list
    if not refresh:
        return None

    list_versions = _safe_getattr(stage, "list_versions_perstage")
    if _safe_call(list_versions, project) is _FAILED:
        _fail()
    project_exists = _project_exists_perstage(stage, project)
    if project_exists is not True:
        return None
    return _safe_call(_safe_getattr(filestore, "get_file_entry"), relpath)


def _get_entry(
    filestore: object,
    stage: object,
    marker: str,
    relpath: str,
) -> object:
    if marker == "+f":
        entry = _safe_call(_safe_getattr(filestore, "get_file_entry"), relpath)
        if entry is _FAILED:
            _fail()
        if entry is None:
            entry = _refresh_f_entry(filestore, stage, relpath)
    else:
        get_key = _safe_getattr(filestore, "get_key_from_relpath")
        key = _safe_call(get_key, relpath)
        if key is _FAILED or key is None:
            _fail()
        exists = _safe_call(_safe_getattr(key, "exists"))
        if exists is not True:
            _fail()
        get_entry = _safe_getattr(filestore, "get_file_entry_from_key")
        entry = _safe_call(get_entry, key)
    if entry is _FAILED or entry is None:
        _fail()
    return entry


def _entry_is_consistent(
    entry: object,
    relpath: str,
    user: str,
    index: str,
) -> bool:
    project = _safe_getattr(entry, "project")
    version = _safe_getattr(entry, "version")
    return (
        _safe_getattr(entry, "relpath") == relpath
        and _safe_getattr(entry, "user") == user
        and _safe_getattr(entry, "index") == index
        and isinstance(project, str)
        and bool(project)
        and isinstance(version, str)
        and bool(version)
    )


def _get_release_link(
    stage: object,
    entry: object,
    relpath: str,
) -> object | None:
    link = _safe_call(_safe_getattr(stage, "get_link_from_entrypath"), relpath)
    if link is _FAILED or link is None:
        _fail()
    relation = _safe_getattr(link, "rel")
    if not isinstance(relation, str):
        _fail()
    if relation != _RELEASE_RELATION:
        return None

    if (
        _safe_getattr(link, "relpath") != relpath
        or _safe_getattr(link, "project") != _safe_getattr(entry, "project")
        or _safe_getattr(link, "version") != _safe_getattr(entry, "version")
        or _safe_getattr(link, "for_entrypath") is not None
    ):
        _fail()
    return link


def _get_entry_sha256(entry: object) -> str:
    hashes = _safe_getattr(entry, "hashes")
    if not isinstance(hashes, Mapping):
        _fail()
    sha256 = _safe_getitem(hashes, "sha256")
    if sha256 is _FAILED:
        _fail()
    try:
        return validate_sha256(sha256)
    except InvalidSha256:
        pass
    _fail()


def resolve_release_sha256(request) -> str | None:
    """Resolve a protected devpi release request to its persisted SHA-256."""
    method = _safe_getattr(request, "method")
    if not isinstance(method, str) or method not in {"GET", "HEAD"}:
        return None

    path_identity = _classify_path(request)
    if path_identity is None:
        return None

    user, index, marker, tail, relpath = path_identity
    xom = _get_xom(request)
    stage = _get_stage(xom, user, index)
    _crosscheck_routed_attributes(
        request,
        user=user,
        index=index,
        marker=marker,
        tail=tail,
    )
    filestore = _get_filestore(xom)
    entry = _get_entry(filestore, stage, marker, relpath)
    consistent = _entry_is_consistent(entry, relpath, user, index)
    if not consistent:
        _fail()
    if _get_release_link(stage, entry, relpath) is None:
        return None
    return _get_entry_sha256(entry)
