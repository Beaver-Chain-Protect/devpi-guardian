from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from typing import Any

from devpi_guardian.verdicts.errors import InvalidSha256
from devpi_guardian.verdicts.models import validate_sha256

_F_ROUTE = "/{user}/{index}/+f/{relpath:.*}"
_E_ROUTE = "/{user}/{index}/+e/{relpath:.*}"
_PROTECTED_ROUTES = {_F_ROUTE: "+f", _E_ROUTE: "+e"}
_METADATA_SUFFIX = ".metadata"
_RELEASE_RELATION = "releasefile"
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


def _raw_paths_are_unambiguous(request: object) -> bool:
    environ = _safe_getattr(request, "environ")
    if not isinstance(environ, Mapping):
        return False

    for key in ("RAW_URI", "REQUEST_URI", "RAW_PATH_INFO"):
        raw_target = _safe_optional_getitem(environ, key)
        if raw_target is _MISSING:
            continue
        if raw_target is _FAILED or not isinstance(raw_target, str):
            return False
        raw_path = raw_target.partition("?")[0]
        if "%" in raw_path or "#" in raw_path:
            return False
    return True


def _extract_relpath(request: object, marker: str) -> tuple[str, str, str]:
    matchdict = _safe_getattr(request, "matchdict")
    if not isinstance(matchdict, Mapping):
        _fail()
    user = _safe_getitem(matchdict, "user")
    index = _safe_getitem(matchdict, "index")
    tail = _safe_getitem(matchdict, "relpath")
    if not _valid_route_segment(user) or not _valid_route_segment(index):
        _fail()
    if not _valid_relpath_tail(tail):
        _fail()

    requested_relpath = f"{user}/{index}/{marker}/{tail}"
    path_info = _safe_getattr(request, "path_info")
    if path_info != f"/{requested_relpath}":
        _fail()
    if not _raw_paths_are_unambiguous(request):
        _fail()

    artifact_tail = tail
    if artifact_tail.endswith(_METADATA_SUFFIX):
        artifact_tail = artifact_tail.removesuffix(_METADATA_SUFFIX)
        basename = artifact_tail.rsplit("/", 1)[-1]
        nested_metadata = artifact_tail.endswith(_METADATA_SUFFIX)
        if nested_metadata or not basename.endswith(".whl"):
            _fail()
    artifact_relpath = f"{user}/{index}/{marker}/{artifact_tail}"
    return user, index, artifact_relpath


def _get_stage(request: object, user: str, index: str) -> object:
    context = _safe_getattr(request, "context")
    stage = _safe_getattr(context, "stage")
    if stage is _FAILED or stage is None:
        _fail()
    stage_user = _safe_getattr(stage, "username")
    stage_index = _safe_getattr(stage, "index")
    if stage_user != user or stage_index != index:
        _fail()
    return stage


def _get_filestore(request: object) -> object:
    registry = _safe_getattr(request, "registry")
    xom = _safe_getitem(registry, "xom")
    filestore = _safe_getattr(xom, "filestore")
    if filestore is _FAILED or filestore is None:
        _fail()
    return filestore


def _get_entry(filestore: object, marker: str, relpath: str) -> object:
    if marker == "+f":
        entry = _safe_call(_safe_getattr(filestore, "get_file_entry"), relpath)
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

    route = _safe_getattr(request, "matched_route")
    route_name = _safe_getattr(route, "name")
    if not isinstance(route_name, str):
        return None
    marker = _PROTECTED_ROUTES.get(route_name)
    if marker is None:
        return None

    user, index, relpath = _extract_relpath(request, marker)
    stage = _get_stage(request, user, index)
    filestore = _get_filestore(request)
    entry = _get_entry(filestore, marker, relpath)
    consistent = _entry_is_consistent(entry, relpath, user, index)
    if not consistent:
        _fail()
    if _get_release_link(stage, entry, relpath) is None:
        return None
    return _get_entry_sha256(entry)
