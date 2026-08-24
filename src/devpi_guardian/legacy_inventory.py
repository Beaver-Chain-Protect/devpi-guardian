"""Read-only inventory of Artifact-like data already persisted by devpi.

This module deliberately speaks only to the small KeyFS snapshot interface
needed for activation.  In particular, it does not resolve entries through
the devpi model or attempt to read bytes from a file store.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Any


class ExistingArtifactCandidate(StrEnum):
    FILE_ENTRY = "file_entry"
    RELEASE_LINK = "release_link"
    UNCLASSIFIED = "unclassified"


_PROJSIMPLELINKS = "PROJSIMPLELINKS"
_PROJVERSION = "PROJVERSION"
_STAGEFILE = "STAGEFILE"
_PYPIFILE_NOMD5 = "PYPIFILE_NOMD5"
_TOXRESULT = "toxresult"
_DOCZIP = "doczip"
_RELEASEFILE = "releasefile"
_MISSING = object()


class _MalformedInventory(Exception):
    """Internal bounded failure; no persisted value is attached."""


def _candidate(candidate: ExistingArtifactCandidate) -> str:
    # StrEnum.value is the public boundary: callers must never receive the
    # enum.
    return candidate.value


def _safe_relpath(value: object) -> bool:
    """Return whether *value* is a safe, persisted relative path."""

    if type(value) is not str:
        return False
    if not value or len(value) > 4096:
        return False
    try:
        value.encode("utf-8")
    except Exception:
        return False
    if "\x00" in value or "\\" in value or value.startswith("/"):
        return False
    return all(segment not in {"", ".", ".."} for segment in value.split("/"))


def _safe_scalar(value: object) -> bool:
    invalid_type = type(value) is not str
    invalid_shape = not value or len(value) > 4096 or "\x00" in value
    if invalid_type or invalid_shape:
        return False
    try:
        value.encode("utf-8")
    except Exception:
        return False
    return True


def _as_mapping(value: object) -> Mapping[Any, Any]:
    if not isinstance(value, Mapping):
        raise _MalformedInventory
    return value


def _mapping_value(mapping: Mapping[Any, Any], key: str) -> object:
    try:
        return mapping[key]
    except KeyError:
        return _MISSING
    except Exception as exc:
        raise _MalformedInventory from exc


def _as_sequence(value: object) -> list[object]:
    # ``str`` subclasses are rejected too; do not invoke their overridden
    # methods.
    is_string = isinstance(value, (str, bytes, bytearray))
    if is_string or not isinstance(value, Sequence):
        raise _MalformedInventory
    try:
        return list(value)
    except Exception as exc:
        raise _MalformedInventory from exc


def _info_fields(info: object) -> tuple[str, str, object]:
    try:
        keyname = info.keyname
        relpath = info.relpath
        value = info.value
    except Exception as exc:
        raise _MalformedInventory from exc
    if type(keyname) is not str or not _safe_relpath(relpath):
        raise _MalformedInventory
    return keyname, relpath, value


def _simple_link_path(item: object) -> str:
    """Extract the entrypath from one persisted simple-link item."""

    if isinstance(item, Mapping):
        path = _mapping_value(item, "entrypath")
        if path is _MISSING:
            # Some devpi versions use href for this compact relation.  It is
            # still a persisted path at this boundary, never a URL to be
            # fetched.
            path = _mapping_value(item, "href")
    else:
        values = _as_sequence(item)
        if len(values) != 2 or not _safe_scalar(values[0]):
            raise _MalformedInventory
        path = values[1]
    if not _safe_relpath(path):
        raise _MalformedInventory
    return path


def _check_simple_value(value: object) -> bool:
    mapping = _as_mapping(value)
    try:
        if len(mapping) == 0:
            return False
    except Exception as exc:
        raise _MalformedInventory from exc
    links = _mapping_value(mapping, "links")
    if links is _MISSING:
        raise _MalformedInventory
    items = _as_sequence(links)
    for item in items:
        _simple_link_path(item)
    return bool(items)


def _check_version_value(
    value: object,
    known_non_artifacts: set[str],
    relation_paths: dict[str, set[str]],
) -> bool:
    mapping = _as_mapping(value)
    elinks = _mapping_value(mapping, "+elinks")
    if elinks is _MISSING:
        return False
    items = _as_sequence(elinks)
    has_release = False
    for item in items:
        item_mapping = _as_mapping(item)
        relation = _mapping_value(item_mapping, "rel")
        entrypath = _mapping_value(item_mapping, "entrypath")
        if not _safe_scalar(relation) or not _safe_relpath(entrypath):
            raise _MalformedInventory
        relations = relation_paths.setdefault(entrypath, set())
        relations.add(relation)
        # A path cannot simultaneously be confidently non-Artifact and another
        # relation.  Fail closed before considering any release relation.
        if len(relations) > 1:
            raise _MalformedInventory
        if relation == _RELEASEFILE:
            has_release = True
        elif relation in {_TOXRESULT, _DOCZIP}:
            known_non_artifacts.add(entrypath)
        else:
            raise _MalformedInventory
    return has_release


def _iter_infos(tx: object, keys: Sequence[object], serial: object):
    try:
        iterator = tx.iter_relpaths_at(keys, serial)
        yield from iterator
    except Exception as exc:
        raise _MalformedInventory from exc


def _scan_snapshot(
    tx: object,
    key_map: Mapping[str, object],
    serial: object,
) -> str | None:
    known_non_artifacts: set[str] = set()
    relation_paths: dict[str, set[str]] = {}

    relation_infos = _iter_infos(
        tx,
        [key_map[_PROJSIMPLELINKS], key_map[_PROJVERSION]],
        serial,
    )
    for info in relation_infos:
        keyname, _relpath, value = _info_fields(info)
        if keyname not in {_PROJSIMPLELINKS, _PROJVERSION}:
            raise _MalformedInventory
        if value is None:
            continue
        if keyname == _PROJSIMPLELINKS:
            if _check_simple_value(value):
                return _candidate(ExistingArtifactCandidate.RELEASE_LINK)
        elif _check_version_value(value, known_non_artifacts, relation_paths):
            return _candidate(ExistingArtifactCandidate.RELEASE_LINK)

    file_infos = _iter_infos(
        tx,
        [key_map[_STAGEFILE], key_map[_PYPIFILE_NOMD5]],
        serial,
    )
    file_candidate = False
    for info in file_infos:
        keyname, relpath, value = _info_fields(info)
        if keyname not in {_STAGEFILE, _PYPIFILE_NOMD5}:
            raise _MalformedInventory
        if value is None:
            continue
        if keyname == _PYPIFILE_NOMD5 or relpath not in known_non_artifacts:
            file_candidate = True
    if file_candidate:
        return _candidate(ExistingArtifactCandidate.FILE_ENTRY)
    return None


def find_existing_artifact_candidate(xom: object) -> str | None:
    """Return a bounded category for the first live Artifact candidate.

    All KeyFS access is contained in one read transaction.  Any malformed
    persisted shape or KeyFS failure returns ``"unclassified"`` so activation
    remains safe.
    """

    try:
        keyfs = xom.keyfs
        with keyfs.read_transaction() as tx:
            key_map = {
                name: keyfs.get_key(name)
                for name in (
                    _PROJSIMPLELINKS,
                    _PROJVERSION,
                    _STAGEFILE,
                    _PYPIFILE_NOMD5,
                )
            }
            serial = tx.at_serial
            return _scan_snapshot(tx, key_map, serial)
    except Exception:
        return _candidate(ExistingArtifactCandidate.UNCLASSIFIED)
