from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from types import MappingProxyType, SimpleNamespace

import pytest

from devpi_guardian.legacy_inventory import (
    ExistingArtifactCandidate,
    find_existing_artifact_candidate,
)


class FakeRelpathInfo:
    def __init__(self, keyname: str, relpath: str, value: object) -> None:
        self.keyname = keyname
        self.relpath = relpath
        self.value = value


class ReadonlySequence(Sequence[object]):
    def __init__(self, values: tuple[object, ...]) -> None:
        self._values = values

    def __getitem__(self, index: int | slice) -> object:
        return self._values[index]

    def __len__(self) -> int:
        return len(self._values)


class FakeKey:
    def __init__(self, keyname: str) -> None:
        self.keyname = keyname


class FakeTransaction:
    at_serial = 73

    def __init__(
        self,
        rows: Mapping[str, Sequence[object]],
        *,
        error: Exception | None = None,
    ) -> None:
        self.rows = rows
        self.error = error
        self.iter_calls: list[tuple[tuple[str, ...], int]] = []

    def iter_relpaths_at(
        self,
        keys: Sequence[FakeKey],
        serial: int,
    ) -> Iterator[object]:
        names = tuple(key.keyname for key in keys)
        self.iter_calls.append((names, serial))
        if self.error is not None:
            raise self.error
        for name in names:
            yield from self.rows.get(name, ())


class FakeReadTransaction:
    def __init__(self, transaction: FakeTransaction, owner: FakeKeyFS) -> None:
        self.transaction = transaction
        self.owner = owner

    def __enter__(self) -> FakeTransaction:
        self.owner.read_transactions += 1
        return self.transaction

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        if self.owner.context_error is not None:
            raise self.owner.context_error
        return False


class FakeKeyFS:
    def __init__(
        self,
        rows: Mapping[str, Sequence[object]],
        *,
        key_error: Exception | None = None,
        iterator_error: Exception | None = None,
        context_error: Exception | None = None,
    ) -> None:
        self.rows = rows
        self.key_error = key_error
        self.context_error = context_error
        self.read_transactions = 0
        self.requested_keys: list[str] = []
        self.transaction = FakeTransaction(rows, error=iterator_error)

    def get_key(self, keyname: str) -> FakeKey:
        self.requested_keys.append(keyname)
        if self.key_error is not None:
            raise self.key_error
        return FakeKey(keyname)

    def read_transaction(self) -> FakeReadTransaction:
        return FakeReadTransaction(self.transaction, self)


class FakeXom:
    def __init__(
        self,
        rows: Mapping[str, Sequence[object]],
        **kwargs: object,
    ) -> None:
        self.keyfs = FakeKeyFS(rows, **kwargs)
        self.model = _ForbiddenAttribute()
        self.filestore = _ForbiddenAttribute()
        self.http = _ForbiddenAttribute()


class _ForbiddenAttribute:
    def __getattr__(self, name: str) -> object:
        raise AssertionError(f"forbidden access: {name}")


def info(keyname: str, relpath: str, value: object) -> FakeRelpathInfo:
    return FakeRelpathInfo(keyname, relpath, value)


def test_empty_snapshot_has_no_candidate() -> None:
    xom = FakeXom({})

    result = find_existing_artifact_candidate(xom)

    assert result is None
    assert xom.keyfs.read_transactions == 1
    assert xom.keyfs.requested_keys == [
        "PROJSIMPLELINKS",
        "PROJVERSION",
        "STAGEFILE",
        "PYPIFILE_NOMD5",
    ]
    assert xom.keyfs.transaction.iter_calls == [
        (("PROJSIMPLELINKS", "PROJVERSION"), 73),
        (("STAGEFILE", "PYPIFILE_NOMD5"), 73),
    ]


def test_private_release_elink_is_candidate() -> None:
    xom = FakeXom(
        {
            "PROJVERSION": [
                info(
                    "PROJVERSION",
                    "root/dev/demo/1.0/.config",
                    {
                        "+elinks": (
                            {
                                "rel": "releasefile",
                                "entrypath": "root/dev/+f/a.whl",
                            },
                        )
                    },
                )
            ]
        }
    )

    result = find_existing_artifact_candidate(xom)

    assert result == "release_link"
    assert type(result) is str
    assert result is ExistingArtifactCandidate.RELEASE_LINK.value
    assert xom.keyfs.transaction.iter_calls == [
        (("PROJSIMPLELINKS", "PROJVERSION"), 73),
    ]


def test_nonempty_persisted_simple_links_are_candidate() -> None:
    filename = "demo-1.0.whl"
    entrypath = "root/pypi/+e/demo-1.0.whl"
    links = ReadonlySequence(((filename, entrypath),))
    simple = MappingProxyType(
        {"links": links},
    )
    simple_info = info("PROJSIMPLELINKS", "root/pypi/demo", simple)
    xom = FakeXom({"PROJSIMPLELINKS": [simple_info]})

    assert find_existing_artifact_candidate(xom) == "release_link"


def test_empty_persisted_mirror_mapping_is_well_formed() -> None:
    xom = FakeXom(
        {"PROJSIMPLELINKS": [info("PROJSIMPLELINKS", "root/pypi/demo", {})]},
    )

    assert find_existing_artifact_candidate(xom) is None


@pytest.mark.parametrize(
    "filename",
    ["", "\x00demo.whl", "\ud800", "a" * 4097],
)
def test_malformed_simple_link_filename_is_unclassified(filename: str) -> None:
    simple = {"links": ((filename, "root/pypi/+e/demo-1.0.whl"),)}
    simple_info = info("PROJSIMPLELINKS", "root/pypi/demo", simple)
    xom = FakeXom({"PROJSIMPLELINKS": [simple_info]})

    assert find_existing_artifact_candidate(xom) == "unclassified"


def test_cached_mirror_file_is_candidate() -> None:
    xom = FakeXom(
        {
            "PYPIFILE_NOMD5": [
                info(
                    "PYPIFILE_NOMD5",
                    "root/pypi/+f/aa/demo.whl",
                    {"size": 12},
                )
            ]
        },
    )

    assert find_existing_artifact_candidate(xom) == "file_entry"


@pytest.mark.parametrize("keyname", ["STAGEFILE", "PYPIFILE_NOMD5"])
def test_tombstones_are_ignored(keyname: str) -> None:
    xom = FakeXom({keyname: [info(keyname, "root/pypi/+f/aa/demo.whl", None)]})

    assert find_existing_artifact_candidate(xom) is None


@pytest.mark.parametrize("relation", ["doczip", "toxresult"])
def test_known_non_artifact_stage_files_are_ignored(relation: str) -> None:
    entrypath = f"root/dev/+f/aa/demo.whl.{relation}"
    xom = FakeXom(
        {
            "PROJVERSION": [
                info(
                    "PROJVERSION",
                    "root/dev/demo/1.0/.config",
                    {"+elinks": ({"rel": relation, "entrypath": entrypath},)},
                )
            ],
            "STAGEFILE": [info("STAGEFILE", entrypath, {"size": 4})],
        }
    )

    assert find_existing_artifact_candidate(xom) is None


def test_unclassified_stage_file_is_fail_closed_candidate() -> None:
    stage_info = info("STAGEFILE", "root/dev/+f/aa/demo.whl", {"size": 1})
    xom = FakeXom({"STAGEFILE": [stage_info]})

    result = find_existing_artifact_candidate(xom)

    assert result == "file_entry"
    assert type(result) is str


def test_unknown_relation_is_unclassified_even_with_live_file() -> None:
    entrypath = "root/dev/+f/aa/demo.whl"
    relation_item = {"rel": "future-relation", "entrypath": entrypath}
    version_value = {"+elinks": (relation_item,)}
    xom = FakeXom(
        {
            "PROJVERSION": [
                info(
                    "PROJVERSION",
                    "root/dev/demo/1.0/.config",
                    version_value,
                )
            ],
            "STAGEFILE": [info("STAGEFILE", entrypath, {"size": 1})],
        }
    )

    assert find_existing_artifact_candidate(xom) == "unclassified"


def test_unknown_relation_without_live_file_is_unclassified() -> None:
    xom = FakeXom(
        {
            "PROJVERSION": [
                info(
                    "PROJVERSION",
                    "root/dev/demo/1.0/.config",
                    {
                        "+elinks": (
                            {
                                "rel": "future-relation",
                                "entrypath": "root/dev/+f/aa/demo.whl",
                            },
                        )
                    },
                )
            ]
        }
    )

    assert find_existing_artifact_candidate(xom) == "unclassified"


@pytest.mark.parametrize(
    "relation",
    ["", "\x00future", "\ud800", "a" * 4097],
)
def test_unsafe_unknown_relation_is_unclassified(relation: str) -> None:
    xom = FakeXom(
        {
            "PROJVERSION": [
                info(
                    "PROJVERSION",
                    "root/dev/demo/1.0/.config",
                    {
                        "+elinks": (
                            {
                                "rel": relation,
                                "entrypath": "root/dev/+f/aa/demo.whl",
                            },
                        )
                    },
                )
            ]
        }
    )

    assert find_existing_artifact_candidate(xom) == "unclassified"


def test_version_without_elinks_is_well_formed() -> None:
    xom = FakeXom(
        {
            "PROJVERSION": [
                info(
                    "PROJVERSION",
                    "root/dev/demo/1.0/.config",
                    {"serial": 1},
                )
            ]
        },
    )

    assert find_existing_artifact_candidate(xom) is None


@pytest.mark.parametrize(
    "rows",
    [
        {
            "PROJSIMPLELINKS": [
                info(
                    "PROJSIMPLELINKS",
                    "root/pypi/demo",
                    {"links": None},
                )
            ],
        },
        {
            "PROJSIMPLELINKS": [
                info(
                    "PROJSIMPLELINKS",
                    "root/pypi/demo",
                    {"links": (1,)},
                )
            ],
        },
        {
            "PROJVERSION": [
                info(
                    "PROJVERSION",
                    "root/dev/demo/1.0/.config",
                    {"+elinks": ("bad",)},
                )
            ]
        },
        {
            "PROJVERSION": [
                info(
                    "PROJVERSION",
                    "root/dev/demo/1.0/.config",
                    {"+elinks": ({"rel": "releasefile"},)},
                )
            ]
        },
    ],
)
def test_malformed_relation_data_is_unclassified(
    rows: Mapping[str, Sequence[object]],
) -> None:
    result = find_existing_artifact_candidate(FakeXom(rows))

    assert result == "unclassified"
    assert type(result) is str


@pytest.mark.parametrize(
    "entrypath",
    [
        "/root/dev/+f/a.whl",
        "root//dev/a.whl",
        "root/./dev/a.whl",
        "root/../dev/a.whl",
        "root\\dev/a.whl",
        "root/\x00a.whl",
    ],
)
def test_unsafe_paths_are_unclassified(entrypath: str) -> None:
    xom = FakeXom(
        {
            "PROJVERSION": [
                info(
                    "PROJVERSION",
                    "root/dev/demo/1.0/.config",
                    {
                        "+elinks": (
                            {
                                "rel": "releasefile",
                                "entrypath": entrypath,
                            },
                        )
                    },
                )
            ]
        }
    )

    assert find_existing_artifact_candidate(xom) == "unclassified"


def test_duplicate_contradictory_relation_is_unclassified() -> None:
    entrypath = "root/dev/+f/aa/demo.whl"
    xom = FakeXom(
        {
            "PROJVERSION": [
                info(
                    "PROJVERSION",
                    "root/dev/demo/1.0/.config",
                    {
                        "+elinks": (
                            {"rel": "doczip", "entrypath": entrypath},
                            {"rel": "releasefile", "entrypath": entrypath},
                        )
                    },
                )
            ]
        }
    )

    assert find_existing_artifact_candidate(xom) == "unclassified"


@pytest.mark.parametrize("error_kind", ["key", "iterator", "context"])
def test_keyfs_failures_are_unclassified(error_kind: str) -> None:
    kwargs = {
        "key_error": RuntimeError("secret filename"),
        "iterator_error": RuntimeError("secret digest"),
        "context_error": RuntimeError("secret URL"),
    }
    xom = FakeXom({}, **{f"{error_kind}_error": kwargs[f"{error_kind}_error"]})

    assert find_existing_artifact_candidate(xom) == "unclassified"


def test_one_snapshot_and_no_model_or_network_access() -> None:
    stage_info = info(
        "STAGEFILE",
        "root/dev/+f/a.whl",
        SimpleNamespace(size=1),
    )
    xom = FakeXom({"STAGEFILE": [stage_info]})

    assert find_existing_artifact_candidate(xom) == "file_entry"
    assert xom.keyfs.read_transactions == 1
