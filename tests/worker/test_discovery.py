from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from devpi_guardian.worker.discovery import (
    DiscoveryCandidate,
    DiscoveryUnavailable,
    FileDiscoverySink,
    get_discovery_sink,
    set_discovery_sink,
)

SHA256 = "a" * 64


def candidate(**changes) -> DiscoveryCandidate:
    values = {
        "stage": "company/guardian",
        "project": "demo-package",
        "filename": "demo_package-1.0.0-py3-none-any.whl",
        "sha256": SHA256,
        "link_href": "/root/pypi/+f/aaa/demo.whl#sha256=" + SHA256,
    }
    values.update(changes)
    return DiscoveryCandidate(**values)


def test_file_sink_persists_metadata_once_and_returns_immediately(tmp_path) -> None:
    sink = FileDiscoverySink(tmp_path)
    item = candidate()

    assert sink.discover(item) is None
    assert sink.discover(item) is None

    [stored] = tuple((tmp_path / "pending").iterdir())
    assert json.loads(stored.read_text(encoding="utf-8")) == {
        "filename": item.filename,
        "link_href": item.link_href,
        "project": item.project,
        "sha256": item.sha256,
        "stage": item.stage,
    }
    assert len(tuple((tmp_path / "pending").iterdir())) == 1


def test_file_sink_keeps_distinct_release_mappings_for_the_same_sha256(tmp_path) -> None:
    sink = FileDiscoverySink(tmp_path)

    sink.discover(candidate())
    sink.discover(
        candidate(
            stage="other/guardian",
            link_href="/other/guardian/+f/aaa/demo.whl#sha256=" + SHA256,
        )
    )

    assert len(tuple((tmp_path / "pending").iterdir())) == 2


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("stage", ""),
        ("project", ""),
        ("filename", ""),
        ("link_href", ""),
        ("sha256", "A" * 64),
    ],
)
def test_candidate_rejects_unusable_metadata(field, value) -> None:
    with pytest.raises(ValueError):
        candidate(**{field: value})


def test_xom_accessor_returns_only_the_registered_sink(tmp_path) -> None:
    xom = SimpleNamespace()
    sink = FileDiscoverySink(tmp_path)

    with pytest.raises(DiscoveryUnavailable):
        get_discovery_sink(xom)

    set_discovery_sink(xom, sink)

    assert get_discovery_sink(xom) is sink


def test_file_sink_maps_storage_failure_to_discovery_unavailable(tmp_path) -> None:
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")

    with pytest.raises(DiscoveryUnavailable):
        FileDiscoverySink(blocked).discover(candidate())
