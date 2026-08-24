"""F6's ReleaseLookup against a real F4 verdict store.

The database is built with F4's own `ConnectionFactory` and `migrate`, and
seeded the way `tests/verdicts/test_reader.py` seeds it, so these tests
exercise the real `list_allowed_releases` query rather than a stand-in.
"""

from __future__ import annotations

import pytest

from devpi_guardian.baseline import ReleaseRecord, select_baseline
from devpi_guardian.baseline.diff import compare_release_to_baseline
from devpi_guardian.baseline.release_lookup import (
    AllowedReleaseSource,
    UnknownArtifactOrigin,
    VerdictReaderReleaseLookup,
)
from devpi_guardian.verdicts.db import ConnectionFactory
from devpi_guardian.verdicts.errors import StoreUnavailable
from devpi_guardian.verdicts.interfaces import VerdictReader
from devpi_guardian.verdicts.models import AllowedRelease, ArtifactState, Decision, ReleaseArtifact
from devpi_guardian.verdicts.reader import SQLiteVerdictReader

from .fakes import FakeArtifactBytesSource
from .store_seed import (
    NOW,
    build_store,
    seed_allowed,
    seed_artifact,
    seed_release,
)

SHA_OLD = "a" * 64
SHA_MID = "b" * 64
SHA_NEW = "c" * 64
SHA_REVIEW = "d" * 64
SHA_SDIST = "e" * 64


def build_lookup(factory) -> VerdictReaderReleaseLookup:
    return VerdictReaderReleaseLookup(SQLiteVerdictReader(factory, now=lambda: NOW))


# --- protocol conformance -------------------------------------------------


def test_the_real_reader_satisfies_the_adapter_protocol(tmp_path):
    reader = SQLiteVerdictReader(build_store(tmp_path), now=lambda: NOW)
    assert isinstance(reader, AllowedReleaseSource)


def test_the_public_verdict_reader_interface_covers_what_the_adapter_needs():
    # The F4 README points F6 consumers at the registry-provided VerdictReader,
    # so anything satisfying that interface must satisfy this adapter too.
    assert "list_allowed_releases" in VerdictReader.__protocol_attrs__
    assert "get_artifact_releases" in VerdictReader.__protocol_attrs__


def test_the_preexisting_six_field_allowed_release_constructor_remains_valid():
    release = AllowedRelease(
        "root/dev",
        "demo-package",
        "1.0.0",
        "demo_package-1.0.0-py3-none-any.whl",
        SHA_OLD,
        "https://devpi.example/demo.whl",
    )

    assert release.sha256 == SHA_OLD


def test_missing_matching_release_mapping_fails_closed_for_expected_size():
    allowed = AllowedRelease(
        "root/dev",
        "demo-package",
        "1.0.0",
        "demo_package-1.0.0-py3-none-any.whl",
        SHA_OLD,
        "https://devpi.example/demo.whl",
    )

    class Reader:
        def list_allowed_releases(self, project):
            return (allowed,)

        def get_artifact_releases(self, sha256):
            return ()

    with pytest.raises(UnknownArtifactOrigin):
        VerdictReaderReleaseLookup(Reader()).allowed_releases("demo-package")


def test_disagreeing_matching_release_sizes_fail_closed():
    allowed = AllowedRelease(
        "root/dev",
        "demo-package",
        "1.0.0",
        "demo_package-1.0.0-py3-none-any.whl",
        SHA_OLD,
        "https://devpi.example/demo.whl",
    )

    def mapping(size_bytes):
        return ReleaseArtifact(
            stage=allowed.stage,
            project=allowed.project,
            version=allowed.version,
            filename=allowed.filename,
            sha256=allowed.sha256,
            origin_url=allowed.origin_url,
            size_bytes=size_bytes,
        )

    class Reader:
        def list_allowed_releases(self, project):
            return (allowed,)

        def get_artifact_releases(self, sha256):
            return (mapping(1), mapping(2))

    with pytest.raises(UnknownArtifactOrigin):
        VerdictReaderReleaseLookup(Reader()).allowed_releases("demo-package")


def test_matching_release_size_lookup_is_cached_per_digest():
    allowed = AllowedRelease(
        "root/dev",
        "demo-package",
        "1.0.0",
        "demo_package-1.0.0-py3-none-any.whl",
        SHA_OLD,
        "https://devpi.example/demo.whl",
    )
    mapping = ReleaseArtifact(
        stage=allowed.stage,
        project=allowed.project,
        version=allowed.version,
        filename=allowed.filename,
        sha256=allowed.sha256,
        origin_url=allowed.origin_url,
        size_bytes=1,
    )

    class Reader:
        calls = 0

        def list_allowed_releases(self, project):
            return (allowed, allowed)

        def get_artifact_releases(self, sha256):
            self.calls += 1
            return (mapping,)

    reader = Reader()
    assert len(VerdictReaderReleaseLookup(reader).allowed_releases("demo-package")) == 1
    assert reader.calls == 1


def test_any_object_with_list_allowed_releases_is_accepted():
    class MinimalReader:
        def list_allowed_releases(self, project):
            return ()

        def get_artifact_releases(self, sha256):
            return ()

    assert isinstance(MinimalReader(), AllowedReleaseSource)
    assert VerdictReaderReleaseLookup(MinimalReader()).allowed_releases("demo") == []


def test_the_adapter_satisfies_f6_release_lookup(tmp_path):
    from devpi_guardian.baseline import ReleaseLookup

    assert isinstance(build_lookup(build_store(tmp_path)), ReleaseLookup)


# --- conversion -----------------------------------------------------------


def test_allowed_releases_converts_to_f6_release_records(tmp_path):
    factory = build_store(tmp_path)
    seed_allowed(factory, SHA_OLD, version="1.0.0", filename="demo_package-1.0.0-py3-none-any.whl")

    records = build_lookup(factory).allowed_releases("demo-package")
    assert records == [
        ReleaseRecord(
            project="demo-package",
            version="1.0.0",
            filename="demo_package-1.0.0-py3-none-any.whl",
            sha256=SHA_OLD,
            size_bytes=1,
        )
    ]


def test_the_project_name_is_normalized_by_the_reader(tmp_path):
    factory = build_store(tmp_path)
    seed_allowed(factory, SHA_OLD, version="1.0.0", filename="demo_package-1.0.0-py3-none-any.whl")

    lookup = build_lookup(factory)
    assert lookup.allowed_releases("Demo_Package") == lookup.allowed_releases("demo-package")


def test_a_project_with_no_approved_release_returns_nothing(tmp_path):
    assert build_lookup(build_store(tmp_path)).allowed_releases("demo-package") == []


def test_only_allowed_artifacts_are_returned(tmp_path):
    factory = build_store(tmp_path)
    seed_allowed(factory, SHA_OLD, version="1.0.0", filename="demo_package-1.0.0-py3-none-any.whl")
    seed_artifact(
        factory, SHA_REVIEW, ArtifactState.REVIEW, automated=(Decision.REVIEW, "policy-1")
    )
    seed_release(
        factory,
        SHA_REVIEW,
        version="1.5.0",
        filename="demo_package-1.5.0-py3-none-any.whl",
    )

    records = build_lookup(factory).allowed_releases("demo-package")
    assert [record.sha256 for record in records] == [SHA_OLD]


def test_the_same_artifact_in_two_stages_is_folded_into_one_record(tmp_path):
    factory = build_store(tmp_path)
    seed_artifact(factory, SHA_OLD, ArtifactState.ALLOW, automated=(Decision.ALLOW, "policy-1"))
    for stage in ("root/dev", "root/prod"):
        seed_release(
            factory,
            SHA_OLD,
            stage=stage,
            version="1.0.0",
            filename="demo_package-1.0.0-py3-none-any.whl",
        )

    records = build_lookup(factory).allowed_releases("demo-package")
    assert len(records) == 1


# --- origin URL resolution ------------------------------------------------


def test_the_origin_url_of_a_returned_release_is_resolvable(tmp_path):
    factory = build_store(tmp_path)
    seed_allowed(
        factory,
        SHA_OLD,
        version="1.0.0",
        filename="demo_package-1.0.0-py3-none-any.whl",
        origin_url=(
            f"https://devpi.example/root/dev/+f/{SHA_OLD[:3]}"
            f"/{SHA_OLD[3:16]}/demo_package-1.0.0-py3-none-any.whl"
        ),
    )

    lookup = build_lookup(factory)
    lookup.allowed_releases("demo-package")
    assert lookup.origin_url(SHA_OLD) == (
        f"https://devpi.example/root/dev/+f/{SHA_OLD[:3]}"
        f"/{SHA_OLD[3:16]}/demo_package-1.0.0-py3-none-any.whl"
    )
    assert lookup.expected_size(SHA_OLD) == 1


def test_an_unseen_digest_has_no_origin_url(tmp_path):
    lookup = build_lookup(build_store(tmp_path))
    with pytest.raises(UnknownArtifactOrigin):
        lookup.origin_url(SHA_NEW)
    with pytest.raises(UnknownArtifactOrigin):
        lookup.expected_size(SHA_NEW)


def test_the_adapter_satisfies_the_origin_url_resolver_protocol(tmp_path):
    from devpi_guardian.baseline.artifact_source import OriginUrlResolver

    assert isinstance(build_lookup(build_store(tmp_path)), OriginUrlResolver)


# --- store failures -------------------------------------------------------


def test_a_broken_store_raises_instead_of_looking_like_a_first_release(tmp_path):
    not_a_database = tmp_path / "guardian.db"
    not_a_database.write_bytes(b"this is not a SQLite database" * 10)
    lookup = build_lookup(ConnectionFactory(not_a_database))

    with pytest.raises(StoreUnavailable):
        lookup.allowed_releases("demo-package")


def test_a_broken_store_becomes_an_analyzer_error_not_a_skipped_diff(tmp_path):
    not_a_database = tmp_path / "guardian.db"
    not_a_database.write_bytes(b"this is not a SQLite database" * 10)
    target = ReleaseRecord(
        project="demo-package",
        version="2.0.0",
        filename="demo_package-2.0.0-py3-none-any.whl",
        sha256=SHA_NEW,
        size_bytes=0,
    )

    result = compare_release_to_baseline(
        target,
        tmp_path / "demo_package-2.0.0-py3-none-any.whl",
        lookup=build_lookup(ConnectionFactory(not_a_database)),
        bytes_source=FakeArtifactBytesSource(tmp_path / "store"),
    )
    assert result.has_baseline is False
    assert result.diff is None
    assert [(finding.rule, origin) for finding, origin in result.findings] == [
        ("analyzer_error", "diff_artifact")
    ]
    assert "StoreUnavailable" in result.findings[0][0].snippet


# --- driving F6's priority chain from real data ---------------------------


def test_select_baseline_picks_the_newest_allowed_release_from_the_store(tmp_path):
    factory = build_store(tmp_path)
    seed_allowed(factory, SHA_OLD, version="1.0.0", filename="demo_package-1.0.0-py3-none-any.whl")
    seed_allowed(factory, SHA_MID, version="1.9.0", filename="demo_package-1.9.0-py3-none-any.whl")
    seed_artifact(
        factory, SHA_REVIEW, ArtifactState.REVIEW, automated=(Decision.REVIEW, "policy-1")
    )
    seed_release(
        factory,
        SHA_REVIEW,
        version="1.9.5",
        filename="demo_package-1.9.5-py3-none-any.whl",
    )

    target = ReleaseRecord(
        project="demo-package",
        version="2.0.0",
        filename="demo_package-2.0.0-py3-none-any.whl",
        sha256=SHA_NEW,
        size_bytes=0,
    )
    selection = select_baseline(target, build_lookup(factory))
    assert selection is not None
    assert selection.tier == "same_tag"
    # 1.9.5 is newer but only REVIEW, so it is never a baseline.
    assert selection.release.sha256 == SHA_MID


def test_the_sdist_tier_is_reachable_from_real_store_data(tmp_path):
    factory = build_store(tmp_path)
    seed_allowed(factory, SHA_SDIST, version="1.0.0", filename="demo_package-1.0.0.tar.gz")

    target = ReleaseRecord(
        project="demo-package",
        version="2.0.0",
        filename="demo_package-2.0.0-cp311-cp311-manylinux_2_17_x86_64.whl",
        sha256=SHA_NEW,
        size_bytes=0,
    )
    selection = select_baseline(target, build_lookup(factory))
    assert selection is not None
    assert selection.tier == "sdist"
    assert selection.release.filename == "demo_package-1.0.0.tar.gz"
