"""F6 baseline selection: filename classification and the priority chain."""

from __future__ import annotations

import logging

import pytest
from packaging.version import Version

from devpi_guardian.baseline import (
    ArtifactBytesSource,
    BaselineSelection,
    ReleaseLookup,
    ReleaseRecord,
    artifact_kind,
    canonical_project_name,
    eligible_candidates,
    parse_wheel_tag,
    select_baseline,
)

from .fakes import (
    FakeArtifactBytesSource,
    FakeReleaseLookup,
    digest,
    release,
)

PURE = "acme-2.0.0-py3-none-any.whl"
PLATFORM = "acme-2.0.0-cp311-cp311-manylinux_2_17_x86_64.whl"
SDIST = "acme-2.0.0.tar.gz"


def choose(target: ReleaseRecord, *candidates: ReleaseRecord) -> BaselineSelection | None:
    return select_baseline(target, FakeReleaseLookup(candidates))


# --- protocol conformance -------------------------------------------------


def test_fakes_satisfy_the_injected_protocols(tmp_path):
    assert isinstance(FakeReleaseLookup(), ReleaseLookup)
    assert isinstance(FakeArtifactBytesSource(tmp_path), ArtifactBytesSource)


def test_artifact_bytes_source_round_trip(tmp_path):
    source = FakeArtifactBytesSource(tmp_path)
    sha256 = digest("payload")
    source.add(sha256, b"payload", filename=SDIST)
    assert source.open(sha256).read_bytes() == b"payload"
    with pytest.raises(FileNotFoundError):
        source.open(digest("absent"))


# --- record validation ----------------------------------------------------


def test_release_record_requires_a_valid_sha256():
    with pytest.raises(ValueError):
        ReleaseRecord(
            project="acme",
            version="1.0",
            filename=SDIST,
            sha256="nope",
            size_bytes=0,
        )


@pytest.mark.parametrize("size_bytes", [-1, True, 1.5])
def test_release_record_requires_a_nonnegative_integer_size(size_bytes):
    with pytest.raises(ValueError):
        ReleaseRecord(
            project="acme",
            version="1.0",
            filename=SDIST,
            sha256=digest("size"),
            size_bytes=size_bytes,
        )


@pytest.mark.parametrize("blank_field", ["project", "version", "filename"])
def test_release_record_rejects_blank_identity(blank_field):
    fields = {
        "project": "acme",
        "version": "1.0",
        "filename": SDIST,
        "sha256": digest("x"),
        "size_bytes": 0,
        blank_field: "  ",
    }
    with pytest.raises(ValueError):
        ReleaseRecord(**fields)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("project", 1),
        ("project", True),
        ("version", object()),
        ("filename", " "),
        ("filename", b"name"),
    ],
)
def test_release_record_requires_builtin_nonblank_strings(field, value):
    fields = {
        "project": "acme",
        "version": "1.0",
        "filename": SDIST,
        "sha256": digest("strict-string"),
        "size_bytes": 0,
    }
    fields[field] = value
    with pytest.raises(ValueError):
        ReleaseRecord(**fields)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Acme", "acme"),
        ("zope.interface", "zope-interface"),
        ("ruamel_yaml", "ruamel-yaml"),
        ("  Foo__Bar  ", "foo-bar"),
    ],
)
def test_canonical_project_name(raw, expected):
    assert canonical_project_name(raw) == expected


# --- filename classification ---------------------------------------------


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        (PURE, "wheel"),
        (PLATFORM, "wheel"),
        ("acme-2.0.0.tar.gz", "sdist"),
        ("acme-2.0.0.zip", "sdist"),
        ("acme-2.0.0.tar.bz2", "sdist"),
        ("acme-2.0.0.TAR.GZ", "sdist"),
        ("acme-2.0.0.egg", "unknown"),
        ("acme-2.0.0", "unknown"),
    ],
)
def test_artifact_kind(filename, expected):
    assert artifact_kind(filename) == expected


@pytest.mark.parametrize(
    ("filename", "text", "universal"),
    [
        (PURE, "py3-none-any", True),
        ("acme-2.0.0-py2.py3-none-any.whl", "py2.py3-none-any", True),
        (PLATFORM, "cp311-cp311-manylinux_2_17_x86_64", False),
        ("acme-2.0.0-1-py3-none-any.whl", "py3-none-any", True),
        ("acme-2.0.0-PY3-NONE-ANY.whl", "py3-none-any", True),
    ],
)
def test_parse_wheel_tag(filename, text, universal):
    tag = parse_wheel_tag(filename)
    assert tag is not None
    assert tag.text == text
    assert tag.universal is universal


@pytest.mark.parametrize(
    "filename", [SDIST, "acme-2.0.0-py3-none.whl", "acme.whl", "-py3-none-any.whl"]
)
def test_parse_wheel_tag_rejects_unusable_filenames(filename):
    assert parse_wheel_tag(filename) is None


# --- candidate eligibility ------------------------------------------------


def test_only_strictly_lower_versions_are_eligible():
    target = release("acme", "2.0.0", PURE)
    candidates = [
        release("acme", "1.9.0", "acme-1.9.0-py3-none-any.whl"),
        release("acme", "2.0.0", "acme-2.0.0-py3-none-any-other.whl"),
        release("acme", "2.0.1", "acme-2.0.1-py3-none-any.whl"),
    ]
    eligible = eligible_candidates(target, candidates)
    assert [record.version for _, record in eligible] == ["1.9.0"]


def test_prereleases_below_the_target_stay_eligible():
    target = release("acme", "2.0.0", PURE)
    candidates = [
        release("acme", "2.0.0rc1", "acme-2.0.0rc1-py3-none-any.whl"),
        release("acme", "2.0.1a1", "acme-2.0.1a1-py3-none-any.whl"),
    ]
    eligible = eligible_candidates(target, candidates)
    assert [record.version for _, record in eligible] == ["2.0.0rc1"]
    assert eligible[0][0] == Version("2.0.0rc1")


def test_unparsable_versions_are_dropped_with_a_reason(caplog):
    target = release("acme", "2.0.0", PURE)
    candidate = release("acme", "v1-beta!!", "acme-weird-py3-none-any.whl")
    with caplog.at_level(logging.DEBUG, logger="devpi_guardian.baseline"):
        assert eligible_candidates(target, [candidate]) == []
    assert "category=invalid_version" in caplog.text
    assert "v1-beta!!" not in caplog.text


def test_an_unparsable_target_version_selects_nothing(caplog):
    target = release("acme", "not-a-version", PURE)
    older = release("acme", "1.0.0", "acme-1.0.0-py3-none-any.whl")
    with caplog.at_level(logging.DEBUG, logger="devpi_guardian.baseline"):
        assert choose(target, older) is None
    assert "category=invalid_version" in caplog.text
    assert "not-a-version" not in caplog.text


def test_the_target_itself_is_never_its_own_baseline():
    target = release("acme", "2.0.0", PURE)
    same = ReleaseRecord(
        project="acme",
        version="2.0.0",
        filename=PURE,
        sha256=target.sha256,
        size_bytes=0,
    )
    assert eligible_candidates(target, [same]) == []


def test_other_projects_are_rejected_defensively(caplog):
    target = release("acme", "2.0.0", PURE)
    other = release("other", "1.0.0", "other-1.0.0-py3-none-any.whl")
    with caplog.at_level(logging.DEBUG, logger="devpi_guardian.baseline"):
        assert eligible_candidates(target, [other]) == []
    assert "category=project_mismatch" in caplog.text
    assert "other" not in caplog.text


def test_project_names_are_compared_after_normalization():
    target = release("Zope.Interface", "2.0.0", "zope_interface-2.0.0-py3-none-any.whl")
    older = release("zope-interface", "1.0.0", "zope_interface-1.0.0-py3-none-any.whl")
    selection = choose(target, older)
    assert selection is not None
    assert selection.release == older


def test_same_version_and_filename_ties_choose_the_same_digest_regardless_of_order():
    target = release("acme", "2.0.0", PLATFORM)
    first = release(
        "acme",
        "1.0.0",
        "acme-1.0.0-cp311-cp311-manylinux_2_17_x86_64.whl",
        sha256=digest("first"),
    )
    second = release(
        "acme",
        "1.0.0",
        "acme-1.0.0-cp311-cp311-manylinux_2_17_x86_64.whl",
        sha256=digest("second"),
    )

    left = choose(target, first, second)
    right = choose(target, second, first)

    assert left is not None
    assert right is not None
    assert left.release.sha256 == right.release.sha256 == min(first.sha256, second.sha256)


def test_lookup_is_queried_with_the_target_project_name():
    lookup = FakeReleaseLookup([release("acme", "1.0.0", "acme-1.0.0-py3-none-any.whl")])
    select_baseline(release("acme", "2.0.0", PURE), lookup)
    assert lookup.calls == ["acme"]


# --- the priority chain ---------------------------------------------------


def test_tier_one_prefers_an_exact_tag_match():
    target = release("acme", "2.0.0", PLATFORM)
    exact = release("acme", "1.0.0", "acme-1.0.0-cp311-cp311-manylinux_2_17_x86_64.whl")
    universal = release("acme", "1.9.0", "acme-1.9.0-py3-none-any.whl")
    sdist = release("acme", "1.9.9", "acme-1.9.9.tar.gz")
    selection = choose(target, universal, sdist, exact)
    assert selection is not None
    assert selection.tier == "same_tag"
    assert selection.release == exact


def test_an_exact_tag_match_wins_even_at_a_much_older_version():
    target = release("acme", "9.0.0", PLATFORM)
    exact = release("acme", "0.0.1", "acme-0.0.1-cp311-cp311-manylinux_2_17_x86_64.whl")
    universal = release("acme", "8.9.0", "acme-8.9.0-py3-none-any.whl")
    selection = choose(target, universal, exact)
    assert selection is not None
    assert selection.tier == "same_tag"
    assert selection.release == exact


def test_a_differing_tag_is_not_an_exact_match():
    target = release("acme", "2.0.0", PLATFORM)
    other_abi = release("acme", "1.0.0", "acme-1.0.0-cp312-cp312-manylinux_2_17_x86_64.whl")
    assert choose(target, other_abi) is None


def test_tier_two_falls_back_to_a_universal_wheel():
    target = release("acme", "2.0.0", PLATFORM)
    universal = release("acme", "1.9.0", "acme-1.9.0-py2.py3-none-any.whl")
    sdist = release("acme", "1.9.9", "acme-1.9.9.tar.gz")
    selection = choose(target, sdist, universal)
    assert selection is not None
    assert selection.tier == "universal_wheel"
    assert selection.release == universal


def test_tier_three_falls_back_to_an_sdist():
    target = release("acme", "2.0.0", PLATFORM)
    sdist = release("acme", "1.9.0", "acme-1.9.0.tar.gz")
    unrelated_wheel = release("acme", "1.9.5", "acme-1.9.5-cp312-cp312-win_amd64.whl")
    selection = choose(target, unrelated_wheel, sdist)
    assert selection is not None
    assert selection.tier == "sdist"
    assert selection.release == sdist


def test_no_candidate_means_no_baseline():
    assert choose(release("acme", "2.0.0", PURE)) is None


def test_a_universal_target_matches_its_own_tag_first():
    target = release("acme", "2.0.0", PURE)
    same_tag = release("acme", "1.0.0", "acme-1.0.0-py3-none-any.whl")
    other_universal = release("acme", "1.9.0", "acme-1.9.0-py2.py3-none-any.whl")
    selection = choose(target, other_universal, same_tag)
    assert selection is not None
    assert selection.tier == "same_tag"
    assert selection.release == same_tag


def test_within_a_tier_the_newest_eligible_version_wins():
    target = release("acme", "3.0.0", PURE)
    for candidates in (
        [
            release("acme", "1.0.0", "acme-1.0.0-py3-none-any.whl"),
            release("acme", "2.5.0", "acme-2.5.0-py3-none-any.whl"),
            release("acme", "2.0.0", "acme-2.0.0-py3-none-any.whl"),
        ],
    ):
        selection = choose(target, *candidates)
        assert selection is not None
        assert selection.version == Version("2.5.0")
        assert selection.release.version == "2.5.0"


def test_ties_at_the_same_version_resolve_by_filename():
    target = release("acme", "3.0.0", PLATFORM)
    first = release("acme", "2.0.0", "acme-2.0.0-1-py3-none-any.whl")
    second = release("acme", "2.0.0", "acme-2.0.0-2-py3-none-any.whl")
    forward = choose(target, first, second)
    reversed_order = choose(target, second, first)
    assert forward is not None and forward.release == first
    assert reversed_order == forward


def test_selection_is_independent_of_lookup_ordering():
    target = release("acme", "3.0.0", PLATFORM)
    candidates = [
        release("acme", "2.9.0", "acme-2.9.0.tar.gz"),
        release("acme", "1.0.0", "acme-1.0.0-cp311-cp311-manylinux_2_17_x86_64.whl"),
        release("acme", "2.5.0", "acme-2.5.0-py3-none-any.whl"),
    ]
    selections = {choose(target, *candidates), choose(target, *reversed(candidates))}
    assert len(selections) == 1
    assert next(iter(selections)).tier == "same_tag"


# --- sdist and unclassifiable targets -------------------------------------


def test_an_sdist_target_only_considers_sdists():
    target = release("acme", "2.0.0", SDIST)
    older_sdist = release("acme", "1.0.0", "acme-1.0.0.tar.gz")
    newer_universal = release("acme", "1.9.0", "acme-1.9.0-py3-none-any.whl")
    selection = choose(target, newer_universal, older_sdist)
    assert selection is not None
    assert selection.tier == "sdist"
    assert selection.release == older_sdist


def test_an_sdist_target_without_an_older_sdist_has_no_baseline():
    target = release("acme", "2.0.0", SDIST)
    universal = release("acme", "1.9.0", "acme-1.9.0-py3-none-any.whl")
    assert choose(target, universal) is None


def test_an_unclassifiable_target_selects_nothing(caplog):
    target = release("acme", "2.0.0", "acme-2.0.0.egg")
    older = release("acme", "1.0.0", "acme-1.0.0.tar.gz")
    with caplog.at_level(logging.DEBUG, logger="devpi_guardian.baseline"):
        assert choose(target, older) is None
    assert "category=unsupported_artifact" in caplog.text
    assert "acme-2.0.0.egg" not in caplog.text


def test_a_wheel_target_with_an_unreadable_tag_skips_only_tier_one(caplog):
    target = release("acme", "2.0.0", "acme.whl")
    universal = release("acme", "1.9.0", "acme-1.9.0-py3-none-any.whl")
    with caplog.at_level(logging.DEBUG, logger="devpi_guardian.baseline"):
        selection = choose(target, universal)
    assert selection is not None
    assert selection.tier == "universal_wheel"
    assert "category=unreadable_target_tag" in caplog.text


def test_a_candidate_wheel_with_an_unreadable_tag_matches_no_wheel_tier():
    target = release("acme", "2.0.0", PURE)
    broken = release("acme", "1.9.0", "acme.whl")
    assert choose(target, broken) is None


# An unreadable candidate tag must be an explicit "not a universal wheel"
# verdict. It must never become "cannot tell, so skip the check and pass".


@pytest.mark.parametrize(
    "filename",
    [
        "acme.whl",
        "acme-1.9.0-py3-none.whl",
        # The last three dash-separated parts spell a universal tag, but the
        # filename as a whole is not a readable wheel name. A check that only
        # looked at the suffix would wrongly accept these.
        "acme-py3-none-any.whl",
        "acme-1.9.0-1-extra-py3-none-any.whl",
    ],
)
def test_an_unreadable_candidate_tag_is_rejected_by_the_universal_tier(filename, caplog):
    # The target wheel has no readable tag either, so the same_tag tier is
    # skipped and universal_wheel is the first tier actually consulted.
    target = release("acme", "2.0.0", "acme.whl")
    broken = release("acme", "1.9.0", filename)

    # The candidate clears every eligibility filter: same project, parsable
    # version, strictly older. Only the tier verdict can reject it.
    assert [record.filename for _, record in eligible_candidates(target, [broken])] == [filename]

    with caplog.at_level(logging.DEBUG, logger="devpi_guardian.baseline"):
        assert choose(target, broken) is None
    assert "universal_wheel" in caplog.text
    assert "category=unreadable_candidate_tag" in caplog.text
    assert filename not in caplog.text


def test_an_unreadable_candidate_tag_never_outranks_a_real_universal_wheel():
    target = release("acme", "3.0.0", PLATFORM)
    # Newer, and would win the tier on version alone if it were accepted.
    broken = release("acme", "2.9.0", "acme-py3-none-any.whl")
    genuine = release("acme", "1.0.0", "acme-1.0.0-py3-none-any.whl")
    selection = choose(target, broken, genuine)
    assert selection is not None
    assert selection.tier == "universal_wheel"
    assert selection.release == genuine


def test_an_unreadable_candidate_tag_does_not_block_the_sdist_tier():
    target = release("acme", "3.0.0", PLATFORM)
    broken = release("acme", "2.9.0", "acme-py3-none-any.whl")
    sdist = release("acme", "1.0.0", "acme-1.0.0.tar.gz")
    selection = choose(target, broken, sdist)
    assert selection is not None
    assert selection.tier == "sdist"
    assert selection.release == sdist


def test_selection_debug_logs_use_only_bounded_categories_and_tiers(caplog):
    """Selection diagnostics never expose release metadata.

    The release records deliberately contain URL, credential, path, and full
    digest sentinels.  Each branch that emits a selection diagnostic is
    exercised against the real module logger so a future log argument cannot
    accidentally turn release metadata into a log record.
    """

    project = "https://user:project-secret@example.invalid/pkg"
    other_project = "https://user:other-secret@example.invalid/other"
    invalid_version = "https://user:version-secret@example.invalid/not-a-version"
    digest_sentinel = "deadbeef" * 8
    filenames = {
        "invalid-target": "/private/guardian/invalid target.whl",
        "invalid-candidate": "/private/guardian/invalid candidate.whl",
        "unknown-target": "/private/guardian/unknown target.egg",
        "unreadable-target": "/private/guardian/unreadable target.whl",
        "unreadable-candidate": "/private/guardian/unreadable candidate.whl",
        "non-older-candidate": "/private/guardian/non-older candidate.whl",
        "mismatched-project": "/private/guardian/mismatched project.whl",
        "selected-target": (
            "/private/guardian/selected target-2.0.0-cp311-cp311-manylinux_2_17_x86_64.whl"
        ),
        "selected-candidate": (
            "/private/guardian/selected candidate-1.0.0-cp311-cp311-manylinux_2_17_x86_64.whl"
        ),
    }

    invalid_target = release(
        project,
        invalid_version,
        filenames["invalid-target"],
        sha256=digest_sentinel,
    )
    invalid_candidate = release(
        project,
        invalid_version,
        filenames["invalid-candidate"],
        sha256=digest("invalid-candidate"),
    )
    unknown_target = release(
        project,
        "2.0.0",
        filenames["unknown-target"],
        sha256=digest("unknown-target"),
    )
    unreadable_target = release(
        project,
        "2.0.0",
        filenames["unreadable-target"],
        sha256=digest("unreadable-target"),
    )
    unreadable_candidate = release(
        project,
        "1.0.0",
        filenames["unreadable-candidate"],
        sha256=digest("unreadable-candidate"),
    )
    non_older_candidate = release(
        project,
        "2.1.0",
        filenames["non-older-candidate"],
        sha256=digest("non-older-candidate"),
    )
    mismatched_project = release(
        other_project,
        "1.0.0",
        filenames["mismatched-project"],
        sha256=digest("mismatched-project"),
    )
    selected_target = release(
        project,
        "2.0.0",
        filenames["selected-target"],
        sha256=digest("selected-target"),
    )
    selected_candidate = release(
        project,
        "1.0.0",
        filenames["selected-candidate"],
        sha256=digest("selected-candidate"),
    )

    with caplog.at_level(logging.DEBUG, logger="devpi_guardian.baseline"):
        assert choose(invalid_target) is None
        assert choose(release(project, "2.0.0", "known-target.whl"), invalid_candidate) is None
        assert choose(unknown_target) is None
        assert choose(unreadable_target, release(project, "1.0.0", PURE)) is not None
        assert choose(release(project, "2.0.0", PLATFORM), unreadable_candidate) is None
        assert choose(release(project, "2.0.0", PURE), non_older_candidate) is None
        assert eligible_candidates(release(project, "2.0.0", PURE), [mismatched_project]) == []
        selection = choose(selected_target, selected_candidate)

    assert selection is not None
    assert selection.tier == "same_tag"
    assert "category=invalid_version" in caplog.text
    assert "category=unsupported_artifact" in caplog.text
    assert "category=unreadable_target_tag" in caplog.text
    assert "category=unreadable_candidate_tag" in caplog.text
    assert "category=non_older_candidate" in caplog.text
    assert "category=project_mismatch" in caplog.text
    assert "category=selected" in caplog.text
    assert "tier=same_tag" in caplog.text
    for sentinel in (*filenames.values(), project, other_project, invalid_version, digest_sentinel):
        assert sentinel not in caplog.text
