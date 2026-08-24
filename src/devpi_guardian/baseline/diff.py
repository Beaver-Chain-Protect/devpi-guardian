"""F7: compare one artifact against its approved baseline release.

The comparison is a diff, not a fresh scan. Only the Python files that the
baseline does not contain, or that the baseline contains with different bytes,
are analyzed; everything the baseline already carried was approved once and is
not re-litigated here.

A changed file is analyzed in full, but only the credential flows the
baseline version did not already carry are reported. Otherwise an unrelated
edit anywhere in a file would resurface evidence the baseline was approved
with, and an unchanged file and a comment-only edit of it would disagree.
Flows the baseline already carried are kept in `carried_flows` as context.

The security judgement itself is F8's. This module extracts artifacts with
F8's hardened archive reader and runs F8's own analyses on the diffed files:
credential-to-network flows, the risky-call classification behind
`wheel_only_risky_python`, and the executable-`.pth` line test. What F7 adds is
the baseline comparison and the origin marker saying a finding is new relative
to the baseline; the rule vocabulary in `DIFF_RULES` mirrors F9's `wheel_only_*`
actions one for one.

Not every F8 rule is diffed. `analyzers.install_surface` judges an artifact as
a whole - build backends, setup.py behavior, entry points, `sitecustomize`,
`__init__` side effects - and those checks are the standalone scan's job, not
this comparison's. F7 covers the file-scoped evidence, plus whatever
`extract_artifact` rejects at the archive level.
"""

from __future__ import annotations

import ast
import hashlib
import os
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from ..analyzers.archive import ExtractedArtifact, extract_artifact
from ..analyzers.astutil import (
    AnalysisLimitExceeded,
    CredentialFlow,
    build_alias_table,
    find_credential_network_flows,
    parse_python,
    scan_calls,
)
from ..analyzers.rules import RULES, Rule
from ..analyzers.sdist_wheel import (
    _NATIVE_SUFFIXES,
    _collect_entry_points,
    _executable_pth_lines,
    _ignored,
    _read_python,
    _strip_sdist_prefix,
    _wheel_paths,
)
from ..analyzers.serialization import finding_fingerprint
from ..analyzers.types import Finding, make_finding, sort_findings
from .selection import (
    ArtifactBytesSource,
    BaselineSelection,
    BaselineTier,
    ReleaseLookup,
    ReleaseRecord,
    artifact_kind,
    select_baseline,
)

#: Why a finding exists in a baseline diff. Every finding F7 returns carries
#: one of these, because `Finding` is frozen and must not grow a field.
Origin = Literal["diff_new", "diff_changed", "diff_artifact"]


@dataclass(frozen=True, slots=True)
class FindingAttribution:
    """A finding paired with its diff origin and baseline confidence tier."""

    finding: Finding
    origin: Origin
    tier: BaselineTier | None

    def __iter__(self):
        """Keep the pre-F10 two-value iteration API source-compatible."""

        yield self.finding
        yield self.origin

    def __getitem__(self, index: int):
        return (self.finding, self.origin, self.tier)[index]


#: Rules that only baseline diffing can raise. F8's RULES has no baseline
#: vocabulary, and reusing a `wheel_only_*` rule would show operators a message
#: about wheels for a finding that has nothing to do with sdist/wheel skew.
#: Actions mirror the corresponding `wheel_only_*` rule exactly. Merge these
#: into `analyzers/rules.py` when F7 lands beside F8.
DIFF_RULES: dict[str, Rule] = {
    "baseline_new_credential_network": Rule(
        "DENY",
        "baseline에 없던 코드가 credential을 읽어 외부 통신 함수로 전달합니다.",
    ),
    "baseline_new_risky_python": Rule(
        "DENY",
        "baseline에 없던 Python 코드가 프로세스·네트워크·동적 실행을 수행합니다.",
    ),
    "baseline_new_executable_pth": Rule(
        "DENY",
        "baseline에 없던 .pth 파일이 Python 시작 시 코드를 실행합니다.",
    ),
    "baseline_new_native": Rule(
        "REVIEW",
        "baseline에 없던 네이티브 바이너리가 추가되었습니다.",
    ),
    "baseline_new_entry_point": Rule(
        "REVIEW",
        "baseline에 없던 console 또는 GUI 실행 명령이 등록되었습니다.",
    ),
}

#: Call categories F8 treats as risky wherever they appear. Mirrors the set
#: `sdist_wheel._wheel_only_python_findings` uses for `wheel_only_risky_python`.
_RISKY_CALL_CATEGORIES = frozenset({"process", "network", "dynamic_exec"})

#: Dynamically imported top-level modules F8 treats as risky, same source.
_RISKY_DYNAMIC_MODULES = frozenset({"subprocess", "requests", "urllib", "socket", "http", "httpx"})


@dataclass(frozen=True, slots=True)
class FileDiff:
    """Path-level comparison, after metadata paths have been excluded."""

    added: tuple[str, ...]
    changed: tuple[str, ...]
    removed: tuple[str, ...]
    unchanged: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NewSurface:
    """Imports and calls a diffed file adds. Context only, never a verdict."""

    file: str
    origin: Origin
    imports: tuple[str, ...]
    calls: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CarriedFlow:
    """A credential flow the baseline already carried, so not a new finding.

    Kept so that suppressing it never hides the fact that the file performs
    the flow at all. `line` points into the new artifact.
    """

    file: str
    line: int
    source: str
    sink: str
    snippet: str


@dataclass(frozen=True, slots=True)
class CarriedEvidence:
    """Non-credential evidence the baseline version already carried.

    The counterpart of `CarriedFlow` for risky calls and executable `.pth`
    lines: suppressed as a finding because the baseline was approved with it,
    kept here so suppression never hides what the file does.
    """

    file: str
    rule: str
    snippet: str
    line: int | None = None


@dataclass(frozen=True, slots=True)
class BaselineDiff:
    """Everything F7 learned about one artifact/baseline pair."""

    findings: tuple[FindingAttribution, ...]
    files: FileDiff
    surface: tuple[NewSurface, ...]
    carried_flows: tuple[CarriedFlow, ...]
    carried_evidence: tuple[CarriedEvidence, ...]
    usable: bool
    tier: BaselineTier | None = None


_EMPTY_FILES = FileDiff((), (), (), ())


def _rule(rule_id: str) -> Rule:
    """Resolve F7's own rules first, then fall back to F8's shared RULES."""

    definition = DIFF_RULES.get(rule_id)
    return definition if definition is not None else RULES[rule_id]


def _finding(
    rule_id: str,
    *,
    file: str,
    line: int | None,
    snippet: str,
    source: str | None = None,
    sink: str | None = None,
) -> Finding:
    definition = _rule(rule_id)
    return make_finding(
        rule=rule_id,
        action=definition.action,
        file=file,
        line=line,
        snippet=snippet,
        message=definition.message,
        source=source,
        sink=sink,
    )


def _error(file: str, exc: BaseException) -> Finding:
    return _finding(
        "analyzer_error",
        file=file,
        line=None,
        snippet=f"{type(exc).__name__}: {exc}",
    )


def _ordered(
    pairs: Iterable[tuple[Finding, Origin]],
    *,
    tier: BaselineTier | None = None,
) -> tuple[FindingAttribution, ...]:
    """De-duplicate by evidence identity and reuse F8's public ordering."""

    grouped: dict[str, tuple[Finding, set[Origin]]] = {}
    for finding, origin in pairs:
        fingerprint = finding_fingerprint(finding)
        entry = grouped.setdefault(fingerprint, (finding, set()))
        entry[1].add(origin)

    ordered: list[FindingAttribution] = []
    for finding in sort_findings([representative for representative, _ in grouped.values()]):
        origins = grouped[finding_fingerprint(finding)][1]
        ordered.extend(FindingAttribution(finding, origin, tier) for origin in sorted(origins))
    return tuple(ordered)


def _flow_key(flow: CredentialFlow) -> tuple[str, str, str]:
    """Line-independent identity for one credential flow.

    Line numbers move whenever anything above them changes, so they cannot be
    part of the identity. The credential source, the network sink, and the
    exact call text are what make two flows the same piece of evidence.
    """

    return (flow.source.description, flow.sink.qualified_name, flow.sink.snippet)


def _logical_paths(extracted: ExtractedArtifact, filename: str) -> dict[str, str]:
    """Map comparable paths to extracted paths, per artifact kind.

    An sdist wraps everything in a `pkg-1.0/` directory and often keeps import
    packages under `src/`; a wheel does not. F9 already solved that skew, so
    its normalization is reused rather than restated, which keeps F7 and F9
    from drifting apart.
    """

    if artifact_kind(filename) == "sdist":
        return _strip_sdist_prefix(extracted.files)
    return _wheel_paths(extracted.files)


def _comparable(paths: dict[str, str]) -> dict[str, str]:
    """Drop `.dist-info`/`.egg-info` contents, RECORD, and signature files.

    Archive member timestamps are never read, so they cannot cause a spurious
    difference: the comparison is over member paths and file bytes only.
    """

    return {logical: actual for logical, actual in paths.items() if not _ignored(logical)}


def _physical(extracted: ExtractedArtifact, actual: str) -> Path:
    return extracted.root / Path(*PurePosixPath(actual).parts)


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _classify_files(
    baseline: ExtractedArtifact,
    baseline_paths: dict[str, str],
    artifact: ExtractedArtifact,
    artifact_paths: dict[str, str],
) -> tuple[FileDiff, list[tuple[Finding, Origin]]]:
    added: list[str] = []
    changed: list[str] = []
    unchanged: list[str] = []
    findings: list[tuple[Finding, Origin]] = []

    for logical in sorted(artifact_paths):
        if logical not in baseline_paths:
            added.append(logical)
            continue
        try:
            same = _digest(_physical(artifact, artifact_paths[logical])) == _digest(
                _physical(baseline, baseline_paths[logical])
            )
        except OSError as exc:
            # An unreadable member cannot be shown identical to the baseline,
            # so it is treated as changed and analyzed.
            findings.append((_error(logical, exc), "diff_changed"))
            changed.append(logical)
            continue
        (unchanged if same else changed).append(logical)

    removed = sorted(set(baseline_paths) - set(artifact_paths))
    return (
        FileDiff(tuple(added), tuple(changed), tuple(removed), tuple(unchanged)),
        findings,
    )


def _module_facts(tree: ast.Module, source: str) -> tuple[set[str], list, list]:
    """Everything one parsed module contributes: imports, calls, dynamic imports."""

    calls, dynamic_imports = scan_calls(tree, source)
    imports = set(build_alias_table(tree).values())
    imports.update(entry.module for entry in dynamic_imports)
    return imports, calls, dynamic_imports


def _call_key(qualified_name: str, snippet: str) -> tuple[str, str]:
    """Line-independent identity for one risky call, matching `_flow_key`."""

    return (qualified_name, snippet)


def _parse_baseline(logical: str, baseline_physical: Path | None) -> tuple[ast.Module, str] | None:
    """Parse the baseline version of a file, or give up and fail closed.

    Returning None means "nothing is known to have been approved before", so
    the caller reports the new artifact's whole evidence rather than trusting
    a baseline it could not read.
    """

    if baseline_physical is None:
        return None
    try:
        source = _read_python(baseline_physical)
        return parse_python(source, filename=logical), source
    except (AnalysisLimitExceeded, SyntaxError, UnicodeError, LookupError, OSError):
        return None


def _analyze_python(
    logical: str,
    physical: Path,
    origin: Origin,
    baseline_physical: Path | None,
) -> tuple[
    list[tuple[Finding, Origin]],
    NewSurface | None,
    list[CarriedFlow],
    list[CarriedEvidence],
]:
    """Run F8's Python judgement on one added or changed file.

    Two rules are applied, both taken from F8: the credential-to-network flow
    analysis, and the risky-call classification F9 uses for wheel-only files.
    Evidence the baseline version already carried is suppressed and recorded
    rather than reported, exactly as for credential flows.
    """

    try:
        source = _read_python(physical)
        tree = parse_python(source, filename=logical)
    except AnalysisLimitExceeded as exc:
        finding = _finding("analysis_limit_exceeded", file=logical, line=None, snippet=str(exc))
        return [(finding, origin)], None, [], []
    except (SyntaxError, UnicodeError, LookupError, OSError) as exc:
        line = getattr(exc, "lineno", None)
        finding = _finding(
            "ast_parse_failed",
            file=logical,
            line=line if isinstance(line, int) else None,
            snippet=f"{type(exc).__name__}: {exc}",
        )
        return [(finding, origin)], None, [], []

    imports, calls, dynamic_imports = _module_facts(tree, source)

    baseline_state = _parse_baseline(logical, baseline_physical)
    carried_flow_keys: set[tuple[str, str, str]] = set()
    carried_call_keys: set[tuple[str, str]] = set()
    baseline_imports: set[str] = set()
    baseline_call_names: set[str] = set()
    if baseline_state is not None:
        baseline_tree, baseline_source = baseline_state
        carried_flow_keys = {
            _flow_key(flow)
            for flow in find_credential_network_flows(baseline_tree, baseline_source)
        }
        baseline_imports, baseline_calls, baseline_dynamic = _module_facts(
            baseline_tree, baseline_source
        )
        baseline_call_names = {call.qualified_name for call in baseline_calls}
        carried_call_keys = {
            _call_key(call.qualified_name, call.snippet)
            for call in baseline_calls
            if call.category in _RISKY_CALL_CATEGORIES
        }
        carried_call_keys.update(
            _call_key(entry.module, entry.snippet) for entry in baseline_dynamic
        )

    findings: list[tuple[Finding, Origin]] = []
    carried_flows: list[CarriedFlow] = []
    carried: list[CarriedEvidence] = []

    flows = find_credential_network_flows(tree, source)
    for flow in flows:
        if _flow_key(flow) in carried_flow_keys:
            carried_flows.append(
                CarriedFlow(
                    file=logical,
                    line=flow.sink.line,
                    source=flow.source.description,
                    sink=flow.sink.qualified_name,
                    snippet=flow.sink.snippet,
                )
            )
            continue
        findings.append(
            (
                _finding(
                    "baseline_new_credential_network",
                    file=logical,
                    line=flow.sink.line,
                    snippet=flow.sink.snippet,
                    source=flow.source.description,
                    sink=flow.sink.qualified_name,
                ),
                origin,
            )
        )

    # A sink already reported as a credential flow is not reported a second
    # time as a plain risky call. This is F9's rule, kept identical.
    flow_sinks = {(flow.sink.line, flow.sink.qualified_name) for flow in flows}
    for call in calls:
        if (call.line, call.qualified_name) in flow_sinks:
            continue
        if call.category not in _RISKY_CALL_CATEGORIES:
            continue
        if _call_key(call.qualified_name, call.snippet) in carried_call_keys:
            carried.append(
                CarriedEvidence(
                    file=logical,
                    rule="baseline_new_risky_python",
                    line=call.line,
                    snippet=call.snippet,
                )
            )
            continue
        findings.append(
            (
                _finding(
                    "baseline_new_risky_python",
                    file=logical,
                    line=call.line,
                    snippet=call.snippet,
                    sink=call.qualified_name,
                ),
                origin,
            )
        )

    for entry in dynamic_imports:
        if entry.module.split(".", 1)[0] not in _RISKY_DYNAMIC_MODULES:
            continue
        if _call_key(entry.module, entry.snippet) in carried_call_keys:
            carried.append(
                CarriedEvidence(
                    file=logical,
                    rule="baseline_new_risky_python",
                    line=entry.line,
                    snippet=entry.snippet,
                )
            )
            continue
        findings.append(
            (
                _finding(
                    "baseline_new_risky_python",
                    file=logical,
                    line=entry.line,
                    snippet=entry.snippet,
                    sink=entry.module,
                ),
                origin,
            )
        )

    new_imports = imports - baseline_imports
    new_calls = {call.qualified_name for call in calls} - baseline_call_names
    surface = NewSurface(
        file=logical,
        origin=origin,
        imports=tuple(sorted(new_imports)),
        calls=tuple(sorted(new_calls)),
    )
    return (
        findings,
        (surface if (surface.imports or surface.calls) else None),
        carried_flows,
        carried,
    )


def _analyze_pth(
    logical: str,
    physical: Path,
    origin: Origin,
    baseline_physical: Path | None,
) -> tuple[list[tuple[Finding, Origin]], list[CarriedEvidence]]:
    """Report `.pth` lines that execute code at interpreter startup.

    Uses F8's own line classifier, so what counts as executable here is what
    counts as executable in `executable_pth` and `wheel_only_executable_pth`.
    """

    try:
        lines = _executable_pth_lines(physical)
    except OSError as exc:
        return [(_error(logical, exc), origin)], []

    carried_lines: set[str] = set()
    if baseline_physical is not None:
        try:
            carried_lines = {
                snippet.strip() for _, snippet in _executable_pth_lines(baseline_physical)
            }
        except OSError:
            carried_lines = set()

    findings: list[tuple[Finding, Origin]] = []
    carried: list[CarriedEvidence] = []
    for line, snippet in lines:
        if snippet.strip() in carried_lines:
            carried.append(
                CarriedEvidence(
                    file=logical,
                    rule="baseline_new_executable_pth",
                    line=line,
                    snippet=snippet,
                )
            )
            continue
        findings.append(
            (
                _finding(
                    "baseline_new_executable_pth",
                    file=logical,
                    line=line,
                    snippet=snippet,
                ),
                origin,
            )
        )
    return findings, carried


def _entry_point_evidence(
    baseline: ExtractedArtifact,
    baseline_paths: dict[str, str],
    artifact: ExtractedArtifact,
    artifact_paths: dict[str, str],
) -> tuple[list[tuple[Finding, Origin]], list[CarriedEvidence]]:
    """Compare declared entry points as parsed sets, not as files.

    `entry_points.txt` lives inside `.dist-info`, which the file comparison
    excludes, and the directory name carries the version - so the same logical
    file is at a different path in every release and could never be diffed by
    path. F9 already solved that by parsing entry points out of
    `entry_points.txt`, `setup.cfg`, `pyproject.toml`, and `setup.py` into one
    canonical set, which also makes an sdist baseline comparable to a wheel.
    Reusing it here leaves the `.dist-info` exclusion completely untouched.
    """

    try:
        baseline_entries, _ = _collect_entry_points(baseline, baseline_paths)
        artifact_entries, source_path = _collect_entry_points(artifact, artifact_paths)
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        return [(_error("<entry-points>", exc), "diff_artifact")], []

    file = source_path or "<entry-points>"
    findings = [
        (
            _finding("baseline_new_entry_point", file=file, line=None, snippet=entry),
            "diff_new",
        )
        for entry in sorted(artifact_entries - baseline_entries)
    ]
    carried = [
        CarriedEvidence(file=file, rule="baseline_new_entry_point", snippet=entry)
        for entry in sorted(artifact_entries & baseline_entries)
    ]
    return findings, carried


def _compare(
    baseline: ExtractedArtifact,
    baseline_filename: str,
    artifact: ExtractedArtifact,
    artifact_filename: str,
    tier: BaselineTier | None,
) -> BaselineDiff:
    findings: list[tuple[Finding, Origin]] = [
        (finding, "diff_artifact") for finding in (*baseline.findings, *artifact.findings)
    ]
    if not baseline.usable or not artifact.usable:
        return BaselineDiff(_ordered(findings, tier=tier), _EMPTY_FILES, (), (), (), False, tier)

    # The full maps still contain `.dist-info`; only the file comparison
    # below drops it. Entry point parsing needs what is inside it.
    baseline_all = _logical_paths(baseline, baseline_filename)
    artifact_all = _logical_paths(artifact, artifact_filename)
    baseline_paths = _comparable(baseline_all)
    artifact_paths = _comparable(artifact_all)

    files, read_failures = _classify_files(baseline, baseline_paths, artifact, artifact_paths)
    findings.extend(read_failures)

    entry_findings, entry_carried = _entry_point_evidence(
        baseline, baseline_all, artifact, artifact_all
    )
    findings.extend(entry_findings)

    surfaces: list[NewSurface] = []
    carried_flows: list[CarriedFlow] = []
    carried: list[CarriedEvidence] = list(entry_carried)
    for logical, origin in (
        *((path, "diff_new") for path in files.added),
        *((path, "diff_changed") for path in files.changed),
    ):
        lowered = logical.lower()
        baseline_actual = baseline_paths.get(logical)
        baseline_physical = (
            _physical(baseline, baseline_actual) if baseline_actual is not None else None
        )
        physical = _physical(artifact, artifact_paths[logical])

        if lowered.endswith(".py"):
            file_findings, surface, file_flows, file_carried = _analyze_python(
                logical, physical, origin, baseline_physical
            )
            findings.extend(file_findings)
            carried_flows.extend(file_flows)
            carried.extend(file_carried)
            if surface is not None:
                surfaces.append(surface)
        elif lowered.endswith(".pth"):
            file_findings, file_carried = _analyze_pth(logical, physical, origin, baseline_physical)
            findings.extend(file_findings)
            carried.extend(file_carried)
        elif lowered.endswith(_NATIVE_SUFFIXES) and origin == "diff_new":
            # Only a native binary the baseline did not have at all. A rebuilt
            # binary differs on every release, so reporting changed ones would
            # mark every native release for review without saying anything.
            findings.append(
                (
                    _finding(
                        "baseline_new_native",
                        file=logical,
                        line=None,
                        snippet=PurePosixPath(logical).name,
                    ),
                    origin,
                )
            )

    ordered_flows = tuple(
        sorted(carried_flows, key=lambda flow: (flow.file, flow.line, flow.source, flow.sink))
    )
    ordered_carried = tuple(
        sorted(
            carried,
            key=lambda item: (
                item.file,
                -1 if item.line is None else item.line,
                item.rule,
                item.snippet,
            ),
        )
    )
    return BaselineDiff(
        _ordered(findings, tier=tier),
        files,
        tuple(surfaces),
        ordered_flows,
        ordered_carried,
        True,
        tier,
    )


def diff_against_baseline(
    baseline_path: str | os.PathLike[str],
    artifact_path: str | os.PathLike[str],
    *,
    tier: BaselineTier | None = None,
) -> BaselineDiff:
    """Diff one artifact against its baseline. No exception reaches the caller."""

    baseline_name = Path(baseline_path).name or "<baseline>"
    artifact_name = Path(artifact_path).name or "<artifact>"
    try:
        with tempfile.TemporaryDirectory(prefix="devpi-guardian-f7-") as temp_dir:
            root = Path(temp_dir)
            baseline = extract_artifact(baseline_path, root / "baseline")
            artifact = extract_artifact(artifact_path, root / "artifact")
            return _compare(baseline, baseline_name, artifact, artifact_name, tier)
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        return BaselineDiff(
            _ordered([(_error(artifact_name, exc), "diff_artifact")], tier=tier),
            _EMPTY_FILES,
            (),
            (),
            (),
            False,
        )


def compare_to_baseline(
    baseline_path: str | os.PathLike[str],
    artifact_path: str | os.PathLike[str],
    *,
    tier: BaselineTier | None = None,
) -> list[FindingAttribution]:
    """F7's judgement surface: findings new relative to the baseline.

    Each finding is paired with its origin because `Finding` is frozen and
    deliberately not extended with a diff-specific field.
    """

    return list(diff_against_baseline(baseline_path, artifact_path, tier=tier).findings)


def findings_only(pairs: Sequence[FindingAttribution]) -> list[Finding]:
    """Drop baseline attribution for callers that only consume F8 findings."""

    return [pair.finding for pair in pairs]


@dataclass(frozen=True, slots=True)
class BaselineComparison:
    """F6 and F7 joined: what to compare against, and what the diff found.

    `baseline_sha256` is what F5 puts into `VerdictInput.baseline_sha256`, so
    "no baseline" travels to the verdict store as `None` rather than as a
    silently skipped step.

    F10 integration note — forward `selection.tier` as well.
    `selection.tier` says *how comparable* the baseline was: an exact
    compatibility-tag match is far stronger evidence than an sdist fallback,
    and the same finding deserves different operator weight depending on it.
    Nothing downstream pulls this field automatically:

    * `VerdictInput` has no tier field, `verdicts` has no tier column, and the
      DTO is frozen with strict validation, so the tier cannot ride along with
      `baseline_sha256`.
    * `Finding` is frozen and deliberately not extended, and the pairs in
      `findings` carry only `Origin`, so per-finding conversion never sees it.

    An F10 loop that builds one `EvidenceInput` per entry in `findings` will
    therefore drop the tier silently, because it never has to touch
    `selection`. Put `selection.tier` (and the pair's `Origin`) into
    `EvidenceInput.details`, which is free-form JSON and the only field that
    accepts them without a schema change.
    """

    has_baseline: bool
    baseline_sha256: str | None
    #: Also carries `tier`. See the F10 integration note above before mapping
    #: `findings` to `EvidenceInput`.
    selection: BaselineSelection | None
    diff: BaselineDiff | None
    findings: tuple[FindingAttribution, ...]


_NO_BASELINE = BaselineComparison(
    has_baseline=False,
    baseline_sha256=None,
    selection=None,
    diff=None,
    findings=(),
)


def compare_release_to_baseline(
    target: ReleaseRecord,
    artifact_path: str | os.PathLike[str],
    *,
    lookup: ReleaseLookup,
    bytes_source: ArtifactBytesSource,
) -> BaselineComparison:
    """Pick a baseline (F6) and diff against it (F7).

    A project whose first release is being scanned has nothing approved to
    compare against. That is not an error and not a finding: F7 is skipped and
    `has_baseline` is False, leaving the artifact to F8's standalone analysis.

    A baseline that was selected but could not be read is a different case. It
    is reported as an analyzer error with `has_baseline` True, so a broken
    filestore can never be mistaken for a first release.

    When wiring this into F10, forward `selection.tier` alongside the
    findings; see the note on `BaselineComparison`.
    """

    artifact_name = Path(artifact_path).name or "<artifact>"
    try:
        selection = select_baseline(target, lookup)
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        return BaselineComparison(
            has_baseline=False,
            baseline_sha256=None,
            selection=None,
            diff=None,
            findings=_ordered([(_error(artifact_name, exc), "diff_artifact")]),
        )

    if selection is None:
        return _NO_BASELINE

    try:
        baseline_path = bytes_source.open(selection.release.sha256)
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        return BaselineComparison(
            has_baseline=True,
            baseline_sha256=selection.release.sha256,
            selection=selection,
            diff=None,
            findings=_ordered(
                [(_error(selection.release.filename, exc), "diff_artifact")],
                tier=selection.tier,
            ),
        )

    diff = diff_against_baseline(baseline_path, artifact_path, tier=selection.tier)
    return BaselineComparison(
        has_baseline=True,
        baseline_sha256=selection.release.sha256,
        selection=selection,
        diff=diff,
        findings=diff.findings,
    )
