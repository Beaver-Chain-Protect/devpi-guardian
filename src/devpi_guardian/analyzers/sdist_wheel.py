"""F9: compare normalized sdist and wheel contents without executing code."""

from __future__ import annotations

import ast
import configparser
import json
import re
import tempfile
import tokenize
import tomllib
from dataclasses import dataclass
from email import policy
from email.parser import Parser
from pathlib import Path, PurePosixPath

from .archive import ExtractedArtifact, extract_artifact
from .astutil import (
    AnalysisLimitExceeded,
    find_credential_network_flows,
    normalized_ast,
    parse_python,
    scan_calls,
)
from .rules import rule
from .types import Finding, make_finding, sort_findings

_NATIVE_SUFFIXES = (".so", ".dll", ".dylib")
_IGNORED_METADATA_FILES = frozenset({"record", "wheel", "metadata", "installer", "pkg-info"})
_SIGNATURE_SUFFIXES = (".asc", ".sig", ".p7s", ".jws")
_REQUIRES_DIST_OPERATOR = re.compile(r"^(===|==|!=|~=|<=|>=|<|>)\s*\S+$")
_MARKER_TOKEN = re.compile(
    r"(?:\s+|(?P<string>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")|"
    r"(?P<operator>===|==|!=|<=|>=|~=|<|>|\(|\))|"
    r"(?P<word>[A-Za-z0-9_.+*-]+))"
)


@dataclass(frozen=True)
class _ArtifactIdentity:
    name: str
    version: str
    source_path: str


def _finding(
    rule_id: str,
    *,
    file: str,
    line: int | None,
    snippet: str,
    source: str | None = None,
    sink: str | None = None,
) -> Finding:
    definition = rule(rule_id)
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


def _strip_sdist_prefix(paths: tuple[str, ...]) -> dict[str, str]:
    """Map normalized comparison paths to their actual extracted paths."""

    split_paths = [PurePosixPath(path).parts for path in paths]
    should_strip = bool(split_paths) and all(
        len(parts) > 1 and parts[0] == split_paths[0][0] for parts in split_paths
    )
    result: dict[str, str] = {}
    for actual, parts in zip(paths, split_paths, strict=True):
        logical_parts = parts[1:] if should_strip else parts
        logical = PurePosixPath(*logical_parts).as_posix()
        result.setdefault(logical, actual)

    # PEP 517 projects commonly keep import packages below src/ in the sdist,
    # while a wheel installs those packages at archive root. Normalize that
    # layout only when doing so is collision-free.
    src_normalized: dict[str, str] = {}
    for logical, actual in result.items():
        parts = PurePosixPath(logical).parts
        normalized = (
            PurePosixPath(*parts[1:]).as_posix()
            if len(parts) > 1 and parts[0].casefold() == "src"
            else logical
        )
        if normalized in src_normalized and src_normalized[normalized] != actual:
            return result
        src_normalized[normalized] = actual
    return src_normalized


def _wheel_paths(paths: tuple[str, ...]) -> dict[str, str]:
    return {PurePosixPath(path).as_posix(): path for path in paths}


def _ignored(logical_path: str) -> bool:
    path = PurePosixPath(logical_path)
    lowered_parts = [part.lower() for part in path.parts]
    if any(part.endswith((".dist-info", ".egg-info")) for part in lowered_parts[:-1]):
        return True
    name = path.name.lower()
    return name in _IGNORED_METADATA_FILES or name.endswith(_SIGNATURE_SUFFIXES)


def _normalize_project_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip()).casefold().strip("-")


def _metadata_candidates(paths: dict[str, str], *, wheel: bool) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    for logical, actual in paths.items():
        path = PurePosixPath(logical)
        expected = "metadata" if wheel else "pkg-info"
        if path.name.casefold() != expected:
            continue
        if wheel and not any(part.casefold().endswith(".dist-info") for part in path.parts[:-1]):
            continue
        candidates.append((logical, actual))
    if wheel:
        return sorted(candidates)
    # Prefer a root PKG-INFO, then the conventional common-root egg-info copy.
    return sorted(
        candidates,
        key=lambda item: (
            0 if len(PurePosixPath(item[0]).parts) == 1 else 1,
            0
            if any(
                part.casefold().endswith(".egg-info") for part in PurePosixPath(item[0]).parts[:-1]
            )
            else 1,
            item[0],
        ),
    )


def _read_core_metadata(
    extracted: ExtractedArtifact, paths: dict[str, str], *, wheel: bool
) -> tuple[object, str] | None:
    for logical, actual in _metadata_candidates(paths, wheel=wheel):
        physical = extracted.root / Path(*PurePosixPath(actual).parts)
        try:
            text = physical.read_text(encoding="utf-8", errors="replace")
            return Parser(policy=policy.default).parsestr(text), logical
        except (OSError, UnicodeError):
            continue
    return None


def _read_artifact_identity(
    extracted: ExtractedArtifact,
    paths: dict[str, str],
    *,
    wheel: bool,
) -> _ArtifactIdentity | None:
    for logical, actual in _metadata_candidates(paths, wheel=wheel):
        physical = extracted.root / Path(*PurePosixPath(actual).parts)
        try:
            message = Parser(policy=policy.default).parsestr(
                physical.read_text(encoding="utf-8", errors="replace")
            )
        except OSError:
            continue
        name = message.get("Name")
        version = message.get("Version")
        if name and version:
            return _ArtifactIdentity(
                _normalize_project_name(str(name)),
                str(version).strip().lower(),
                logical,
            )
    return None


def _split_requirement_marker(value: str) -> tuple[str, str | None]:
    quote: str | None = None
    escaped = False
    depth = 0
    for index, character in enumerate(value):
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in "'\"":
            quote = character
        elif character in "([":
            depth += 1
        elif character in ")]":
            depth = max(depth - 1, 0)
        elif character == ";" and depth == 0:
            return value[:index], value.split(";", 1)[1]
    return value, None


def _normalize_marker(value: str) -> str | None:
    tokens: list[str] = []
    position = 0
    while position < len(value):
        match = _MARKER_TOKEN.match(value, position)
        if match is None:
            return None
        token = match.group(0)
        if match.group("string") is not None:
            try:
                parsed = ast.literal_eval(match.group("string"))
            except (SyntaxError, ValueError):
                return None
            if not isinstance(parsed, str):
                return None
            tokens.append(json.dumps(parsed, ensure_ascii=False))
        elif match.group("word") is not None:
            word = match.group("word")
            tokens.append(
                word.casefold() if word.casefold() in {"and", "or", "not", "in"} else word
            )
        elif match.group("operator") is not None:
            tokens.append(match.group("operator"))
        position += len(token)
    return " ".join(tokens).strip()


def _split_specifier_clauses(value: str) -> list[str] | None:
    clauses: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    depth = 0
    for index, character in enumerate(value):
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in "'\"":
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                return None
        elif character == "," and depth == 0:
            clauses.append(value[start:index])
            start = index + 1
    if quote is not None or depth != 0:
        return None
    clauses.append(value[start:])
    return clauses


def _normalize_requirement(value: str) -> str:
    fallback = " ".join(value.strip().split())
    left, marker = _split_requirement_marker(value)
    match = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\s*\[([^]]*)\])?(.*)$", left)
    if match is None or (match.group(2) is None and match.group(3).lstrip().startswith("[")):
        return fallback

    name = _normalize_project_name(match.group(1))
    extras_value = match.group(2)
    extras: list[str] = []
    if extras_value is not None:
        for extra in extras_value.split(","):
            normalized = _normalize_project_name(extra)
            if not normalized:
                return fallback
            extras.append(normalized)
        extras = sorted(set(extras))
    base = name + (f"[{','.join(extras)}]" if extras else "")
    remainder = match.group(3).strip()
    specifier = ""
    if remainder.startswith("@"):
        url = remainder[1:].strip()
        if not url:
            return fallback
        specifier = f" @ {url}"
    elif remainder:
        if remainder.startswith("(") and remainder.endswith(")"):
            remainder = remainder[1:-1].strip()
        clauses = _split_specifier_clauses(remainder)
        if clauses is None:
            return fallback
        normalized_clauses: list[str] = []
        for clause in clauses:
            compact = " ".join(clause.split())
            if not _REQUIRES_DIST_OPERATOR.fullmatch(compact):
                return fallback
            normalized_clauses.append(re.sub(r"\s+", "", compact))
        specifier = ",".join(sorted(set(normalized_clauses)))

    normalized = base + specifier
    if marker is not None:
        normalized_marker = _normalize_marker(marker)
        if normalized_marker is None:
            return fallback
        normalized += f" ; {normalized_marker}"
    return normalized


def _metadata_version(message: object) -> tuple[int, ...] | None:
    raw = getattr(message, "get", lambda _name: None)("Metadata-Version")
    if raw is None:
        return None
    pieces = str(raw).strip().split(".")
    if not pieces or any(not piece.isdigit() for piece in pieces):
        return None
    return tuple(int(piece) for piece in pieces)


def _dynamic_fields(message: object) -> set[str]:
    get_all = getattr(message, "get_all", lambda _name, failobj=None: failobj)
    values = get_all("Dynamic", []) or []
    return {
        item.strip().casefold()
        for value in values
        for item in str(value).split(",")
        if item.strip()
    }


def _requires_dist(message: object) -> set[str]:
    get_all = getattr(message, "get_all", lambda _name, failobj=None: failobj)
    values = get_all("Requires-Dist", []) or []
    return {_normalize_requirement(str(value)) for value in values}


def _bounded_requirement_diff(values: list[str], *, max_items: int = 5) -> str:
    shown = values[:max_items]
    rendered = [value if len(value) <= 18 else value[:17] + "…" for value in shown]
    if len(values) > max_items:
        rendered.append(f"+{len(values) - max_items}개")
    return repr(rendered)


def _requires_dist_snippet(wheel_only: set[str], sdist_only: set[str]) -> str:
    wheel_values = sorted(wheel_only)
    sdist_values = sorted(sdist_only)
    return (
        f"wheel 전용={_bounded_requirement_diff(wheel_values)}; "
        f"sdist 전용={_bounded_requirement_diff(sdist_values)}"
    )


def _compare_requires_dist(
    sdist: ExtractedArtifact,
    sdist_paths: dict[str, str],
    wheel: ExtractedArtifact,
    wheel_paths: dict[str, str],
) -> Finding | None:
    sdist_metadata = _read_core_metadata(sdist, sdist_paths, wheel=False)
    wheel_metadata = _read_core_metadata(wheel, wheel_paths, wheel=True)
    if sdist_metadata is None or wheel_metadata is None:
        return None
    sdist_message, sdist_path = sdist_metadata
    wheel_message, wheel_path = wheel_metadata
    version = _metadata_version(sdist_message)
    if version is None or version < (2, 2):
        return None
    dynamic = "requires-dist" in _dynamic_fields(sdist_message)
    sdist_requirements = _requires_dist(sdist_message)
    wheel_requirements = _requires_dist(wheel_message)
    if version < (2, 6) and dynamic:
        return None
    wheel_only = wheel_requirements - sdist_requirements
    sdist_only = sdist_requirements - wheel_requirements
    if version >= (2, 6) and dynamic:
        if not sdist_only:
            return None
    elif not wheel_only and not sdist_only:
        return None
    return _finding(
        "requires_dist_mismatch",
        file=wheel_path or sdist_path,
        line=None,
        snippet=_requires_dist_snippet(wheel_only, sdist_only),
    )


def _wheel_scope_finding(extracted: ExtractedArtifact, paths: dict[str, str]) -> Finding | None:
    for logical, actual in sorted(paths.items()):
        if PurePosixPath(logical).name.lower() != "wheel":
            continue
        if not any(
            part.lower().endswith(".dist-info") for part in PurePosixPath(logical).parts[:-1]
        ):
            continue
        physical = extracted.root / Path(*PurePosixPath(actual).parts)
        try:
            message = Parser(policy=policy.default).parsestr(
                physical.read_text(encoding="utf-8", errors="replace")
            )
        except OSError:
            return None
        purelib = str(message.get("Root-Is-Purelib", "")).strip().lower()
        tags = [str(tag).strip().lower() for tag in message.get_all("Tag", [])]
        supported_tags = [
            tag
            for tag in tags
            if len(tag.split("-")) == 3
            and tag.split("-")[1:] == ["none", "any"]
            and "py3" in tag.split("-")[0].split(".")
        ]
        if purelib == "false" or (tags and not supported_tags):
            detail = f"Root-Is-Purelib={purelib or '<missing>'}; tags={','.join(tags) or '<none>'}"
            return _finding(
                "unsupported_wheel_scope",
                file=logical,
                line=None,
                snippet=detail,
            )
        return None
    return None


def _read_python(path: Path) -> str:
    with tokenize.open(path) as source_file:
        return source_file.read()


def _parse_failure(file: str, exc: BaseException) -> Finding:
    line = getattr(exc, "lineno", None)
    return _finding(
        "ast_parse_failed",
        file=file,
        line=line if isinstance(line, int) else None,
        snippet=f"{type(exc).__name__}: {exc}",
    )


def _limit_failure(file: str, exc: AnalysisLimitExceeded) -> Finding:
    return _finding(
        "analysis_limit_exceeded",
        file=file,
        line=None,
        snippet=str(exc),
    )


def _executable_pth_lines(path: Path) -> list[tuple[int, str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    matches: list[tuple[int, str]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.lstrip()
        if stripped == "import" or stripped.startswith(("import ", "import\t")):
            matches.append((line_number, raw_line))
    return matches


def _canonical_entry_point(group: str, name: str, target: str) -> str:
    normalized_group = group.strip().lower().replace("-", "_")
    if normalized_group == "scripts":
        normalized_group = "console_scripts"
    elif normalized_group == "gui_scripts":
        normalized_group = "gui_scripts"
    return f"{normalized_group}:{name.strip()}={target.strip()}"


def _wheel_only_python_findings(logical_path: str, physical_path: Path) -> list[Finding]:
    try:
        source = _read_python(physical_path)
        tree = parse_python(source, filename=logical_path)
    except AnalysisLimitExceeded as exc:
        return [_limit_failure(logical_path, exc)]
    except (SyntaxError, UnicodeError, LookupError, OSError) as exc:
        return [_parse_failure(logical_path, exc)]

    findings: list[Finding] = []
    flows = find_credential_network_flows(tree, source)
    flow_sinks = {(flow.sink.line, flow.sink.qualified_name) for flow in flows}
    for flow in flows:
        findings.append(
            _finding(
                "wheel_only_credential_network",
                file=logical_path,
                line=flow.sink.line,
                snippet=flow.sink.snippet,
                source=flow.source.description,
                sink=flow.sink.qualified_name,
            )
        )

    calls, dynamic_imports = scan_calls(tree, source)
    for call in calls:
        if (call.line, call.qualified_name) in flow_sinks:
            continue
        if call.category in {"process", "network", "dynamic_exec"}:
            findings.append(
                _finding(
                    "wheel_only_risky_python",
                    file=logical_path,
                    line=call.line,
                    snippet=call.snippet,
                )
            )
    for imported in dynamic_imports:
        if imported.module.split(".", 1)[0] in {
            "subprocess",
            "requests",
            "urllib",
            "socket",
            "http",
            "httpx",
        }:
            findings.append(
                _finding(
                    "wheel_only_risky_python",
                    file=logical_path,
                    line=imported.line,
                    snippet=imported.snippet,
                )
            )
    return findings


def _parse_ini_entry_points(path: Path) -> set[str]:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read_string(path.read_text(encoding="utf-8"))
    entries: set[str] = set()
    for section in parser.sections():
        lowered = section.lower()
        if lowered == "options.entry_points":
            for group, value in parser.items(section):
                if group.strip().lower() not in {
                    "console_scripts",
                    "gui_scripts",
                }:
                    continue
                for line in value.splitlines():
                    if not line.strip():
                        continue
                    name, separator, target = line.partition("=")
                    if separator:
                        entries.add(_canonical_entry_point(group, name, target))
        elif lowered in {"console_scripts", "gui_scripts"}:
            entries.update(
                _canonical_entry_point(lowered, name, target)
                for name, target in parser.items(section)
            )
    return entries


def _parse_pyproject_entry_points(path: Path) -> set[str]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    project = data.get("project", {})
    if not isinstance(project, dict):
        return set()
    entries: set[str] = set()
    for group in ("scripts", "gui-scripts"):
        values = project.get(group, {})
        if isinstance(values, dict):
            entries.update(
                _canonical_entry_point(group, str(name), str(target))
                for name, target in values.items()
            )
    return entries


def _parse_setup_py_entry_points(path: Path) -> set[str]:
    source = _read_python(path)
    tree = parse_python(source, filename=path.name)
    entries: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function_name = (
            node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
        )
        if function_name != "setup":
            continue
        for keyword in node.keywords:
            if keyword.arg != "entry_points" or not isinstance(keyword.value, ast.Dict):
                continue
            for key, value in zip(keyword.value.keys, keyword.value.values, strict=True):
                group = key.value if isinstance(key, ast.Constant) else None
                if group not in {"console_scripts", "gui_scripts"}:
                    continue
                if isinstance(value, (ast.List, ast.Tuple)):
                    for item in value.elts:
                        if isinstance(item, ast.Constant) and isinstance(item.value, str):
                            name, separator, target = item.value.partition("=")
                            if separator:
                                entries.add(_canonical_entry_point(group, name, target))
    return entries


def _collect_entry_points(
    extracted: ExtractedArtifact, paths: dict[str, str]
) -> tuple[frozenset[str], str | None]:
    entries: set[str] = set()
    source_paths: list[str] = []
    for logical, actual in sorted(paths.items()):
        logical_path = PurePosixPath(logical)
        name = logical_path.name.lower()
        is_root_build_file = len(logical_path.parts) == 1
        is_entry_points_metadata = name == "entry_points.txt" and any(
            part.lower().endswith((".dist-info", ".egg-info")) for part in logical_path.parts[:-1]
        )
        physical = extracted.root / Path(*PurePosixPath(actual).parts)
        try:
            parsed: set[str] = set()
            if (name == "setup.cfg" and is_root_build_file) or is_entry_points_metadata:
                parsed = _parse_ini_entry_points(physical)
            elif name == "pyproject.toml" and is_root_build_file:
                parsed = _parse_pyproject_entry_points(physical)
            elif name == "setup.py" and is_root_build_file:
                parsed = _parse_setup_py_entry_points(physical)
            if parsed:
                entries.update(parsed)
                source_paths.append(logical)
        except (
            OSError,
            UnicodeError,
            configparser.Error,
            tomllib.TOMLDecodeError,
            SyntaxError,
            AnalysisLimitExceeded,
        ):
            continue
    return frozenset(entries), (sorted(source_paths)[0] if source_paths else None)


def _compare_extracted(sdist: ExtractedArtifact, wheel: ExtractedArtifact) -> list[Finding]:
    findings: list[Finding] = [*sdist.findings, *wheel.findings]
    if not sdist.usable or not wheel.usable:
        return findings

    sdist_paths = _strip_sdist_prefix(sdist.files)
    wheel_paths = _wheel_paths(wheel.files)
    scope_finding = _wheel_scope_finding(wheel, wheel_paths)
    if scope_finding is not None:
        findings.append(scope_finding)
        return findings
    sdist_identity = _read_artifact_identity(sdist, sdist_paths, wheel=False)
    wheel_identity = _read_artifact_identity(wheel, wheel_paths, wheel=True)
    if (
        sdist_identity is not None
        and wheel_identity is not None
        and (
            sdist_identity.name != wheel_identity.name
            or sdist_identity.version != wheel_identity.version
        )
    ):
        findings.append(
            _finding(
                "artifact_identity_mismatch",
                file=wheel_identity.source_path,
                line=None,
                snippet=(
                    f"sdist={sdist_identity.name}=={sdist_identity.version}; "
                    f"wheel={wheel_identity.name}=={wheel_identity.version}"
                ),
            )
        )
        return findings

    requires_dist_finding = _compare_requires_dist(sdist, sdist_paths, wheel, wheel_paths)
    if requires_dist_finding is not None:
        findings.append(requires_dist_finding)

    sdist_entries, sdist_entry_source = _collect_entry_points(sdist, sdist_paths)
    wheel_entries, wheel_entry_source = _collect_entry_points(wheel, wheel_paths)
    if sdist_entries != wheel_entries:
        only_wheel = sorted(wheel_entries - sdist_entries)
        only_sdist = sorted(sdist_entries - wheel_entries)
        summary = f"wheel 전용={only_wheel}; sdist 전용={only_sdist}"
        findings.append(
            _finding(
                "entry_point_mismatch",
                file=wheel_entry_source or sdist_entry_source or "<entry-points>",
                line=None,
                snippet=summary,
            )
        )

    comparable_sdist = {path: actual for path, actual in sdist_paths.items() if not _ignored(path)}
    comparable_wheel = {path: actual for path, actual in wheel_paths.items() if not _ignored(path)}

    for logical_path in sorted(set(comparable_sdist) & set(comparable_wheel)):
        if not logical_path.lower().endswith(".py"):
            continue
        sdist_file = sdist.root / Path(*PurePosixPath(comparable_sdist[logical_path]).parts)
        wheel_file = wheel.root / Path(*PurePosixPath(comparable_wheel[logical_path]).parts)
        try:
            sdist_source = _read_python(sdist_file)
            wheel_source = _read_python(wheel_file)
            left = normalized_ast(sdist_source, logical_path)
            right = normalized_ast(wheel_source, logical_path)
        except AnalysisLimitExceeded as exc:
            findings.append(_limit_failure(logical_path, exc))
            continue
        except (SyntaxError, UnicodeError, LookupError, OSError) as exc:
            findings.append(_parse_failure(logical_path, exc))
            continue
        if left != right:
            findings.append(
                _finding(
                    "python_ast_mismatch",
                    file=logical_path,
                    line=None,
                    snippet="sdist와 wheel의 정규화 AST가 다름",
                )
            )

    wheel_only = sorted(set(comparable_wheel) - set(comparable_sdist))
    for logical_path in wheel_only:
        physical = wheel.root / Path(*PurePosixPath(comparable_wheel[logical_path]).parts)
        lowered = logical_path.lower()
        if lowered.endswith(".py"):
            findings.extend(_wheel_only_python_findings(logical_path, physical))
        elif lowered.endswith(".pth"):
            try:
                for line, snippet in _executable_pth_lines(physical):
                    findings.append(
                        _finding(
                            "wheel_only_executable_pth",
                            file=logical_path,
                            line=line,
                            snippet=snippet,
                        )
                    )
            except OSError as exc:
                findings.append(_error(logical_path, exc))
        elif lowered.endswith(_NATIVE_SUFFIXES):
            findings.append(
                _finding(
                    "wheel_only_native",
                    file=logical_path,
                    line=None,
                    snippet=PurePosixPath(logical_path).name,
                )
            )
    return findings


def compare_sdist_wheel(sdist_path: str, wheel_path: str) -> list[Finding]:
    """F9. Compare one same-release sdist/wheel pair and return evidence only.

    A missing sdist deliberately skips this optional comparison and returns an
    empty list. No artifact code is imported or executed, and no exception is
    exposed to the caller.
    """

    try:
        if not sdist_path or not Path(sdist_path).is_file():
            return []
        with tempfile.TemporaryDirectory(prefix="devpi-guardian-f9-") as temp_dir:
            root = Path(temp_dir)
            sdist = extract_artifact(sdist_path, root / "sdist")
            wheel = extract_artifact(wheel_path, root / "wheel")
            return sort_findings(_compare_extracted(sdist, wheel))
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        return sort_findings([_error(Path(wheel_path).name or "<artifact>", exc)])
