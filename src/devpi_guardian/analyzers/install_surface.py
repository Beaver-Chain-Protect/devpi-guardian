"""F8: inspect installation and import-time attack surfaces in one artifact."""

from __future__ import annotations

import ast
import configparser
import tempfile
import tokenize
import tomllib
from pathlib import Path, PurePosixPath

from .archive import ExtractedArtifact, extract_artifact
from .astutil import (
    AnalysisLimitExceeded,
    build_alias_table,
    find_credential_network_flows,
    parse_python,
    resolve_qualified_name,
    scan_calls,
    source_snippet,
    top_level_calls,
)
from .rules import KNOWN_BUILD_REQUIREMENTS, STANDARD_BUILD_BACKENDS, rule
from .types import Action, Finding, make_finding, sort_findings

_NATIVE_SUFFIXES = (".so", ".dll", ".dylib", ".exe")
_CMDCLASS_KEYS = frozenset({"install", "develop", "build_py"})


def _rule_finding(
    rule_id: str,
    *,
    file: str,
    line: int | None,
    snippet: str,
    action: Action | None = None,
    message: str | None = None,
    source: str | None = None,
    sink: str | None = None,
) -> Finding:
    definition = rule(rule_id)
    return make_finding(
        rule=rule_id,
        action=action or definition.action,
        file=file,
        line=line,
        snippet=snippet,
        message=message or definition.message,
        source=source,
        sink=sink,
    )


def _error_finding(file: str, exc: BaseException) -> Finding:
    return _rule_finding(
        "analyzer_error",
        file=file,
        line=None,
        snippet=f"{type(exc).__name__}: {exc}",
    )


def _read_python(path: Path) -> str:
    with tokenize.open(path) as source_file:
        return source_file.read()


def _parse_python(
    path: Path, internal_path: str
) -> tuple[str | None, ast.Module | None, Finding | None]:
    try:
        source = _read_python(path)
        return source, parse_python(source, filename=internal_path), None
    except AnalysisLimitExceeded as exc:
        return (
            None,
            None,
            _rule_finding(
                "analysis_limit_exceeded",
                file=internal_path,
                line=None,
                snippet=str(exc),
            ),
        )
    except (SyntaxError, UnicodeError, LookupError, OSError) as exc:
        line = getattr(exc, "lineno", None)
        return (
            None,
            None,
            _rule_finding(
                "ast_parse_failed",
                file=internal_path,
                line=line if isinstance(line, int) else None,
                snippet=f"{type(exc).__name__}: {exc}",
            ),
        )


def _iter_constant_dict_keys(node: ast.AST, assignments: dict[str, ast.AST]) -> set[str]:
    if isinstance(node, ast.Name) and node.id in assignments:
        return _iter_constant_dict_keys(assignments[node.id], assignments)
    if not isinstance(node, ast.Dict):
        return set()
    keys: set[str] = set()
    for key in node.keys:
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            keys.add(key.value)
    return keys


def _setup_py_findings(internal_path: str, source: str, tree: ast.Module) -> list[Finding]:
    findings: list[Finding] = []
    calls, dynamic_imports = scan_calls(tree, source)
    for call in calls:
        if call.category == "process":
            findings.append(
                _rule_finding(
                    "setup_py_process",
                    file=internal_path,
                    line=call.line,
                    snippet=call.snippet,
                )
            )
        elif call.category == "network":
            findings.append(
                _rule_finding(
                    "setup_py_network",
                    file=internal_path,
                    line=call.line,
                    snippet=call.snippet,
                )
            )
        elif call.category == "file_write":
            findings.append(
                _rule_finding(
                    "setup_py_file_write",
                    file=internal_path,
                    line=call.line,
                    snippet=call.snippet,
                )
            )

    for imported in dynamic_imports:
        if imported.module == "subprocess" or imported.module == "os":
            findings.append(
                _rule_finding(
                    "setup_py_process",
                    file=internal_path,
                    line=imported.line,
                    snippet=imported.snippet,
                )
            )
        elif imported.module.split(".", 1)[0] in {
            "requests",
            "urllib",
            "socket",
            "http",
            "httpx",
        }:
            findings.append(
                _rule_finding(
                    "setup_py_network",
                    file=internal_path,
                    line=imported.line,
                    snippet=imported.snippet,
                )
            )

    assignments: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = node.value

    aliases = build_alias_table(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        qualified = resolve_qualified_name(node.func, aliases) or ""
        if qualified.rsplit(".", 1)[-1] != "setup":
            continue
        for keyword in node.keywords:
            if keyword.arg != "cmdclass":
                continue
            overridden = _iter_constant_dict_keys(keyword.value, assignments) & _CMDCLASS_KEYS
            if overridden:
                findings.append(
                    _rule_finding(
                        "setup_py_cmdclass",
                        file=internal_path,
                        line=getattr(keyword.value, "lineno", getattr(node, "lineno", 1)),
                        snippet=", ".join(sorted(overridden)),
                    )
                )
    return findings


def _canonical_requirement_name(requirement: str) -> str:
    text = requirement.split(";", 1)[0].strip()
    for delimiter in ("[", "<", ">", "=", "!", "~", " "):
        if delimiter in text:
            text = text.split(delimiter, 1)[0]
    return text.lower().replace("_", "-").replace(".", "-")


def _pyproject_findings(path: Path, internal_path: str) -> list[Finding]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        return [_error_finding(internal_path, exc)]

    build_system = data.get("build-system", {})
    if not isinstance(build_system, dict):
        return []
    findings: list[Finding] = []
    backend = build_system.get("build-backend")
    if isinstance(backend, str) and backend not in STANDARD_BUILD_BACKENDS:
        findings.append(
            _rule_finding(
                "nonstandard_build_backend",
                file=internal_path,
                line=None,
                snippet=backend,
            )
        )
    requirements = build_system.get("requires", [])
    if isinstance(requirements, list):
        for requirement in requirements:
            if not isinstance(requirement, str):
                continue
            package = _canonical_requirement_name(requirement)
            if package and package not in KNOWN_BUILD_REQUIREMENTS:
                findings.append(
                    _rule_finding(
                        "unknown_build_requirement",
                        file=internal_path,
                        line=None,
                        snippet=requirement,
                    )
                )
    return findings


def _read_config(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read_string(path.read_text(encoding="utf-8"))
    return parser


def _setup_cfg_findings(path: Path, internal_path: str) -> list[Finding]:
    try:
        parser = _read_config(path)
    except (OSError, UnicodeError, configparser.Error) as exc:
        return [_error_finding(internal_path, exc)]

    target_section = next(
        (section for section in parser.sections() if section.lower() == "options.entry_points"),
        None,
    )
    if target_section is None:
        return []
    findings = [
        _rule_finding(
            "setup_cfg_entry_points",
            file=internal_path,
            line=None,
            snippet=f"[{target_section}]",
        )
    ]
    for name, value in parser.items(target_section):
        if name.strip().lower() not in {"console_scripts", "gui_scripts"}:
            continue
        for entry in sorted(line.strip() for line in value.splitlines() if line.strip()):
            findings.append(
                _rule_finding(
                    "entry_point",
                    file=internal_path,
                    line=None,
                    snippet=f"{name}: {entry}",
                )
            )
    return findings


def _entry_points_txt_findings(path: Path, internal_path: str) -> list[Finding]:
    try:
        parser = _read_config(path)
    except (OSError, UnicodeError, configparser.Error) as exc:
        return [_error_finding(internal_path, exc)]
    findings: list[Finding] = []
    for section in sorted(parser.sections()):
        if section.lower() not in {"console_scripts", "gui_scripts"}:
            continue
        for name, target in sorted(parser.items(section)):
            findings.append(
                _rule_finding(
                    "entry_point",
                    file=internal_path,
                    line=None,
                    snippet=f"{section}: {name} = {target}",
                )
            )
    return findings


def _pyproject_entry_point_findings(path: Path, internal_path: str) -> list[Finding]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return []
    project = data.get("project", {})
    if not isinstance(project, dict):
        return []
    findings: list[Finding] = []
    for table_name in ("scripts", "gui-scripts"):
        entries = project.get(table_name, {})
        if not isinstance(entries, dict):
            continue
        for name, target in sorted(entries.items()):
            findings.append(
                _rule_finding(
                    "entry_point",
                    file=internal_path,
                    line=None,
                    snippet=f"{table_name}: {name} = {target}",
                )
            )
    return findings


def _setup_py_entry_point_findings(
    internal_path: str, source: str, tree: ast.Module
) -> list[Finding]:
    findings: list[Finding] = []
    aliases = build_alias_table(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        qualified = resolve_qualified_name(node.func, aliases) or ""
        if qualified.rsplit(".", 1)[-1] != "setup":
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
                            findings.append(
                                _rule_finding(
                                    "entry_point",
                                    file=internal_path,
                                    line=getattr(
                                        item,
                                        "lineno",
                                        getattr(node, "lineno", 1),
                                    ),
                                    snippet=f"{group}: {item.value}",
                                )
                            )
    return findings


def _pth_findings(path: Path, internal_path: str) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [_error_finding(internal_path, exc)]
    findings: list[Finding] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.lstrip()
        if stripped == "import" or stripped.startswith(("import ", "import\t")):
            findings.append(
                _rule_finding(
                    "executable_pth",
                    file=internal_path,
                    line=line_number,
                    snippet=raw_line,
                )
            )
    return findings


def _init_findings(internal_path: str, source: str, tree: ast.Module) -> list[Finding]:
    findings: list[Finding] = []
    aliases = build_alias_table(tree)
    flows = find_credential_network_flows(tree, source)
    flow_by_sink = {
        (flow.sink.line, flow.sink.qualified_name): flow
        for flow in flows
        if flow.trigger_line is None
    }
    flow_by_trigger: dict[int, list] = {}
    for flow in flows:
        if flow.trigger_line is not None:
            flow_by_trigger.setdefault(flow.trigger_line, []).append(flow)
    emitted_flows: set[tuple[int, str]] = set()

    for call in top_level_calls(tree):
        qualified = resolve_qualified_name(call.func, aliases) or "<dynamic-call>"
        line = getattr(call, "lineno", 1)
        triggered_flows = flow_by_trigger.get(line, [])
        direct_flow = flow_by_sink.get((line, qualified))
        matched_flows = triggered_flows or ([direct_flow] if direct_flow is not None else [])
        if matched_flows:
            for flow in matched_flows:
                findings.append(
                    _rule_finding(
                        "init_top_level_side_effect",
                        action="DENY",
                        file=internal_path,
                        line=flow.sink.line,
                        snippet=flow.sink.snippet,
                        message="패키지 import 시 credential을 읽어 네트워크 함수로 전달합니다.",
                        source=flow.source.description,
                        sink=flow.sink.qualified_name,
                    )
                )
                emitted_flows.add((flow.sink.line, flow.sink.qualified_name))
        else:
            findings.append(
                _rule_finding(
                    "init_top_level_side_effect",
                    file=internal_path,
                    line=line,
                    snippet=source_snippet(source, call),
                )
            )

    # A flow in a top-level if/try is normally already represented above. Keep
    # this defensive path for unusual AST shapes while avoiding duplicates.
    top_level_lines = {getattr(call, "lineno", 1) for call in top_level_calls(tree)}
    for flow in flows:
        key = (flow.sink.line, flow.sink.qualified_name)
        if (
            flow.trigger_line is None
            and flow.sink.line in top_level_lines
            and key not in emitted_flows
        ):
            findings.append(
                _rule_finding(
                    "init_top_level_side_effect",
                    action="DENY",
                    file=internal_path,
                    line=flow.sink.line,
                    snippet=flow.sink.snippet,
                    message="패키지 import 시 credential을 읽어 네트워크 함수로 전달합니다.",
                    source=flow.source.description,
                    sink=flow.sink.qualified_name,
                )
            )
    return findings


def _scan_extracted(extracted: ExtractedArtifact) -> list[Finding]:
    findings: list[Finding] = list(extracted.findings)
    if not extracted.usable:
        return findings

    for internal_path in extracted.files:
        path = extracted.root / Path(*PurePosixPath(internal_path).parts)
        name = PurePosixPath(internal_path).name.lower()

        if name == "setup.py":
            source, tree, parse_finding = _parse_python(path, internal_path)
            if parse_finding:
                findings.append(parse_finding)
            elif source is not None and tree is not None:
                findings.extend(_setup_py_findings(internal_path, source, tree))
                findings.extend(_setup_py_entry_point_findings(internal_path, source, tree))
        elif name == "pyproject.toml":
            findings.extend(_pyproject_findings(path, internal_path))
            findings.extend(_pyproject_entry_point_findings(path, internal_path))
        elif name == "setup.cfg":
            findings.extend(_setup_cfg_findings(path, internal_path))
        elif name == "entry_points.txt" and any(
            part.lower().endswith((".dist-info", ".egg-info"))
            for part in PurePosixPath(internal_path).parts
        ):
            findings.extend(_entry_points_txt_findings(path, internal_path))

        if name.endswith(".pth"):
            findings.extend(_pth_findings(path, internal_path))
        if name in {"sitecustomize.py", "usercustomize.py"}:
            findings.append(
                _rule_finding(
                    "customize_module",
                    file=internal_path,
                    line=None,
                    snippet=name,
                )
            )
        if name == "__init__.py":
            source, tree, parse_finding = _parse_python(path, internal_path)
            if parse_finding:
                findings.append(parse_finding)
            elif source is not None and tree is not None:
                findings.extend(_init_findings(internal_path, source, tree))

        if internal_path in extracted.executable_files or name.endswith(_NATIVE_SUFFIXES):
            findings.append(
                _rule_finding(
                    "native_or_executable",
                    file=internal_path,
                    line=None,
                    snippet="실행 권한" if internal_path in extracted.executable_files else name,
                )
            )
    return findings


def scan_install_surface(artifact_path: str) -> list[Finding]:
    """F8. Inspect one artifact and return evidence, never a final verdict.

    An empty result means "not detected by these rules", not "safe".
    No artifact code is imported or executed.
    """

    try:
        with tempfile.TemporaryDirectory(prefix="devpi-guardian-f8-") as temp_dir:
            extracted = extract_artifact(artifact_path, Path(temp_dir) / "artifact")
            return sort_findings(_scan_extracted(extracted))
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        return sort_findings([_error_finding(Path(artifact_path).name or "<artifact>", exc)])
