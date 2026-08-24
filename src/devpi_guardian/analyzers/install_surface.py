"""F8: inspect installation and import-time attack surfaces in one artifact."""

from __future__ import annotations

import ast
import base64
import binascii
import configparser
import csv
import hashlib
import hmac
import io
import ntpath
import re
import stat
import tempfile
import tokenize
import tomllib
from pathlib import Path, PurePosixPath
from typing import Literal

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
_ArtifactKind = Literal["wheel", "sdist"]
_RECORD_CHUNK_SIZE = 1024 * 1024
_RECORD_SIGNATURE_NAMES = frozenset({"RECORD.jws", "RECORD.p7s"})
_RECORD_SIZE_RE = re.compile(r"[0-9]+\Z")
_RECORD_HASH_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
_WHEEL_SCRIPT_DYNAMIC_IMPORTS = frozenset(
    {"subprocess", "os", "requests", "urllib", "socket", "http", "httpx"}
)


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


def _is_active_sdist_build_file(
    internal_path: str,
    *,
    artifact_kind: _ArtifactKind,
    all_files: tuple[str, ...],
) -> bool:
    """Recognize build metadata at an sdist archive/common project root only."""

    if artifact_kind != "sdist":
        return False
    path = PurePosixPath(internal_path)
    if path.name.lower() not in {"setup.py", "pyproject.toml", "setup.cfg"}:
        return False
    if len(path.parts) == 1:
        return True

    file_parts = [PurePosixPath(candidate).parts for candidate in all_files]
    if not file_parts or not all(len(parts) > 1 for parts in file_parts):
        return False
    common_root = file_parts[0][0].casefold()
    if not all(parts[0].casefold() == common_root for parts in file_parts):
        return False
    return len(path.parts) == 2 and path.parts[0].casefold() == common_root


def _bounded_backend_paths(values: list[str], *, max_items: int = 5) -> str:
    unique = sorted(set(values))
    shown = [value if len(value) <= 24 else value[:23] + "…" for value in unique[:max_items]]
    if len(unique) > max_items:
        shown.append(f"+{len(unique) - max_items}개")
    return repr(shown)


def _is_contained_backend_path(value: str) -> bool:
    """Validate a backend-path without consulting the extracted filesystem."""

    if "\x00" in value:
        return False
    portable = value.replace("\\", "/")
    drive, _ = ntpath.splitdrive(portable)
    if drive or portable.startswith("/"):
        return False

    depth = 0
    for part in portable.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if depth == 0:
                return False
            depth -= 1
        else:
            depth += 1
    return True


def _backend_path_findings(build_system: dict[object, object], internal_path: str) -> list[Finding]:
    if "backend-path" not in build_system:
        return []
    backend_path = build_system["backend-path"]
    if not isinstance(backend_path, list) or any(
        not isinstance(value, str) for value in backend_path
    ):
        return [
            _rule_finding(
                "in_tree_build_backend",
                file=internal_path,
                line=None,
                snippet="invalid backend-path configuration: expected list[str]",
            )
        ]
    if not backend_path:
        return []

    valid = [value for value in backend_path if _is_contained_backend_path(value)]
    unsafe = [value for value in backend_path if not _is_contained_backend_path(value)]
    findings: list[Finding] = []
    if valid:
        findings.append(
            _rule_finding(
                "in_tree_build_backend",
                file=internal_path,
                line=None,
                snippet=f"backend-path={_bounded_backend_paths(valid)}",
            )
        )
    if unsafe:
        findings.append(
            _rule_finding(
                "unsafe_backend_path",
                file=internal_path,
                line=None,
                snippet=f"unsafe backend-path={_bounded_backend_paths(unsafe)}",
            )
        )
    return findings


def _pyproject_findings(path: Path, internal_path: str) -> list[Finding]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        return [_error_finding(internal_path, exc)]

    build_system = data.get("build-system", {})
    if not isinstance(build_system, dict):
        return []
    findings: list[Finding] = []
    findings.extend(_backend_path_findings(build_system, internal_path))
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


def _is_root_setup_py(
    internal_path: str,
    *,
    artifact_kind: _ArtifactKind,
    all_files: tuple[str, ...],
) -> bool:
    """Recognize only the project's root/common-root build setup.py."""
    return _is_active_sdist_build_file(
        internal_path,
        artifact_kind=artifact_kind,
        all_files=all_files,
    )


def _wheel_script_path(internal_path: str) -> bool:
    parts = PurePosixPath(internal_path).parts
    return len(parts) == 3 and parts[0].lower().endswith(".data") and parts[1].lower() == "scripts"


def _script_first_line(path: Path) -> str | None:
    try:
        with path.open("rb") as script_file:
            raw_line = script_file.readline(4096)
    except OSError:
        return None
    try:
        return raw_line.decode("ascii").rstrip("\r\n")
    except UnicodeDecodeError:
        return None


def _is_python_script(path: Path, internal_path: str) -> bool:
    if PurePosixPath(internal_path).suffix.lower() in {".py", ".pyw"}:
        return True

    first_line = _script_first_line(path)
    if first_line in {"#!python", "#!pythonw"}:
        return True
    if first_line is None or not first_line.startswith("#!"):
        return False

    tokens = first_line[2:].strip().split()
    if not tokens:
        return False
    interpreter = tokens[0].replace("\\", "/").rsplit("/", 1)[-1].casefold()
    if interpreter == "env":
        if len(tokens) != 2:
            return False
        interpreter = tokens[1].casefold()
    return interpreter in {"python", "python3", "python.exe"}


def _wheel_install_script_findings(
    path: Path,
    internal_path: str,
) -> list[Finding]:
    findings = [
        _rule_finding(
            "wheel_install_script",
            file=internal_path,
            line=None,
            snippet=PurePosixPath(internal_path).name,
        )
    ]
    if not _is_python_script(path, internal_path):
        return findings

    source, tree, parse_finding = _parse_python(path, internal_path)
    if parse_finding is not None:
        findings.append(parse_finding)
        return findings
    if source is None or tree is None:
        return findings

    flows = find_credential_network_flows(tree, source)
    flow_sinks = {(flow.sink.line, flow.sink.qualified_name) for flow in flows}
    for flow in flows:
        findings.append(
            _rule_finding(
                "wheel_install_script_credential_network",
                file=internal_path,
                line=flow.sink.line,
                snippet=flow.sink.snippet,
                source=flow.source.description,
                sink=flow.sink.qualified_name,
            )
        )

    calls, dynamic_imports = scan_calls(tree, source)
    for call in calls:
        if call.category not in {"process", "network", "dynamic_exec", "file_write"}:
            continue
        if (call.line, call.qualified_name) in flow_sinks:
            continue
        findings.append(
            _rule_finding(
                "wheel_install_script_risky",
                file=internal_path,
                line=call.line,
                snippet=call.snippet,
            )
        )
    for imported in dynamic_imports:
        if imported.module.split(".", 1)[0] not in _WHEEL_SCRIPT_DYNAMIC_IMPORTS:
            continue
        findings.append(
            _rule_finding(
                "wheel_install_script_risky",
                file=internal_path,
                line=imported.line,
                snippet=imported.snippet,
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


def _is_customize_module(
    internal_path: str,
    *,
    artifact_kind: _ArtifactKind,
    all_files: tuple[str, ...],
) -> bool:
    path = PurePosixPath(internal_path)
    if path.name.lower() not in {"sitecustomize.py", "usercustomize.py"}:
        return False

    if artifact_kind == "wheel":
        parts = path.parts
        return len(parts) == 1 or (
            len(parts) == 3
            and parts[0].lower().endswith(".data")
            and parts[1].lower() in {"purelib", "platlib"}
        )

    file_parts = [PurePosixPath(candidate).parts for candidate in all_files]
    common_root = None
    if file_parts and all(len(parts) > 1 for parts in file_parts):
        first = file_parts[0][0]
        if all(parts[0] == first for parts in file_parts):
            common_root = first
    relative_parts = path.parts[1:] if common_root is not None else path.parts
    return relative_parts in {
        ("sitecustomize.py",),
        ("usercustomize.py",),
        ("src", "sitecustomize.py"),
        ("src", "usercustomize.py"),
    }


def _record_path(raw_path: str) -> tuple[str | None, str | None]:
    """Normalize and validate one path from a wheel RECORD row."""

    if not raw_path or "\x00" in raw_path:
        return None, "비어 있거나 NUL 문자를 포함한 RECORD 경로"
    portable = raw_path.replace("\\", "/")
    drive, _ = ntpath.splitdrive(portable)
    if drive or portable.startswith("/"):
        return None, f"절대경로 또는 드라이브 경로: {raw_path}"
    parts = portable.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return None, f"비정규화 또는 상위 경로: {raw_path}"
    if any(":" in part for part in parts):
        return None, f"안전하지 않은 콜론 경로: {raw_path}"
    normalized = "/".join(parts)
    return normalized, None


def _record_finding(file: str, snippet: str) -> Finding:
    return _rule_finding(
        "wheel_record_integrity",
        file=file,
        line=None,
        snippet=snippet,
    )


def _record_hash_spec(value: str) -> tuple[str, bytes] | None:
    algorithm, separator, encoded = value.partition("=")
    if not separator or not algorithm or not encoded or not _RECORD_HASH_RE.fullmatch(encoded):
        return None
    algorithm = algorithm.lower()
    try:
        digest = hashlib.new(algorithm)
    except (ValueError, TypeError):
        return None
    if digest.digest_size < hashlib.sha256().digest_size:
        return None
    if len(encoded) % 4 == 1:
        return None
    try:
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, binascii.Error):
        return None
    if len(decoded) != digest.digest_size:
        return None
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != encoded:
        return None
    return algorithm, decoded


def _record_file_digest(path: Path, algorithm: str) -> bytes:
    digest = hashlib.new(algorithm)
    with path.open("rb") as source:
        while chunk := source.read(_RECORD_CHUNK_SIZE):
            digest.update(chunk)
    return digest.digest()


def _wheel_record_findings(extracted: ExtractedArtifact) -> list[Finding]:
    """Validate a wheel's RECORD against the safely extracted regular files."""

    candidates = sorted(
        path
        for path in extracted.files
        if PurePosixPath(path).name == "RECORD"
        and PurePosixPath(path).parent.name.endswith(".dist-info")
    )
    if not candidates:
        return [
            _rule_finding(
                "wheel_record_missing",
                file="*.dist-info/RECORD",
                line=None,
                snippet="wheel에 RECORD가 없습니다.",
            )
        ]
    if len(candidates) != 1:
        return [
            _record_finding(
                "*.dist-info/RECORD",
                f"RECORD가 여러 개입니다: {', '.join(candidates)}",
            )
        ]

    record_path = candidates[0]
    record_file = extracted.root / Path(*PurePosixPath(record_path).parts)
    findings: list[Finding] = []
    rows: list[tuple[str, str, str]] = []
    try:
        with record_file.open("rb") as raw:
            text = io.TextIOWrapper(raw, encoding="utf-8", newline="")
            try:
                for row in csv.reader(text, strict=True):
                    if len(row) != 3:
                        findings.append(
                            _record_finding(
                                record_path,
                                f"RECORD 행의 열 수가 3이 아닙니다: {len(row)}",
                            )
                        )
                        continue
                    rows.append((row[0], row[1], row[2]))
            finally:
                text.detach()
    except (OSError, UnicodeError, csv.Error, ValueError) as exc:
        findings.append(_record_finding(record_path, f"RECORD 파싱 실패: {type(exc).__name__}"))
        return findings

    extracted_files = set(extracted.files)
    seen: dict[str, tuple[str, str]] = {}
    self_listed = False
    for raw_path, hash_value, size_value in rows:
        normalized, rejection = _record_path(raw_path)
        if rejection:
            findings.append(_record_finding(record_path, rejection))
            continue
        assert normalized is not None
        if normalized in seen:
            findings.append(_record_finding(record_path, f"중복된 RECORD 경로: {normalized}"))
            continue
        seen[normalized] = (hash_value, size_value)
        if normalized == record_path:
            self_listed = True

    if not self_listed:
        findings.append(_record_finding(record_path, "RECORD 자신이 목록에 없습니다."))

    signature_paths = {
        f"{PurePosixPath(record_path).parent.as_posix()}/{name}" for name in _RECORD_SIGNATURE_NAMES
    }
    for path in sorted(extracted_files - set(seen)):
        if path not in signature_paths:
            findings.append(_record_finding(path, f"RECORD에 없는 추출 파일: {path}"))

    for path, (hash_value, size_value) in sorted(seen.items()):
        is_self = path == record_path
        if path not in extracted_files:
            findings.append(_record_finding(path, f"추출되지 않은 RECORD 경로: {path}"))
            continue
        file_path = extracted.root / Path(*PurePosixPath(path).parts)
        try:
            if not stat.S_ISREG(file_path.stat().st_mode):
                findings.append(_record_finding(path, f"일반 파일이 아닌 RECORD 경로: {path}"))
                continue
        except OSError as exc:
            findings.append(_record_finding(path, f"RECORD 파일 확인 실패: {type(exc).__name__}"))
            continue

        if size_value:
            if not _RECORD_SIZE_RE.fullmatch(size_value):
                findings.append(_record_finding(path, f"유효하지 않은 파일 크기: {size_value}"))
            else:
                try:
                    expected_size = int(size_value)
                except (ValueError, OverflowError):
                    findings.append(_record_finding(path, f"유효하지 않은 파일 크기: {size_value}"))
                else:
                    actual_size = file_path.stat().st_size
                    if expected_size != actual_size:
                        findings.append(
                            _record_finding(
                                path,
                                f"파일 크기가 다릅니다: RECORD={expected_size}, 실제={actual_size}",
                            )
                        )

        if not hash_value:
            if not is_self:
                findings.append(_record_finding(path, f"파일 해시가 없습니다: {path}"))
            continue
        hash_spec = _record_hash_spec(hash_value)
        if hash_spec is None:
            findings.append(_record_finding(path, f"유효하지 않은 파일 해시: {path}"))
            continue
        algorithm, expected_digest = hash_spec
        try:
            actual_digest = _record_file_digest(file_path, algorithm)
        except OSError as exc:
            findings.append(_record_finding(path, f"파일 해시 계산 실패: {type(exc).__name__}"))
            continue
        if not hmac.compare_digest(actual_digest, expected_digest):
            findings.append(_record_finding(path, f"파일 해시가 다릅니다: {path}"))
    return findings


def _scan_extracted(
    extracted: ExtractedArtifact,
    *,
    artifact_kind: _ArtifactKind,
) -> list[Finding]:
    findings: list[Finding] = list(extracted.findings)
    if not extracted.usable:
        return findings

    if artifact_kind == "wheel":
        findings.extend(_wheel_record_findings(extracted))

    for internal_path in extracted.files:
        path = extracted.root / Path(*PurePosixPath(internal_path).parts)
        name = PurePosixPath(internal_path).name.lower()

        if name == "setup.py" and _is_root_setup_py(
            internal_path,
            artifact_kind=artifact_kind,
            all_files=extracted.files,
        ):
            source, tree, parse_finding = _parse_python(path, internal_path)
            if parse_finding:
                findings.append(parse_finding)
            elif source is not None and tree is not None:
                findings.extend(_setup_py_findings(internal_path, source, tree))
                findings.extend(_setup_py_entry_point_findings(internal_path, source, tree))
        elif name == "pyproject.toml" and _is_active_sdist_build_file(
            internal_path,
            artifact_kind=artifact_kind,
            all_files=extracted.files,
        ):
            findings.extend(_pyproject_findings(path, internal_path))
            findings.extend(_pyproject_entry_point_findings(path, internal_path))
        elif name == "setup.cfg" and _is_active_sdist_build_file(
            internal_path,
            artifact_kind=artifact_kind,
            all_files=extracted.files,
        ):
            findings.extend(_setup_cfg_findings(path, internal_path))
        elif name == "entry_points.txt" and any(
            part.lower().endswith((".dist-info", ".egg-info"))
            for part in PurePosixPath(internal_path).parts
        ):
            findings.extend(_entry_points_txt_findings(path, internal_path))

        if name.endswith(".pth"):
            findings.extend(_pth_findings(path, internal_path))
        if _is_customize_module(
            internal_path,
            artifact_kind=artifact_kind,
            all_files=extracted.files,
        ):
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

        if artifact_kind == "wheel" and _wheel_script_path(internal_path):
            try:
                regular_file = stat.S_ISREG(path.stat().st_mode)
            except OSError:
                regular_file = False
            if regular_file:
                findings.extend(_wheel_install_script_findings(path, internal_path))

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


def _artifact_kind(path: Path) -> _ArtifactKind:
    name = path.name.lower()
    if name.endswith(".whl"):
        return "wheel"
    if name.endswith((".zip", ".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz", ".tbz2", ".txz")):
        return "sdist"
    raise ValueError("지원 형식은 .whl/.zip/.tar.gz/.tgz/.tar.bz2/.tar.xz/.tbz2/.txz 입니다")


def scan_install_surface(artifact_path: str) -> list[Finding]:
    """F8 trusted direct API; inspect one artifact and return evidence only.

    Use :func:`scan_install_surface_isolated` for untrusted worker input.
    An empty result means "not detected by these rules", not "safe". No
    artifact code is imported or executed.
    """

    try:
        artifact_kind = _artifact_kind(Path(artifact_path))
        with tempfile.TemporaryDirectory(prefix="devpi-guardian-f8-") as temp_dir:
            extracted = extract_artifact(artifact_path, Path(temp_dir) / "artifact")
            return sort_findings(_scan_extracted(extracted, artifact_kind=artifact_kind))
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        return sort_findings([_error_finding(Path(artifact_path).name or "<artifact>", exc)])
