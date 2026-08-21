from __future__ import annotations

import ast

import pytest

import devpi_guardian.analyzers.astutil as astutil_module
from devpi_guardian.analyzers.astutil import (
    AnalysisLimitExceeded,
    build_alias_table,
    parse_python,
    scan_calls,
    top_level_calls,
)


def test_all_import_alias_forms_are_resolved() -> None:
    source = """
import subprocess
import subprocess as sp
from subprocess import run
from subprocess import call as invoke
subprocess.run([])
sp.call([])
run([])
invoke([])
"""
    tree = ast.parse(source)
    aliases = build_alias_table(tree)
    calls, _ = scan_calls(tree, source)

    assert aliases["subprocess"] == "subprocess"
    assert aliases["sp"] == "subprocess"
    assert aliases["run"] == "subprocess.run"
    assert aliases["invoke"] == "subprocess.call"
    assert [call.qualified_name for call in calls] == [
        "subprocess.run",
        "subprocess.call",
        "subprocess.run",
        "subprocess.call",
    ]


def test_comments_and_string_literals_do_not_create_calls() -> None:
    source = '# os.system("bad")\nTEXT = "subprocess.run"\n'
    calls, imports = scan_calls(ast.parse(source), source)
    assert calls == []
    assert imports == []


def test_dynamic_import_string_arguments_are_detected() -> None:
    source = '__import__("subprocess")\nimport importlib\nimportlib.import_module("requests")\n'
    _, imports = scan_calls(ast.parse(source), source)
    assert [(item.module, item.line) for item in imports] == [
        ("subprocess", 1),
        ("requests", 3),
    ]


def test_getattr_with_constant_string_is_resolved_as_process_call() -> None:
    source = "import os\ngetattr(os, 'sys' + 'tem')('echo blocked')\n"
    calls, _ = scan_calls(ast.parse(source), source)
    process_calls = [call for call in calls if call.category == "process"]
    assert [(call.qualified_name, call.line) for call in process_calls] == [("os.system", 2)]


def test_python_source_and_ast_complexity_limits(monkeypatch) -> None:
    monkeypatch.setattr(astutil_module, "MAX_PYTHON_SOURCE_CHARS", 10)
    with pytest.raises(AnalysisLimitExceeded):
        parse_python("value = 12345\n")

    monkeypatch.setattr(astutil_module, "MAX_PYTHON_SOURCE_CHARS", 1_000)
    monkeypatch.setattr(astutil_module, "MAX_AST_NODES", 3)
    with pytest.raises(AnalysisLimitExceeded):
        parse_python("value = 1\n")


def test_safe_init_top_level_constructs_are_whitelisted() -> None:
    source = '''"""module"""
import logging
from typing import TypeVar
__version__ = "1.0"
__all__ = ["x"]
logger = logging.getLogger(__name__)
T = TypeVar("T")
'''
    assert top_level_calls(ast.parse(source)) == []


def test_risky_calls_inside_if_and_try_are_top_level_side_effects() -> None:
    source = """
import os
if True:
    os.system("echo blocked")
try:
    os.system("echo blocked")
except Exception:
    pass
"""
    calls = top_level_calls(ast.parse(source))
    assert [call.lineno for call in calls] == [4, 6]
