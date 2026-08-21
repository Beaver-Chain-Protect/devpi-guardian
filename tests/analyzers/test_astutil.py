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


def test_network_classification_distinguishes_values_from_real_io() -> None:
    source = """
import httpx
import requests
from urllib import request
from socket import create_connection

httpx.URL("https://example.test")
httpx.Response(200)
httpx.Client()
requests.Request("GET", "https://example.test")
request.Request("https://example.test")
httpx.get("https://example.test")
requests.post("https://example.test")
request.urlopen("https://example.test")
create_connection(("example.test", 443))
"""
    calls, _ = scan_calls(ast.parse(source), source)
    network = [call.qualified_name for call in calls if call.category == "network"]
    assert network == [
        "httpx.get",
        "requests.post",
        "urllib.request.urlopen",
        "socket.create_connection",
    ]


def test_client_io_tracks_bindings_contexts_and_reassignment() -> None:
    source = """
import httpx
import requests
from httpx import Client as HttpClient

direct = httpx.Client().get("https://example.test")
client = HttpClient()
client.post("https://example.test")
with requests.Session() as session:
    session.request("https://example.test")
session = {}
session.get("not-network")
with httpx.AsyncClient() as async_client:
    async_client.stream("GET", "https://example.test")
with httpx.Client() as persistent_client:
    pass
persistent_client.get("https://example.test")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    network = [call for call in calls if call.category == "network"]
    assert [(call.qualified_name, call.line) for call in network] == [
        ("httpx.Client.get", 6),
        ("httpx.Client.post", 8),
        ("requests.Session.request", 10),
        ("httpx.AsyncClient.stream", 14),
        ("httpx.Client.get", 17),
    ]


def test_connection_and_opener_instance_io_is_precise() -> None:
    source = """
import http.client as client_http
import socket
from urllib.request import build_opener

client_http.HTTPConnection("example.test")
connection = client_http.HTTPSConnection("example.test")
connection.connect()
opener = build_opener()
opener.open("https://example.test")
sock = socket.socket()
sock.sendall(b"payload")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    network = [call.qualified_name for call in calls if call.category == "network"]
    assert network == [
        "http.client.HTTPSConnection.connect",
        "urllib.request.build_opener.open",
        "socket.socket.sendall",
    ]


def test_constructor_function_alias_is_tracked() -> None:
    source = """
import httpx
Client = httpx.Client
client = Client()
client.get("https://example.test")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [
        (call.qualified_name, call.category) for call in calls if call.category == "network"
    ] == [("httpx.Client.get", "network")]


def test_custom_traversal_keeps_nested_calls_in_ast_children() -> None:
    source = """
import requests

def typed(value: requests.get("https://example.test")):
    return value

values = {}
values[requests.post("https://example.test")] = 1
class Example(requests.get("https://example.test"), metaclass=requests.post()):
    pass
"""
    calls, _ = scan_calls(ast.parse(source), source)
    network = [(call.qualified_name, call.line) for call in calls if call.category == "network"]
    assert network == [
        ("requests.get", 4),
        ("requests.post", 8),
        ("requests.get", 9),
        ("requests.post", 9),
    ]


def test_module_client_binding_is_visible_in_function_but_parameter_shadows_it() -> None:
    source = """
import httpx
client = httpx.Client()
def send():
    client.get("https://example.test")
def unrelated(client):
    client.get("not-network")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.qualified_name, call.line) for call in calls if call.category == "network"] == [
        ("httpx.Client.get", 5)
    ]


def test_importlib_dynamic_import_is_not_dynamic_exec_but_dangerous_literal_remains() -> None:
    source = """
import importlib
importlib.import_module("pydantic.fields")
importlib.import_module("requests")
"""
    calls, imports = scan_calls(ast.parse(source), source)
    assert [call.qualified_name for call in calls if call.category == "dynamic_exec"] == []
    assert [(item.module, item.line) for item in imports] == [
        ("pydantic.fields", 3),
        ("requests", 4),
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
