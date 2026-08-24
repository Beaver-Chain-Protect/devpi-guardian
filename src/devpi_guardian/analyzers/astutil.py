"""AST-only helpers for import resolution and risky-call analysis."""

from __future__ import annotations

import ast
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import ClassVar

PROCESS_CALLS = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
        "os.system",
        "os.popen",
    }
)
NETWORK_CALLS = frozenset(
    {
        *(
            f"requests.{name}"
            for name in ("request", "get", "post", "put", "patch", "delete", "head", "options")
        ),
        *(
            f"requests.api.{name}"
            for name in ("request", "get", "post", "put", "patch", "delete", "head", "options")
        ),
        *(
            f"httpx.{name}"
            for name in (
                "request",
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "head",
                "options",
                "stream",
            )
        ),
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "socket.create_connection",
    }
)
NETWORK_CONSTRUCTORS = frozenset(
    {
        "httpx.Client",
        "httpx.AsyncClient",
        "requests.Session",
        "urllib.request.build_opener",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
        "socket.socket",
    }
)
NETWORK_INSTANCE_METHODS = {
    "httpx.Client": frozenset(
        {"request", "get", "post", "put", "patch", "delete", "head", "options", "stream", "send"}
    ),
    "httpx.AsyncClient": frozenset(
        {"request", "get", "post", "put", "patch", "delete", "head", "options", "stream", "send"}
    ),
    "requests.Session": frozenset(
        {"request", "get", "post", "put", "patch", "delete", "head", "options", "send"}
    ),
    "urllib.request.build_opener": frozenset({"open"}),
    "http.client.HTTPConnection": frozenset({"request", "connect", "send"}),
    "http.client.HTTPSConnection": frozenset({"request", "connect", "send"}),
    "socket.socket": frozenset({"connect", "connect_ex", "send", "sendall", "sendto"}),
}
DYNAMIC_EXEC_CALLS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "builtins.eval",
        "builtins.exec",
        "builtins.compile",
    }
)
DYNAMIC_IMPORT_CALLS = frozenset({"__import__", "builtins.__import__", "importlib.import_module"})
_ALIASED_ROOTS = frozenset(
    name.split(".", 1)[0]
    for name in (
        *NETWORK_CALLS,
        *NETWORK_CONSTRUCTORS,
        *PROCESS_CALLS,
        "importlib",
        "shutil",
        "Path",
    )
)
SENSITIVE_ENV_MARKERS = (
    "TOKEN",
    "SECRET",
    "KEY",
    "PASSWORD",
    "CREDENTIAL",
    "AWS_",
    "GITHUB_",
    "NPM_",
)
SENSITIVE_PATHS = (
    "~/.ssh",
    "~/.aws",
    "~/.kube",
    "~/.netrc",
    "~/.docker/config.json",
    "~/.config/gh",
    "~/.pypirc",
    "~/.git-credentials",
)
MAX_PYTHON_SOURCE_CHARS = 10_000_000
MAX_AST_NODES = 250_000


class AnalysisLimitExceeded(ValueError):
    """Raised internally when deterministic AST resource bounds are exceeded."""


def parse_python(source: str, filename: str = "<artifact>") -> ast.Module:
    """Parse Python source while bounding input size and AST node count."""

    if len(source) > MAX_PYTHON_SOURCE_CHARS:
        raise AnalysisLimitExceeded(
            f"소스 길이 {len(source):,}자가 한도 {MAX_PYTHON_SOURCE_CHARS:,}자를 초과"
        )
    tree = ast.parse(source, filename=filename)
    for count, _ in enumerate(ast.walk(tree), start=1):
        if count > MAX_AST_NODES:
            raise AnalysisLimitExceeded(f"AST 노드 수가 한도 {MAX_AST_NODES:,}개를 초과")
    return tree


@dataclass(frozen=True)
class CallSite:
    qualified_name: str
    category: str | None
    line: int
    snippet: str
    node: ast.Call


@dataclass(frozen=True)
class DynamicImport:
    module: str
    line: int
    snippet: str


@dataclass(frozen=True)
class CredentialAccess:
    description: str
    line: int
    snippet: str
    node: ast.AST


@dataclass(frozen=True)
class CredentialFlow:
    source: CredentialAccess
    sink: CallSite
    trigger_line: int | None = None
    trigger_snippet: str | None = None


class ImportAliasVisitor(ast.NodeVisitor):
    """Collect visible import names and their fully-qualified targets."""

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for imported in node.names:
            if imported.asname:
                self.aliases[imported.asname] = imported.name
            else:
                bound_name = imported.name.split(".", 1)[0]
                self.aliases[bound_name] = bound_name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            for imported in node.names:
                if imported.name != "*":
                    visible = imported.asname or imported.name
                    self.aliases[visible] = f".{imported.name}"
            return
        for imported in node.names:
            if imported.name == "*":
                continue
            visible = imported.asname or imported.name
            self.aliases[visible] = f"{node.module}.{imported.name}"
        self.generic_visit(node)


def build_alias_table(tree: ast.AST) -> dict[str, str]:
    visitor = ImportAliasVisitor()
    visitor.visit(tree)
    return dict(sorted(visitor.aliases.items()))


def resolve_qualified_name(node: ast.AST, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = resolve_qualified_name(node.value, aliases)
        if parent:
            return f"{parent}.{node.attr}"
    if isinstance(node, ast.Call):
        function = resolve_qualified_name(node.func, aliases)
        if function in {"getattr", "builtins.getattr"} and len(node.args) >= 2:
            parent = resolve_qualified_name(node.args[0], aliases)
            attribute = constant_string(node.args[1])
            if parent and attribute:
                return f"{parent}.{attribute}"
        if function == "__import__" and node.args:
            return constant_string(node.args[0])
    return None


def _scoped_resolve_qualified_name(node: ast.AST, aliases: dict[str, str]) -> str | None:
    """Resolve known risky roots only when an active import binds that root."""

    reference = _reference_path(node)
    if reference is not None and reference.split(".", 1)[0] in _ALIASED_ROOTS:
        root = reference.split(".", 1)[0]
        if root not in aliases:
            return None
    return resolve_qualified_name(node, aliases)


def _binding_names(target: ast.AST) -> set[str]:
    """Return names bound by a plain assignment target."""

    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for element in target.elts:
            names.update(_binding_names(element))
        return names
    if isinstance(target, ast.Starred):
        return _binding_names(target.value)
    return set()


class _LocalBinderVisitor(ast.NodeVisitor):
    """Collect Python-local binders without entering nested scopes."""

    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for imported in node.names:
            self.names.add(imported.asname or imported.name.split(".", 1)[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for imported in node.names:
            if imported.name != "*":
                self.names.add(imported.asname or imported.name)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self.names.update(_binding_names(target))
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.names.update(_binding_names(node.target))
        if node.annotation is not None:
            self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.names.update(_binding_names(node.target))
        self.visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.names.update(_binding_names(node.target))
        self.visit(node.value)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            self.names.update(_binding_names(target))

    def visit_For(self, node: ast.For) -> None:
        self.names.update(_binding_names(node.target))
        self.visit(node.iter)
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self.names.update(_binding_names(item.optional_vars))
        for statement in node.body:
            self.visit(statement)

    visit_AsyncWith = visit_With

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        if node.name is not None:
            self.names.add(node.name)
        for statement in node.body:
            self.visit(statement)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        self.visit(node.iter)
        for condition in node.ifs:
            self.visit(condition)


def _local_binder_names(body: Iterable[ast.stmt]) -> set[str]:
    visitor = _LocalBinderVisitor()
    for statement in body:
        visitor.visit(statement)
    return visitor.names


def _local_binder_names_expr(expression: ast.AST) -> set[str]:
    visitor = _LocalBinderVisitor()
    visitor.visit(expression)
    return visitor.names


def _reference_path(node: ast.AST) -> str | None:
    """Return a stable Name/Attribute reference path, if ``node`` has one."""

    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _reference_path(node.value)
        if parent is not None:
            return f"{parent}.{node.attr}"
    return None


def constant_string(node: ast.AST) -> str | None:
    """Resolve string literals and simple literal concatenation without eval."""

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = constant_string(node.left)
        right = constant_string(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def source_snippet(source: str, node: ast.AST) -> str:
    segment = ast.get_source_segment(source, node)
    if segment:
        return " ".join(segment.split())[:200]
    lines = source.splitlines()
    line = getattr(node, "lineno", None)
    if isinstance(line, int) and 1 <= line <= len(lines):
        return lines[line - 1].strip()[:200]
    return ""


def _open_is_write(call: ast.Call) -> bool:
    mode_node: ast.AST | None = None
    if len(call.args) >= 2:
        mode_node = call.args[1]
    for keyword in call.keywords:
        if keyword.arg == "mode":
            mode_node = keyword.value
    mode = constant_string(mode_node) if mode_node is not None else None
    return bool(mode and any(flag in mode for flag in ("w", "a", "x", "+")))


def categorize_call(
    call: ast.Call,
    aliases: dict[str, str],
    instance_bindings: dict[str, str] | None = None,
    constructor_bindings: dict[str, str] | None = None,
    callable_aliases: dict[str, str] | None = None,
) -> tuple[str | None, str]:
    qualified = _qualified_call_name(
        call,
        aliases,
        instance_bindings or {},
        constructor_bindings,
        callable_aliases or {},
    )
    if qualified in PROCESS_CALLS or qualified.startswith(("os.spawn", "os.exec")):
        return "process", qualified
    if qualified in NETWORK_CALLS or _is_network_instance_call(qualified):
        return "network", qualified
    if qualified in DYNAMIC_EXEC_CALLS:
        return "dynamic_exec", qualified
    if qualified in {"open", "builtins.open"} and _open_is_write(call):
        return "file_write", qualified
    if qualified.endswith((".write_text", ".write_bytes")) or qualified.startswith("shutil."):
        return "file_write", qualified
    if qualified in {"os.getenv", "os.environ.get"}:
        return "credential_env", qualified
    if qualified in {"open", "builtins.open", "pathlib.Path", "Path"} and any(
        literal is not None and any(path in literal for path in SENSITIVE_PATHS)
        for literal in (constant_string(argument) for argument in call.args)
    ):
        return "credential_path", qualified
    return None, qualified


def _is_network_instance_call(qualified: str) -> bool:
    constructor, separator, method = qualified.rpartition(".")
    return bool(separator and method in NETWORK_INSTANCE_METHODS.get(constructor, ()))


def _constructor_kind(
    node: ast.AST,
    aliases: dict[str, str],
    constructor_bindings: dict[str, str] | None = None,
) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    qualified = _scoped_resolve_qualified_name(node.func, aliases)
    if isinstance(node.func, ast.Name) and constructor_bindings:
        qualified = constructor_bindings.get(node.func.id, qualified)
    return qualified if qualified in NETWORK_CONSTRUCTORS else None


def _qualified_call_name(
    call: ast.Call,
    aliases: dict[str, str],
    instance_bindings: dict[str, str],
    constructor_bindings: dict[str, str] | None = None,
    callable_aliases: dict[str, str] | None = None,
) -> str:
    callable_aliases = callable_aliases or {}
    callable_identity = _callable_identity(
        call.func,
        aliases,
        instance_bindings,
        constructor_bindings,
        callable_aliases,
    )
    if callable_identity is not None:
        return callable_identity
    if isinstance(call.func, ast.Attribute):
        reference = _reference_path(call.func.value)
        kind = instance_bindings.get(reference) if reference is not None else None
        if kind is not None:
            return f"{kind}.{call.func.attr}"
    qualified = _scoped_resolve_qualified_name(call.func, aliases)
    if qualified is not None:
        return qualified
    if not isinstance(call.func, ast.Attribute):
        return "<dynamic-call>"
    base = call.func.value
    kind = _constructor_kind(base, aliases, constructor_bindings)
    if kind is not None:
        return f"{kind}.{call.func.attr}"
    return "<dynamic-call>"


def _callable_identity(
    node: ast.AST,
    aliases: dict[str, str],
    instance_bindings: dict[str, str],
    constructor_bindings: dict[str, str] | None,
    callable_aliases: dict[str, str],
) -> str | None:
    """Resolve a callable assignment RHS without treating arbitrary names as known."""

    reference = _reference_path(node)
    if reference is not None:
        identity = callable_aliases.get(reference)
        if identity is not None:
            return identity
    if isinstance(node, ast.Name):
        identity = callable_aliases.get(node.id)
        if identity is not None:
            return identity
    if isinstance(node, ast.Attribute):
        reference = _reference_path(node.value)
        kind = instance_bindings.get(reference) if reference is not None else None
        if kind is not None:
            return f"{kind}.{node.attr}"
        kind = _constructor_kind(node.value, aliases, constructor_bindings)
        if kind is not None:
            return f"{kind}.{node.attr}"
    if reference is None:
        return None
    root = reference.split(".", 1)[0]
    if root not in aliases:
        return None
    return _scoped_resolve_qualified_name(node, aliases)


def _target_reference_paths(target: ast.AST) -> list[str]:
    if isinstance(target, (ast.Tuple, ast.List)):
        paths: list[str] = []
        for element in target.elts:
            paths.extend(_target_reference_paths(element))
        return paths
    path = _reference_path(target)
    return [path] if path is not None else []


def _attribute_target_paths(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Attribute):
        path = _reference_path(target)
        return [path] if path is not None else []
    if isinstance(target, (ast.Tuple, ast.List)):
        paths: list[str] = []
        for element in target.elts:
            paths.extend(_attribute_target_paths(element))
        return paths
    if isinstance(target, ast.Starred):
        return _attribute_target_paths(target.value)
    return []


def _clear_reference_path(bindings: dict[str, str], path: str) -> None:
    for known_path in list(bindings):
        if known_path == path or known_path.startswith(f"{path}."):
            bindings.pop(known_path, None)


def _instance_method_receiver(
    node: ast.FunctionDef | ast.AsyncFunctionDef, aliases: dict[str, str]
) -> str | None:
    decorators = {resolve_qualified_name(item, aliases) for item in node.decorator_list}
    if "staticmethod" in decorators or "builtins.staticmethod" in decorators:
        return None
    if "classmethod" in decorators or "builtins.classmethod" in decorators:
        return None
    positional = [*node.args.posonlyargs, *node.args.args]
    return positional[0].arg if positional else None


def _relative_receiver_path(path: str, receiver: str) -> str | None:
    prefix = f"{receiver}."
    if path.startswith(prefix):
        return path.removeprefix(prefix)
    return None


class _ClassAttributeCollector(ast.NodeVisitor):
    """Collect explicit receiver-attribute writes for one class method."""

    def __init__(
        self,
        receiver: str,
        aliases: dict[str, str],
        module_instances: dict[str, str],
        module_constructors: dict[str, str],
        initial: dict[str, str] | None = None,
        callable_initial: dict[str, str] | None = None,
        local_names: Iterable[str] = (),
    ) -> None:
        self.receiver = receiver
        self.aliases = dict(aliases)
        self.module_instances = dict(module_instances)
        self.constructors = dict(module_constructors)
        self.known: dict[str, str] = {}
        self.receiver_known = dict(initial or {})
        self.events: list[tuple[str, str | None]] = []
        self.callable_known: dict[str, str] = {}
        self.receiver_callable_known = dict(callable_initial or {})
        self.callable_events: list[tuple[str, str | None]] = []
        for name in local_names:
            self._clear_local_name(name)

    def _clear_local_name(self, name: str) -> None:
        self.aliases.pop(name, None)
        _clear_reference_path(self.module_instances, name)
        _clear_reference_path(self.constructors, name)
        _clear_reference_path(self.known, name)
        _clear_reference_path(self.callable_known, name)

    def _clear_target_state(self, target: ast.AST) -> None:
        for name in _binding_names(target):
            self._clear_local_name(name)

    def _invalidate_alias_target(self, target: ast.AST) -> None:
        for name in _binding_names(target):
            self.aliases.pop(name, None)

    def visit_Import(self, node: ast.Import) -> None:
        for imported in node.names:
            visible = imported.asname or imported.name.split(".", 1)[0]
            self._clear_local_name(visible)
            self.aliases[visible] = imported.name if imported.asname else visible

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            for imported in node.names:
                if imported.name != "*":
                    visible = imported.asname or imported.name
                    self._clear_local_name(visible)
                    self.aliases[visible] = f".{imported.name}"
            return
        for imported in node.names:
            if imported.name != "*":
                visible = imported.asname or imported.name
                self._clear_local_name(visible)
                self.aliases[visible] = f"{node.module}.{imported.name}"

    def _kind(self, value: ast.AST | None) -> str | None:
        if value is None:
            return None
        kind = _constructor_kind(value, self.aliases, self.constructors)
        reference = _reference_path(value)
        if kind is None and reference is not None:
            kind = self.known.get(reference)
            if kind is None:
                kind = self.module_instances.get(reference)
            if kind is None:
                relative = _relative_receiver_path(reference, self.receiver)
                if relative is not None:
                    kind = self.receiver_known.get(relative)
        return kind

    def _callable_kind(self, value: ast.AST | None) -> str | None:
        if value is None:
            return None
        instances = dict(self.module_instances)
        instances.update(self.known)
        instances.update(
            {f"{self.receiver}.{path}": kind for path, kind in self.receiver_known.items()}
        )
        aliases = dict(self.callable_known)
        aliases.update(
            {f"{self.receiver}.{path}": kind for path, kind in self.receiver_callable_known.items()}
        )
        return _callable_identity(value, self.aliases, instances, self.constructors, aliases)

    def _record(self, target: ast.AST, value: ast.AST | None) -> None:
        kind = self._kind(value)
        for path in _target_reference_paths(target):
            relative = _relative_receiver_path(path, self.receiver)
            binding_map = self.receiver_known if relative is not None else self.known
            binding_path = relative if relative is not None else path
            descendants = [
                known_path
                for known_path in binding_map
                if known_path.startswith(f"{binding_path}.")
            ]
            for descendant in descendants:
                if relative is not None:
                    self.events.append((descendant, None))
            _clear_reference_path(binding_map, binding_path)
            if relative is not None:
                self.events.append((relative, kind))
                if kind is None:
                    self.receiver_known.pop(relative, None)
                else:
                    self.receiver_known[relative] = kind
            elif kind is not None:
                self.known[path] = kind

    def _record_callable(self, target: ast.AST, identity: str | None) -> None:
        for path in _target_reference_paths(target):
            relative = _relative_receiver_path(path, self.receiver)
            binding_map = (
                self.receiver_callable_known if relative is not None else self.callable_known
            )
            binding_path = relative if relative is not None else path
            descendants = [
                known_path
                for known_path in binding_map
                if known_path.startswith(f"{binding_path}.")
            ]
            for descendant in descendants:
                if relative is not None:
                    self.callable_events.append((descendant, None))
            _clear_reference_path(binding_map, binding_path)
            if relative is not None:
                self.callable_events.append((relative, identity))
                if identity is None:
                    self.receiver_callable_known.pop(relative, None)
                else:
                    self.receiver_callable_known[relative] = identity
            elif identity is not None:
                self.callable_known[path] = identity

    def _update_constructor_alias(self, target: ast.AST, value: ast.AST) -> None:
        if not isinstance(target, ast.Name):
            return
        qualified = _scoped_resolve_qualified_name(value, self.aliases)
        if isinstance(value, ast.Name):
            qualified = self.constructors.get(value.id, qualified)
        if qualified in NETWORK_CONSTRUCTORS:
            self.constructors[target.id] = qualified
        else:
            self.constructors.pop(target.id, None)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        identity = self._callable_kind(node.value)
        for target in node.targets:
            self._clear_target_state(target)
            self._update_constructor_alias(target, node.value)
            self._record(target, node.value)
            self._record_callable(target, identity)
            self._invalidate_alias_target(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.annotation is not None:
            self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
            identity = self._callable_kind(node.value)
            self._clear_target_state(node.target)
            self._update_constructor_alias(node.target, node.value)
        else:
            identity = None
            self._clear_target_state(node.target)
        self._record(node.target, node.value)
        self._record_callable(node.target, identity)
        self._invalidate_alias_target(node.target)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        identity = self._callable_kind(node.value)
        self._clear_target_state(node.target)
        self._update_constructor_alias(node.target, node.value)
        self._record(node.target, node.value)
        self._record_callable(node.target, identity)
        self._invalidate_alias_target(node.target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.target)
        self.visit(node.value)
        self._record(node.target, None)
        self._record_callable(node.target, None)
        self._invalidate_alias_target(node.target)
        self._clear_target_state(node.target)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            self._record(target, None)
            self._record_callable(target, None)
            self._invalidate_alias_target(target)
            self._clear_target_state(target)

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self._record(node.target, None)
        self._record_callable(node.target, None)
        self._invalidate_alias_target(node.target)
        self._clear_target_state(node.target)
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._clear_target_state(item.optional_vars)
                self._record(item.optional_vars, item.context_expr)
                self._record_callable(item.optional_vars, None)
                self._invalidate_alias_target(item.optional_vars)
        for statement in node.body:
            self.visit(statement)

    visit_AsyncWith = visit_With

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        if node.name is not None:
            self._clear_local_name(node.name)
        for statement in node.body:
            self.visit(statement)
        if node.name is not None:
            self._clear_local_name(node.name)

    def _visit_comprehension(
        self, generators: list[ast.comprehension], expressions: list[ast.AST]
    ) -> None:
        aliases = self.aliases
        module_instances = self.module_instances
        constructors = self.constructors
        known = self.known
        receiver_known = self.receiver_known
        callable_known = self.callable_known
        receiver_callable_known = self.receiver_callable_known
        receiver_mutations = [
            path for generator in generators for path in _attribute_target_paths(generator.target)
        ]
        for generator in generators:
            self.visit(generator.iter)
            self.aliases = dict(self.aliases)
            self.module_instances = dict(self.module_instances)
            self.constructors = dict(self.constructors)
            self.known = dict(self.known)
            self.receiver_known = dict(self.receiver_known)
            self.callable_known = dict(self.callable_known)
            self.receiver_callable_known = dict(self.receiver_callable_known)
            self._record(generator.target, None)
            self._record_callable(generator.target, None)
            self._invalidate_alias_target(generator.target)
            self._clear_target_state(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        for expression in expressions:
            self.visit(expression)
        receiver_after = self.receiver_known
        self.aliases = aliases
        self.module_instances = module_instances
        self.constructors = constructors
        self.known = known
        self.receiver_known = receiver_known
        receiver_callable_after = self.receiver_callable_known
        self.callable_known = callable_known
        self.receiver_callable_known = receiver_callable_known
        for path in receiver_mutations:
            relative = _relative_receiver_path(path, self.receiver)
            if relative is None:
                continue
            _clear_reference_path(self.receiver_known, relative)
            for known_path, kind in receiver_after.items():
                if known_path == relative or known_path.startswith(f"{relative}."):
                    self.receiver_known[known_path] = kind
            _clear_reference_path(self.receiver_callable_known, relative)
            for known_path, kind in receiver_callable_after.items():
                if known_path == relative or known_path.startswith(f"{relative}."):
                    self.receiver_callable_known[known_path] = kind

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node.generators, [node.key, node.value])

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return


def _class_attribute_summary(
    node: ast.ClassDef,
    aliases: dict[str, str],
    module_instances: dict[str, str],
    module_constructors: dict[str, str],
) -> tuple[
    dict[str, str],
    dict[str, frozenset[int]],
    dict[str, str],
    dict[str, frozenset[int]],
]:
    methods = [
        child
        for child in node.body
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
        and _instance_method_receiver(child, aliases) is not None
    ]
    direct: dict[str, set[str]] = {}
    direct_callable: dict[str, set[str]] = {}
    for method in methods:
        receiver = _instance_method_receiver(method, aliases)
        assert receiver is not None
        local_names = {
            argument.arg
            for argument in [
                *method.args.posonlyargs,
                *method.args.args,
                *method.args.kwonlyargs,
            ]
        }
        if method.args.vararg:
            local_names.add(method.args.vararg.arg)
        if method.args.kwarg:
            local_names.add(method.args.kwarg.arg)
        local_names.update(_local_binder_names(method.body))
        collector = _ClassAttributeCollector(
            receiver, aliases, module_instances, module_constructors, local_names=local_names
        )
        for statement in method.body:
            collector.visit(statement)
        for path, kind in collector.events:
            if kind is not None:
                direct.setdefault(path, set()).add(kind)
        for path, identity in collector.callable_events:
            if identity is not None:
                direct_callable.setdefault(path, set()).add(identity)

    provisional = {path: next(iter(kinds)) for path, kinds in direct.items() if len(kinds) == 1}
    provisional_callable = {
        path: next(iter(kinds)) for path, kinds in direct_callable.items() if len(kinds) == 1
    }
    all_events: dict[str, list[str | None]] = {}
    event_methods: dict[str, set[int]] = {}
    all_callable_events: dict[str, list[str | None]] = {}
    callable_event_methods: dict[str, set[int]] = {}
    for method in methods:
        receiver = _instance_method_receiver(method, aliases)
        assert receiver is not None
        local_names = {
            argument.arg
            for argument in [
                *method.args.posonlyargs,
                *method.args.args,
                *method.args.kwonlyargs,
            ]
        }
        if method.args.vararg:
            local_names.add(method.args.vararg.arg)
        if method.args.kwarg:
            local_names.add(method.args.kwarg.arg)
        local_names.update(_local_binder_names(method.body))
        collector = _ClassAttributeCollector(
            receiver,
            aliases,
            module_instances,
            module_constructors,
            initial=provisional,
            callable_initial=provisional_callable,
            local_names=local_names,
        )
        for statement in method.body:
            collector.visit(statement)
        for path, kind in collector.events:
            all_events.setdefault(path, []).append(kind)
            event_methods.setdefault(path, set()).add(id(method))
        for path, identity in collector.callable_events:
            all_callable_events.setdefault(path, []).append(identity)
            callable_event_methods.setdefault(path, set()).add(id(method))

    summary = {
        path: kinds[0]
        for path, kinds in all_events.items()
        if kinds and None not in kinds and len(set(kinds)) == 1
    }
    writers = {path: frozenset(event_methods[path]) for path in summary}
    callable_summary = {
        path: identities[0]
        for path, identities in all_callable_events.items()
        if identities and None not in identities and len(set(identities)) == 1
    }
    callable_writers = {path: frozenset(callable_event_methods[path]) for path in callable_summary}
    return summary, writers, callable_summary, callable_writers


class _CallVisitor(ast.NodeVisitor):
    def __init__(self, aliases: dict[str, str], source: str) -> None:
        self.aliases = aliases
        self.source = source
        self.calls: list[CallSite] = []
        self.dynamic_imports: list[DynamicImport] = []
        self.credential_subscripts: list[ast.Subscript] = []
        self._instance_scopes: list[dict[str, str]] = [{}]
        self._constructor_scopes: list[dict[str, str]] = [{}]
        self._alias_scopes: list[dict[str, str]] = [{}]
        self._callable_scopes: list[dict[str, str]] = [{}]
        self._class_summaries: dict[ast.ClassDef, dict[str, str]] = {}
        self._class_summary_writers: dict[ast.ClassDef, dict[str, frozenset[int]]] = {}
        self._class_callable_summaries: dict[ast.ClassDef, dict[str, str]] = {}
        self._class_callable_summary_writers: dict[ast.ClassDef, dict[str, frozenset[int]]] = {}
        self._class_stack: list[ast.ClassDef] = []
        self._class_alias_bases: list[dict[str, str]] = []
        self._class_callable_bases: list[dict[str, str]] = []
        self._class_function_depths: list[int] = []
        self._function_depth = 0

    @property
    def active_aliases(self) -> dict[str, str]:
        return self._alias_scopes[-1]

    def _invalidate_alias_target(self, target: ast.AST) -> None:
        for name in _binding_names(target):
            self.active_aliases.pop(name, None)
        for path in _target_reference_paths(target):
            _clear_reference_path(self.callable_aliases, path)

    def _bind_import(self, node: ast.Import) -> None:
        for imported in node.names:
            visible = imported.asname or imported.name.split(".", 1)[0]
            _clear_reference_path(self.instance_bindings, visible)
            _clear_reference_path(self.constructor_bindings, visible)
            _clear_reference_path(self.callable_aliases, visible)
            self.active_aliases[visible] = imported.name if imported.asname else visible

    def _bind_import_from(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            for imported in node.names:
                if imported.name != "*":
                    visible = imported.asname or imported.name
                    _clear_reference_path(self.instance_bindings, visible)
                    _clear_reference_path(self.constructor_bindings, visible)
                    _clear_reference_path(self.callable_aliases, visible)
                    self.active_aliases[visible] = f".{imported.name}"
            return
        for imported in node.names:
            if imported.name != "*":
                visible = imported.asname or imported.name
                _clear_reference_path(self.instance_bindings, visible)
                _clear_reference_path(self.constructor_bindings, visible)
                _clear_reference_path(self.callable_aliases, visible)
                self.active_aliases[visible] = f"{node.module}.{imported.name}"

    def visit_Import(self, node: ast.Import) -> None:
        self._bind_import(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self._bind_import_from(node)

    @property
    def instance_bindings(self) -> dict[str, str]:
        return self._instance_scopes[-1]

    @property
    def constructor_bindings(self) -> dict[str, str]:
        return self._constructor_scopes[-1]

    @property
    def callable_aliases(self) -> dict[str, str]:
        return self._callable_scopes[-1]

    def _bind_target(
        self,
        target: ast.AST,
        kind: str | None,
        constructor: str | None = None,
    ) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind_target(element, None)
            return
        path = _reference_path(target)
        if path is None:
            return
        if constructor is not None and isinstance(target, ast.Name):
            _clear_reference_path(self.instance_bindings, path)
            self.constructor_bindings[path] = constructor
        elif kind is None:
            _clear_reference_path(self.instance_bindings, path)
            self.constructor_bindings.pop(path, None)
        else:
            _clear_reference_path(self.instance_bindings, path)
            self.instance_bindings[path] = kind
            self.constructor_bindings.pop(path, None)

    def _bind_assignment(self, value: ast.AST, targets: list[ast.AST]) -> None:
        kind = _constructor_kind(value, self.active_aliases, self.constructor_bindings)
        reference = _reference_path(value)
        if kind is None and reference is not None:
            kind = self.instance_bindings.get(reference)
        constructor = None
        if not isinstance(value, ast.Call):
            qualified = _scoped_resolve_qualified_name(value, self.active_aliases)
            if isinstance(value, ast.Name):
                qualified = self.constructor_bindings.get(value.id, qualified)
            if qualified in NETWORK_CONSTRUCTORS:
                constructor = qualified
        for target in targets:
            self._bind_target(target, kind, constructor)

    def _bind_callable_assignment(
        self,
        value: ast.AST,
        targets: list[ast.AST],
        identity: str | None = None,
    ) -> None:
        if identity is None:
            identity = _callable_identity(
                value,
                self.active_aliases,
                self.instance_bindings,
                self.constructor_bindings,
                self.callable_aliases,
            )
        if identity is None:
            return
        for target in targets:
            for path in _target_reference_paths(target):
                self.callable_aliases[path] = identity

    def _visit_scope_body(
        self,
        body: list[ast.stmt],
        *,
        clear_names: Iterable[str] = (),
        instance_seed: dict[str, str] | None = None,
        alias_seed: dict[str, str] | None = None,
        callable_seed: dict[str, str] | None = None,
    ) -> None:
        instances = dict(self.instance_bindings)
        constructors = dict(self.constructor_bindings)
        for name in clear_names:
            _clear_reference_path(instances, name)
            _clear_reference_path(constructors, name)
        if instance_seed:
            instances.update(instance_seed)
        aliases = dict(self.active_aliases if alias_seed is None else alias_seed)
        for name in clear_names:
            aliases.pop(name, None)
        self._instance_scopes.append(instances)
        self._constructor_scopes.append(constructors)
        self._alias_scopes.append(aliases)
        callable_aliases = dict(self.callable_aliases if callable_seed is None else {})
        for name in clear_names:
            _clear_reference_path(callable_aliases, name)
        if callable_seed:
            callable_aliases.update(callable_seed)
        self._callable_scopes.append(callable_aliases)
        for statement in body:
            self.visit(statement)
        self._callable_scopes.pop()
        self._alias_scopes.pop()
        self._instance_scopes.pop()
        self._constructor_scopes.pop()

    def _visit_scope_expr(self, expression: ast.AST, *, clear_names: Iterable[str] = ()) -> None:
        instances = dict(self.instance_bindings)
        constructors = dict(self.constructor_bindings)
        for name in clear_names:
            _clear_reference_path(instances, name)
            _clear_reference_path(constructors, name)
        self._instance_scopes.append(instances)
        self._constructor_scopes.append(constructors)
        aliases = dict(self.active_aliases)
        for name in clear_names:
            aliases.pop(name, None)
        self._alias_scopes.append(aliases)
        callable_aliases = dict(self.callable_aliases)
        for name in clear_names:
            _clear_reference_path(callable_aliases, name)
        self._callable_scopes.append(callable_aliases)
        self.visit(expression)
        self._callable_scopes.pop()
        self._alias_scopes.pop()
        self._instance_scopes.pop()
        self._constructor_scopes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for argument in [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]:
            if argument.annotation is not None:
                self.visit(argument.annotation)
        if node.args.vararg and node.args.vararg.annotation is not None:
            self.visit(node.args.vararg.annotation)
        if node.args.kwarg and node.args.kwarg.annotation is not None:
            self.visit(node.args.kwarg.annotation)
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        if node.returns is not None:
            self.visit(node.returns)
        self.active_aliases.pop(node.name, None)
        self.callable_aliases.pop(node.name, None)
        parameter_names = {
            argument.arg
            for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        }
        if node.args.vararg:
            parameter_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            parameter_names.add(node.args.kwarg.arg)
        local_names = set(parameter_names)
        local_names.update(_local_binder_names(node.body))
        instance_seed: dict[str, str] = {}
        if self._class_stack and self._function_depth == self._class_function_depths[-1]:
            receiver = _instance_method_receiver(node, self.active_aliases)
            summary = self._class_summaries.get(self._class_stack[-1], {})
            writers = self._class_summary_writers.get(self._class_stack[-1], {})
            callable_summary = self._class_callable_summaries.get(self._class_stack[-1], {})
            callable_writers = self._class_callable_summary_writers.get(self._class_stack[-1], {})
            if receiver is not None:
                instance_seed = {
                    f"{receiver}.{path}": kind
                    for path, kind in summary.items()
                    if node.name != "__init__"
                    and any(writer != id(node) for writer in writers.get(path, ()))
                }
        self._function_depth += 1
        alias_seed = None
        callable_seed = None
        if self._class_stack and self._function_depth - 1 == self._class_function_depths[-1]:
            alias_seed = self._class_alias_bases[-1]
            callable_seed = dict(self._class_callable_bases[-1])
            callable_seed.update(
                {
                    f"{receiver}.{path}": identity
                    for path, identity in callable_summary.items()
                    if receiver is not None
                    and node.name != "__init__"
                    and any(writer != id(node) for writer in callable_writers.get(path, ()))
                }
            )
        self._visit_scope_body(
            node.body,
            clear_names=local_names,
            instance_seed=instance_seed,
            alias_seed=alias_seed,
            callable_seed=callable_seed,
        )
        self._function_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        parameter_names = {
            argument.arg
            for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        }
        if node.args.vararg:
            parameter_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            parameter_names.add(node.args.kwarg.arg)
        parameter_names.update(_local_binder_names_expr(node.body))
        self._visit_scope_expr(node.body, clear_names=parameter_names)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        outer_aliases = dict(self.active_aliases)
        outer_callable_aliases = dict(self.callable_aliases)
        summary, writers, callable_summary, callable_writers = _class_attribute_summary(
            node,
            outer_aliases,
            self.instance_bindings,
            self.constructor_bindings,
        )
        self._class_summaries[node] = summary
        self._class_summary_writers[node] = writers
        self._class_callable_summaries[node] = callable_summary
        self._class_callable_summary_writers[node] = callable_writers
        self._class_stack.append(node)
        self._class_alias_bases.append(outer_aliases)
        self._class_callable_bases.append(outer_callable_aliases)
        self._class_function_depths.append(self._function_depth)
        self._visit_scope_body(node.body)
        self._class_function_depths.pop()
        self._class_callable_bases.pop()
        self._class_alias_bases.pop()
        self._class_stack.pop()
        self.active_aliases.pop(node.name, None)
        self.callable_aliases.pop(node.name, None)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            self.visit(target)
        callable_identity = _callable_identity(
            node.value,
            self.active_aliases,
            self.instance_bindings,
            self.constructor_bindings,
            self.callable_aliases,
        )
        self._bind_assignment(node.value, list(node.targets))
        for target in node.targets:
            self._invalidate_alias_target(target)
        self._bind_callable_assignment(node.value, list(node.targets), callable_identity)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.annotation is not None:
            self.visit(node.annotation)
        self.visit(node.target)
        if node.value is not None:
            self.visit(node.value)
        callable_identity = (
            _callable_identity(
                node.value,
                self.active_aliases,
                self.instance_bindings,
                self.constructor_bindings,
                self.callable_aliases,
            )
            if node.value is not None
            else None
        )
        self._bind_assignment(
            node.value, [node.target]
        ) if node.value is not None else self._bind_target(node.target, None)
        self._invalidate_alias_target(node.target)
        if node.value is not None:
            self._bind_callable_assignment(node.value, [node.target], callable_identity)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.target)
        self.visit(node.value)
        callable_identity = _callable_identity(
            node.value,
            self.active_aliases,
            self.instance_bindings,
            self.constructor_bindings,
            self.callable_aliases,
        )
        self._bind_assignment(node.value, [node.target])
        self._invalidate_alias_target(node.target)
        self._bind_callable_assignment(node.value, [node.target], callable_identity)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.target)
        self.visit(node.value)
        self._bind_target(node.target, None)
        self._invalidate_alias_target(node.target)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            self.visit(target)
            self._bind_target(target, None)
            self._invalidate_alias_target(target)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        if node.name is not None:
            _clear_reference_path(self.instance_bindings, node.name)
            _clear_reference_path(self.constructor_bindings, node.name)
            _clear_reference_path(self.callable_aliases, node.name)
            self.active_aliases.pop(node.name, None)
        for statement in node.body:
            self.visit(statement)
        # Python clears ``except ... as name`` at the end of the handler.
        if node.name is not None:
            _clear_reference_path(self.instance_bindings, node.name)
            _clear_reference_path(self.constructor_bindings, node.name)
            _clear_reference_path(self.callable_aliases, node.name)
            self.active_aliases.pop(node.name, None)

    def visit_With(self, node: ast.With) -> None:
        self._visit_with_items(node.items, node.body)

    visit_AsyncWith = visit_With

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self.visit(node.target)
        self._bind_target(node.target, None)
        self._invalidate_alias_target(node.target)
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)

    visit_AsyncFor = visit_For

    def _visit_comprehension(
        self, generators: list[ast.comprehension], expressions: list[ast.AST]
    ) -> None:
        attribute_targets = [
            path for generator in generators for path in _attribute_target_paths(generator.target)
        ]
        self._instance_scopes.append(dict(self.instance_bindings))
        self._constructor_scopes.append(dict(self.constructor_bindings))
        self._callable_scopes.append(dict(self.callable_aliases))
        for generator in generators:
            self.visit(generator.iter)
            self._alias_scopes.append(dict(self.active_aliases))
            self.visit(generator.target)
            self._bind_target(generator.target, None)
            self._invalidate_alias_target(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        for expression in expressions:
            self.visit(expression)
        for _ in generators:
            self._alias_scopes.pop()
        self._callable_scopes.pop()
        self._instance_scopes.pop()
        self._constructor_scopes.pop()
        for path in attribute_targets:
            _clear_reference_path(self.instance_bindings, path)
            _clear_reference_path(self.callable_aliases, path)
            self.constructor_bindings.pop(path, None)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node.generators, [node.key, node.value])

    def _visit_with_items(self, items: list[ast.withitem], body: list[ast.stmt]) -> None:
        for item in items:
            self.visit(item.context_expr)
            if item.optional_vars is None:
                continue
            self.visit(item.optional_vars)
            self._bind_assignment(item.context_expr, [item.optional_vars])
            self._invalidate_alias_target(item.optional_vars)
        for statement in body:
            self.visit(statement)

    def visit_Call(self, node: ast.Call) -> None:
        category, qualified = categorize_call(
            node,
            self.active_aliases,
            self.instance_bindings,
            self.constructor_bindings,
            self.callable_aliases,
        )
        snippet = source_snippet(self.source, node)
        self.calls.append(
            CallSite(
                qualified_name=qualified,
                category=category,
                line=getattr(node, "lineno", 1),
                snippet=snippet,
                node=node,
            )
        )
        if qualified in DYNAMIC_IMPORT_CALLS and node.args:
            module = constant_string(node.args[0])
            if module is not None:
                self.dynamic_imports.append(
                    DynamicImport(module, getattr(node, "lineno", 1), snippet)
                )
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if _scoped_resolve_qualified_name(node.value, self.active_aliases) == "os.environ":
            self.credential_subscripts.append(node)
        self.generic_visit(node)


def _scan_call_visitor(tree: ast.AST, source: str) -> _CallVisitor:
    aliases = build_alias_table(tree)
    visitor = _CallVisitor(aliases, source)
    visitor.visit(tree)
    return visitor


def _sorted_call_sites(visitor: _CallVisitor) -> list[CallSite]:
    return sorted(
        visitor.calls,
        key=lambda item: (item.line, item.qualified_name, item.snippet),
    )


def _sorted_dynamic_imports(visitor: _CallVisitor) -> list[DynamicImport]:
    return sorted(
        visitor.dynamic_imports,
        key=lambda item: (item.line, item.module, item.snippet),
    )


def scan_calls(tree: ast.AST, source: str) -> tuple[list[CallSite], list[DynamicImport]]:
    visitor = _scan_call_visitor(tree, source)
    return _sorted_call_sites(visitor), _sorted_dynamic_imports(visitor)


def _sensitive_env_key(key: str | None) -> bool:
    if key is None:
        return True
    upper = key.upper()
    return any(marker in upper for marker in SENSITIVE_ENV_MARKERS)


def _credential_accesses_from_visitor(visitor: _CallVisitor, source: str) -> list[CredentialAccess]:
    found: list[CredentialAccess] = []
    for node in visitor.credential_subscripts:
        key = constant_string(node.slice)
        if _sensitive_env_key(key):
            description = f"os.environ[{key!r}]" if key is not None else "os.environ[...]"
            found.append(
                CredentialAccess(
                    description,
                    getattr(node, "lineno", 1),
                    source_snippet(source, node),
                    node,
                )
            )
    for call in visitor.calls:
        node = call.node
        if call.category == "credential_env":
            qualified = call.qualified_name
            key = constant_string(node.args[0]) if node.args else None
            if _sensitive_env_key(key):
                description = f"{qualified}({key!r})" if key is not None else f"{qualified}(...)"
                found.append(
                    CredentialAccess(
                        description,
                        getattr(node, "lineno", 1),
                        source_snippet(source, node),
                        node,
                    )
                )
        for argument in node.args:
            literal = constant_string(argument)
            if literal and any(path in literal for path in SENSITIVE_PATHS):
                found.append(
                    CredentialAccess(
                        literal,
                        getattr(node, "lineno", 1),
                        source_snippet(source, node),
                        node,
                    )
                )
    return sorted(found, key=lambda item: (item.line, item.description, item.snippet))


def credential_accesses(tree: ast.AST, source: str) -> list[CredentialAccess]:
    return _credential_accesses_from_visitor(_scan_call_visitor(tree, source), source)


class _ScopeNodeVisitor(ast.NodeVisitor):
    """Walk code executed in one scope without entering nested definitions."""

    def __init__(self) -> None:
        self.nodes: list[ast.AST] = []

    def generic_visit(self, node: ast.AST) -> None:
        self.nodes.append(node)
        super().generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


def _scope_nodes(body: Iterable[ast.stmt]) -> list[ast.AST]:
    visitor = _ScopeNodeVisitor()
    for statement in body:
        visitor.visit(statement)
    return visitor.nodes


def _contains_node(container: ast.AST, target: ast.AST) -> bool:
    return any(node is target for node in ast.walk(container))


def _assigned_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
            names.add(child.id)
    return names


def _loaded_names(node: ast.AST) -> set[str]:
    return {
        child.id
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
    }


def _iter_scopes(tree: ast.Module) -> Iterator[list[ast.stmt]]:
    yield tree.body
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.body


def _assignment_parts(
    assignment: ast.Assign | ast.AnnAssign | ast.NamedExpr,
) -> tuple[list[ast.AST], list[ast.AST]]:
    if isinstance(assignment, ast.Assign):
        return [assignment.value], list(assignment.targets)
    if isinstance(assignment, ast.AnnAssign):
        return ([assignment.value] if assignment.value is not None else []), [assignment.target]
    return [assignment.value], [assignment.target]


_TaintOrigin = CredentialAccess | str
_TaintState = dict[str, frozenset[_TaintOrigin]]


def _origin_sort_key(origin: _TaintOrigin) -> tuple[object, ...]:
    if isinstance(origin, CredentialAccess):
        return (0, origin.line, origin.description, origin.snippet)
    return (1, origin)


def _ordered_origins(origins: Iterable[_TaintOrigin]) -> tuple[_TaintOrigin, ...]:
    return tuple(sorted(set(origins), key=_origin_sort_key))


def _copy_taint_state(state: _TaintState) -> _TaintState:
    return {name: frozenset(origins) for name, origins in state.items() if origins}


def _join_taint_states(*states: _TaintState) -> _TaintState:
    merged: _TaintState = {}
    for state in states:
        for name, origins in state.items():
            if origins:
                merged[name] = merged.get(name, frozenset()) | origins
    return merged


def _target_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return {name for item in target.elts for name in _target_names(item)}
    return set()


def _import_bound_names(node: ast.Import | ast.ImportFrom) -> set[str]:
    if isinstance(node, ast.Import):
        return {alias.asname or alias.name.split(".", 1)[0] for alias in node.names}
    return {alias.asname or alias.name for alias in node.names if alias.name != "*"}


class _OrderedTaintAnalyzer:
    """Bounded, ordered taint analysis for one lexical scope."""

    def __init__(
        self,
        scope_sources: list[CredentialAccess],
        network_calls: Iterable[CallSite],
        initial_state: _TaintState | None = None,
    ) -> None:
        self.scope_sources = scope_sources
        self.network_calls = {id(call.node): call for call in network_calls}
        self.state: _TaintState = _copy_taint_state(initial_state or {})
        self.sink_origins: dict[int, tuple[_TaintOrigin, ...]] = {}
        self.return_origins: list[tuple[_TaintOrigin, ...]] = []
        self.call_snapshots: dict[int, _TaintState] = {}
        self.call_argument_origins: dict[int, list[frozenset[_TaintOrigin]]] = {}

    def _exact_origins(self, node: ast.AST) -> frozenset[_TaintOrigin]:
        return frozenset(item for item in self.scope_sources if item.node is node)

    def _assign(self, targets: Iterable[ast.AST], origins: frozenset[_TaintOrigin]) -> None:
        for target in targets:
            for name in _target_names(target):
                if origins:
                    self.state[name] = origins
                else:
                    self.state.pop(name, None)

    def _run_block(self, body: Iterable[ast.stmt], initial: _TaintState) -> _TaintState:
        previous = self.state
        self.state = _copy_taint_state(initial)
        for statement in body:
            self._statement(statement)
        result = _copy_taint_state(self.state)
        self.state = previous
        return result

    def _run_expression(
        self, node: ast.AST, initial: _TaintState
    ) -> tuple[frozenset[_TaintOrigin], _TaintState]:
        previous = self.state
        self.state = _copy_taint_state(initial)
        origins = self._expression(node)
        result = _copy_taint_state(self.state)
        self.state = previous
        return origins, result

    def _expression(self, node: ast.AST) -> frozenset[_TaintOrigin]:
        if isinstance(node, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return self._exact_origins(node)
        if isinstance(node, ast.Name):
            origins = self._exact_origins(node)
            if isinstance(node.ctx, ast.Load):
                origins |= self.state.get(node.id, frozenset())
            return origins
        if isinstance(node, ast.Call):
            self.call_snapshots[id(node)] = _copy_taint_state(self.state)
            origins = self._expression(node.func)
            argument_origins: list[frozenset[_TaintOrigin]] = []
            for argument in node.args:
                argument_origins.append(self._expression(argument))
            for keyword in node.keywords:
                argument_origins.append(self._expression(keyword.value))
            self.call_argument_origins[id(node)] = argument_origins
            payload_origins = (
                frozenset().union(*argument_origins) if argument_origins else frozenset()
            )
            origins = origins | payload_origins | self._exact_origins(node)
            call = self.network_calls.get(id(node))
            if call is not None:
                self.sink_origins[id(node)] = _ordered_origins(payload_origins)
            return origins
        if isinstance(node, ast.NamedExpr):
            origins = self._expression(node.value)
            self._assign([node.target], origins)
            return origins
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            origins = self._exact_origins(node)
            incoming = _copy_taint_state(self.state)
            current = incoming
            possible_states = [incoming]
            for generator in node.generators:
                self.state = current
                iterable_origins = self._expression(generator.iter)
                origins |= iterable_origins
                after_iter = _copy_taint_state(self.state)
                possible_states.append(after_iter)
                self._assign([generator.target], iterable_origins)
                for condition in generator.ifs:
                    origins |= self._expression(condition)
                current = _copy_taint_state(self.state)
            self.state = current
            if isinstance(node, ast.DictComp):
                origins |= self._expression(node.key)
                origins |= self._expression(node.value)
            else:
                origins |= self._expression(node.elt)
            possible_states.append(_copy_taint_state(self.state))
            self.state = _join_taint_states(*possible_states)
            return origins
        if isinstance(node, ast.BoolOp):
            origins = frozenset()
            first = self._expression(node.values[0])
            origins |= first
            paths = [_copy_taint_state(self.state)]
            current = _copy_taint_state(self.state)
            for value in node.values[1:]:
                value_origins, value_state = self._run_expression(value, current)
                origins |= value_origins
                paths.append(value_state)
                current = value_state
            self.state = _join_taint_states(*paths)
            return origins
        if isinstance(node, ast.IfExp):
            origins = self._expression(node.test)
            branch_entry = _copy_taint_state(self.state)
            body_origins, body_state = self._run_expression(node.body, branch_entry)
            else_origins, else_state = self._run_expression(node.orelse, branch_entry)
            self.state = _join_taint_states(body_state, else_state)
            return origins | body_origins | else_origins
        if isinstance(node, ast.Compare):
            origins = self._expression(node.left)
            paths = [_copy_taint_state(self.state)]
            current = _copy_taint_state(self.state)
            for comparator in node.comparators:
                comparator_origins, comparator_state = self._run_expression(comparator, current)
                origins |= comparator_origins
                paths.append(comparator_state)
                current = comparator_state
            self.state = _join_taint_states(*paths)
            return origins
        origins = self._exact_origins(node)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            origins |= self._expression(child)
        return origins

    def _statement(self, node: ast.stmt) -> None:
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            values, targets = _assignment_parts(node)
            origins = frozenset()
            for value in values:
                origins |= self._expression(value)
            for target in targets:
                if not isinstance(target, (ast.Name, ast.Tuple, ast.List)):
                    self._expression(target)
            self._assign(targets, origins)
            return
        if isinstance(node, ast.AugAssign):
            previous = frozenset(
                self.state.get(node.target.id, frozenset())
                if isinstance(node.target, ast.Name)
                else ()
            )
            origins = self._expression(node.value)
            self._expression(node.target)
            if isinstance(node.target, ast.Name):
                self._assign([node.target], previous | origins)
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            self.state = {
                name: origins
                for name, origins in self.state.items()
                if name not in _import_bound_names(node)
            }
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.state.pop(node.name, None)
            return
        if isinstance(node, ast.Delete):
            for target in node.targets:
                for name in _assigned_names(target):
                    self.state.pop(name, None)
            return
        if isinstance(node, ast.If):
            self._expression(node.test)
            incoming = _copy_taint_state(self.state)
            body_state = self._run_block(node.body, incoming)
            else_state = self._run_block(node.orelse, incoming) if node.orelse else incoming
            self.state = _join_taint_states(body_state, else_state)
            return
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            incoming = _copy_taint_state(self.state)
            if isinstance(node, (ast.For, ast.AsyncFor)):
                iterable_origins = self._expression(node.iter)
                self._assign([node.target], iterable_origins)
            else:
                self._expression(node.test)
            loop_entry = _copy_taint_state(self.state)
            body_state = self._run_block(node.body, loop_entry)
            else_state = self._run_block(node.orelse, loop_entry) if node.orelse else loop_entry
            self.state = _join_taint_states(incoming, body_state, else_state)
            return
        if isinstance(node, ast.Try):
            incoming = _copy_taint_state(self.state)
            try_state = self._run_block(node.body, incoming)
            branch_states = [try_state]
            if node.handlers:
                for handler in node.handlers:
                    if handler.type is not None:
                        self._expression(handler.type)
                    handler_state = self._run_block(handler.body, incoming)
                    branch_states.append(handler_state)
            else:
                branch_states.append(incoming)
            merged = _join_taint_states(*branch_states)
            if node.orelse:
                normal_else = self._run_block(node.orelse, try_state)
                merged = _join_taint_states(merged, normal_else)
            self.state = self._run_block(node.finalbody, merged) if node.finalbody else merged
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                context_origins = self._expression(item.context)
                if item.optional_vars is not None:
                    self._assign([item.optional_vars], context_origins)
            self.state = self._run_block(node.body, self.state)
            return
        if isinstance(node, ast.Return):
            if node.value is not None:
                self.return_origins.append(_ordered_origins(self._expression(node.value)))
            return
        if isinstance(node, ast.Expr):
            self._expression(node.value)
            return
        if isinstance(node, ast.Match):
            subject_origins = self._expression(node.subject)
            incoming = _copy_taint_state(self.state)
            branches = []
            for case in node.cases:
                branch = _copy_taint_state(incoming)
                if case.guard is not None:
                    self.state = branch
                    self._expression(case.guard)
                    branch = _copy_taint_state(self.state)
                self._assign([case.pattern], subject_origins)
                branches.append(self._run_block(case.body, branch))
            self.state = _join_taint_states(incoming, *branches)
            return
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                self._statement(child)
            else:
                self._expression(child)

    def run(self, body: Iterable[ast.stmt]) -> None:
        for statement in body:
            self._statement(statement)


def _function_parameter_sinks(
    tree: ast.Module, network_calls: list[CallSite]
) -> dict[str, list[tuple[str, int | None, CallSite]]]:
    """Summarize top-level helpers whose parameter reaches a network call."""

    summaries: dict[str, list[tuple[str, int | None, CallSite]]] = {}
    for function in tree.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        positional = [*function.args.posonlyargs, *function.args.args]
        parameters = [*positional, *function.args.kwonlyargs]
        function_nodes = _scope_nodes(function.body)
        function_sinks = [
            call for call in network_calls if any(node is call.node for node in function_nodes)
        ]
        initial_state: _TaintState = {
            parameter.arg: frozenset({parameter.arg}) for parameter in parameters
        }
        analyzer = _OrderedTaintAnalyzer([], function_sinks, initial_state)
        analyzer.run(function.body)
        for sink in function_sinks:
            used = analyzer.sink_origins.get(id(sink.node), ())
            for parameter_name in sorted(used):
                position = next(
                    (
                        index
                        for index, parameter in enumerate(positional)
                        if parameter.arg == parameter_name
                    ),
                    None,
                )
                summaries.setdefault(function.name, []).append((parameter_name, position, sink))
    return summaries


def _function_return_sources(
    tree: ast.Module, all_sources: list[CredentialAccess]
) -> dict[str, tuple[CredentialAccess, ...]]:
    """Summarize top-level helpers that return a credential-derived value."""

    summaries: dict[str, tuple[CredentialAccess, ...]] = {}
    for function in tree.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        function_nodes = _scope_nodes(function.body)
        scope_sources = [
            item
            for item in all_sources
            if any(_contains_node(node, item.node) for node in function_nodes)
        ]
        if not scope_sources:
            continue
        analyzer = _OrderedTaintAnalyzer(scope_sources, [])
        analyzer.run(function.body)
        origins = {
            origin
            for returned in analyzer.return_origins
            for origin in returned
            if isinstance(origin, CredentialAccess)
        }
        if origins:
            summaries[function.name] = _ordered_origins(origins)  # type: ignore[assignment]
    return summaries


def find_credential_network_flows(tree: ast.Module, source: str) -> list[CredentialFlow]:
    """Find simple same-scope and one-helper credential-to-network flows."""

    visitor = _scan_call_visitor(tree, source)
    all_sources = _credential_accesses_from_visitor(visitor, source)
    calls = _sorted_call_sites(visitor)
    network_calls = [call for call in calls if call.category == "network"]
    flows: list[CredentialFlow] = []

    for body in _iter_scopes(tree):
        nodes = _scope_nodes(body)
        scope_sources = [
            item for item in all_sources if any(_contains_node(node, item.node) for node in nodes)
        ]
        scope_sinks = [
            item for item in network_calls if any(_contains_node(node, item.node) for node in nodes)
        ]
        if not scope_sources or not scope_sinks:
            continue

        analyzer = _OrderedTaintAnalyzer(scope_sources, scope_sinks)
        analyzer.run(body)
        for sink in scope_sinks:
            for origin in analyzer.sink_origins.get(id(sink.node), ()):
                if isinstance(origin, CredentialAccess):
                    flows.append(CredentialFlow(origin, sink))

    # One bounded interprocedural step: a credential read at module scope is
    # passed into a top-level helper whose corresponding parameter reaches a
    # network sink. Deeper call graphs are intentionally outside the contract.
    summaries = _function_parameter_sinks(tree, network_calls)
    return_sources = _function_return_sources(tree, all_sources)
    if summaries or return_sources:
        module_nodes = _scope_nodes(tree.body)
        module_sources = [
            item
            for item in all_sources
            if any(_contains_node(node, item.node) for node in module_nodes)
        ]
        module_calls = [call for call in calls if any(node is call.node for node in module_nodes)]
        for call in module_calls:
            returned_sources = return_sources.get(call.qualified_name)
            if returned_sources is not None:
                module_sources.extend(
                    CredentialAccess(
                        returned_source.description,
                        returned_source.line,
                        returned_source.snippet,
                        call.node,
                    )
                    for returned_source in returned_sources
                )
        module_sinks = [call for call in module_calls if call.category == "network"]
        module_analyzer = _OrderedTaintAnalyzer(module_sources, module_sinks)
        module_analyzer.run(tree.body)
        for sink in module_sinks:
            for origin in module_analyzer.sink_origins.get(id(sink.node), ()):
                if isinstance(origin, CredentialAccess):
                    flows.append(CredentialFlow(origin, sink))
        for call in module_calls:
            helper_name = call.qualified_name
            for parameter_name, position, sink in summaries.get(helper_name, []):
                argument: ast.AST | None = None
                if position is not None and position < len(call.node.args):
                    argument = call.node.args[position]
                for keyword in call.node.keywords:
                    if keyword.arg == parameter_name:
                        argument = keyword.value
                if argument is None:
                    continue
                argument_index = position
                if argument_index is None:
                    for index, keyword in enumerate(call.node.keywords, start=len(call.node.args)):
                        if keyword.arg == parameter_name:
                            argument_index = index
                            break
                argument_origins = module_analyzer.call_argument_origins.get(id(call.node), [])
                if argument_index is not None and argument_index < len(argument_origins):
                    evaluated_origins = argument_origins[argument_index]
                else:
                    evaluated_origins = frozenset()
                for origin in _ordered_origins(evaluated_origins):
                    if not isinstance(origin, CredentialAccess):
                        continue
                    flows.append(
                        CredentialFlow(
                            origin,
                            sink,
                            trigger_line=call.line,
                            trigger_snippet=call.snippet,
                        )
                    )

    unique = {
        (
            flow.source.line,
            flow.source.description,
            flow.sink.line,
            flow.sink.qualified_name,
            flow.trigger_line or -1,
        ): flow
        for flow in flows
    }
    return [unique[key] for key in sorted(unique)]


class _TopLevelBindingVisitor(ast.NodeVisitor):
    """Collect module-scope names that can shadow imported safe helpers."""

    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        return

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        return

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        if node.name is not None:
            self.names.add(node.name)
        for statement in node.body:
            self.visit(statement)

    def _visit_comprehension(
        self,
        generators: list[ast.comprehension],
        expressions: list[ast.AST],
    ) -> None:
        for generator in generators:
            self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        for expression in expressions:
            self.visit(expression)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node.generators, [node.key, node.value])

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Store):
            self.names.add(node.id)


def _top_level_binding_names(tree: ast.Module) -> set[str]:
    visitor = _TopLevelBindingVisitor()
    for statement in tree.body:
        visitor.visit(statement)
    return visitor.names


def _attribute_root_name(node: ast.AST) -> str | None:
    current = node
    while isinstance(current, ast.Attribute):
        current = current.value
    return current.id if isinstance(current, ast.Name) else None


def _is_whitelisted_top_level_call(
    call: ast.Call,
    aliases: dict[str, str],
    shadowed_names: set[str],
) -> bool:
    qualified = resolve_qualified_name(call.func, aliases) or ""
    if isinstance(call.func, ast.Name) and call.func.id in shadowed_names:
        return False
    if _attribute_root_name(call.func) in shadowed_names:
        return False
    return qualified in {
        "logging.getLogger",
        "warnings.filterwarnings",
        "typing.cast",
        "importlib.metadata.version",
        "pkgutil.extend_path",
        "typing.TypeVar",
        "typing.NamedTuple",
        "typing.NewType",
        "TypeVar",
        "NamedTuple",
        "NewType",
    }


class _TopLevelCallVisitor(ast.NodeVisitor):
    def __init__(self, aliases: dict[str, str], shadowed_names: set[str]) -> None:
        self.aliases = aliases
        self.shadowed_names = shadowed_names
        self.calls: list[ast.Call] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Call(self, node: ast.Call) -> None:
        if not _is_whitelisted_top_level_call(node, self.aliases, self.shadowed_names):
            self.calls.append(node)
        self.generic_visit(node)


def top_level_calls(tree: ast.Module) -> list[ast.Call]:
    aliases = build_alias_table(tree)
    visitor = _TopLevelCallVisitor(aliases, _top_level_binding_names(tree))
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        visitor.visit(statement)
    return sorted(
        visitor.calls,
        key=lambda node: (
            getattr(node, "lineno", 1),
            resolve_qualified_name(node.func, aliases) or "",
        ),
    )


class _DocstringStripper(ast.NodeTransformer):
    def _strip_body(self, node: ast.AST) -> ast.AST:
        body = getattr(node, "body", None)
        if (
            isinstance(body, list)
            and body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            del body[0]
        self.generic_visit(node)
        return node

    visit_Module = _strip_body
    visit_FunctionDef = _strip_body
    visit_AsyncFunctionDef = _strip_body
    visit_ClassDef = _strip_body


class _SetuptoolsScmCommitNormalizer(ast.NodeTransformer):
    """Ignore build-provenance values in generated setuptools-scm modules."""

    _NAMES: ClassVar[set[str]] = {"commit_id", "__commit_id__"}

    def visit_Assign(self, node: ast.Assign) -> ast.AST:
        names = {target.id for target in node.targets if isinstance(target, ast.Name)}
        if names and names <= self._NAMES:
            node.value = ast.Constant(value=None)
        return self.generic_visit(node)


def normalized_ast(source: str, filename: str = "<artifact>") -> str:
    tree = parse_python(source, filename=filename)
    if filename.lower().endswith("_version.py") and source.lstrip().startswith(
        "# file generated by setuptools-scm"
    ):
        tree = _SetuptoolsScmCommitNormalizer().visit(tree)
    stripped = _DocstringStripper().visit(tree)
    return ast.dump(stripped, annotate_fields=True, include_attributes=False)
