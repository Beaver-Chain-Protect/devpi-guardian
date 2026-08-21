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
) -> tuple[str | None, str]:
    qualified = _qualified_call_name(
        call,
        aliases,
        instance_bindings or {},
        constructor_bindings,
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
) -> str:
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
        return path[len(prefix) :]
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
        local_names: Iterable[str] = (),
    ) -> None:
        self.receiver = receiver
        self.aliases = dict(aliases)
        self.module_instances = dict(module_instances)
        self.constructors = dict(module_constructors)
        self.known: dict[str, str] = {}
        self.receiver_known = dict(initial or {})
        self.events: list[tuple[str, str | None]] = []
        for name in local_names:
            self._clear_local_name(name)

    def _clear_local_name(self, name: str) -> None:
        self.aliases.pop(name, None)
        _clear_reference_path(self.module_instances, name)
        _clear_reference_path(self.constructors, name)
        _clear_reference_path(self.known, name)

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
        for target in node.targets:
            self._clear_target_state(target)
            self._update_constructor_alias(target, node.value)
            self._record(target, node.value)
            self._invalidate_alias_target(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.annotation is not None:
            self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
            self._clear_target_state(node.target)
            self._update_constructor_alias(node.target, node.value)
        else:
            self._clear_target_state(node.target)
        self._record(node.target, node.value)
        self._invalidate_alias_target(node.target)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._clear_target_state(node.target)
        self._update_constructor_alias(node.target, node.value)
        self._record(node.target, node.value)
        self._invalidate_alias_target(node.target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.target)
        self.visit(node.value)
        self._record(node.target, None)
        self._invalidate_alias_target(node.target)
        self._clear_target_state(node.target)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            self._record(target, None)
            self._invalidate_alias_target(target)
            self._clear_target_state(target)

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self._record(node.target, None)
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
        for generator in generators:
            self.visit(generator.iter)
            self.aliases = dict(self.aliases)
            self.module_instances = dict(self.module_instances)
            self.constructors = dict(self.constructors)
            self.known = dict(self.known)
            self.receiver_known = dict(self.receiver_known)
            self._record(generator.target, None)
            self._invalidate_alias_target(generator.target)
            self._clear_target_state(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        for expression in expressions:
            self.visit(expression)
        self.aliases = aliases
        self.module_instances = module_instances
        self.constructors = constructors
        self.known = known
        self.receiver_known = receiver_known

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
) -> tuple[dict[str, str], dict[str, frozenset[int]]]:
    methods = [
        child
        for child in node.body
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
        and _instance_method_receiver(child, aliases) is not None
    ]
    direct: dict[str, set[str]] = {}
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

    provisional = {path: next(iter(kinds)) for path, kinds in direct.items() if len(kinds) == 1}
    all_events: dict[str, list[str | None]] = {}
    event_methods: dict[str, set[int]] = {}
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
            provisional,
            local_names,
        )
        for statement in method.body:
            collector.visit(statement)
        for path, kind in collector.events:
            all_events.setdefault(path, []).append(kind)
            event_methods.setdefault(path, set()).add(id(method))

    summary = {
        path: kinds[0]
        for path, kinds in all_events.items()
        if kinds and None not in kinds and len(set(kinds)) == 1
    }
    writers = {path: frozenset(event_methods[path]) for path in summary}
    return summary, writers


class _CallVisitor(ast.NodeVisitor):
    def __init__(self, aliases: dict[str, str], source: str) -> None:
        self.aliases = aliases
        self.source = source
        self.calls: list[CallSite] = []
        self.dynamic_imports: list[DynamicImport] = []
        self._instance_scopes: list[dict[str, str]] = [{}]
        self._constructor_scopes: list[dict[str, str]] = [{}]
        self._alias_scopes: list[dict[str, str]] = [{}]
        self._class_summaries: dict[ast.ClassDef, dict[str, str]] = {}
        self._class_summary_writers: dict[ast.ClassDef, dict[str, frozenset[int]]] = {}
        self._class_stack: list[ast.ClassDef] = []
        self._class_alias_bases: list[dict[str, str]] = []
        self._class_function_depths: list[int] = []
        self._function_depth = 0

    @property
    def active_aliases(self) -> dict[str, str]:
        return self._alias_scopes[-1]

    def _invalidate_alias_target(self, target: ast.AST) -> None:
        for name in _binding_names(target):
            self.active_aliases.pop(name, None)

    def _bind_import(self, node: ast.Import) -> None:
        for imported in node.names:
            visible = imported.asname or imported.name.split(".", 1)[0]
            _clear_reference_path(self.instance_bindings, visible)
            _clear_reference_path(self.constructor_bindings, visible)
            self.active_aliases[visible] = imported.name if imported.asname else visible

    def _bind_import_from(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            for imported in node.names:
                if imported.name != "*":
                    visible = imported.asname or imported.name
                    _clear_reference_path(self.instance_bindings, visible)
                    _clear_reference_path(self.constructor_bindings, visible)
                    self.active_aliases[visible] = f".{imported.name}"
            return
        for imported in node.names:
            if imported.name != "*":
                visible = imported.asname or imported.name
                _clear_reference_path(self.instance_bindings, visible)
                _clear_reference_path(self.constructor_bindings, visible)
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

    def _visit_scope_body(
        self,
        body: list[ast.stmt],
        *,
        clear_names: Iterable[str] = (),
        instance_seed: dict[str, str] | None = None,
        alias_seed: dict[str, str] | None = None,
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
        for statement in body:
            self.visit(statement)
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
        self.visit(expression)
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
            if receiver is not None:
                instance_seed = {
                    f"{receiver}.{path}": kind
                    for path, kind in summary.items()
                    if node.name != "__init__"
                    and any(writer != id(node) for writer in writers.get(path, ()))
                }
        self._function_depth += 1
        alias_seed = None
        if self._class_stack and self._function_depth - 1 == self._class_function_depths[-1]:
            alias_seed = self._class_alias_bases[-1]
        self._visit_scope_body(
            node.body,
            clear_names=local_names,
            instance_seed=instance_seed,
            alias_seed=alias_seed,
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
        summary, writers = _class_attribute_summary(
            node,
            outer_aliases,
            self.instance_bindings,
            self.constructor_bindings,
        )
        self._class_summaries[node] = summary
        self._class_summary_writers[node] = writers
        self._class_stack.append(node)
        self._class_alias_bases.append(outer_aliases)
        self._class_function_depths.append(self._function_depth)
        self._visit_scope_body(node.body)
        self._class_function_depths.pop()
        self._class_alias_bases.pop()
        self._class_stack.pop()
        self.active_aliases.pop(node.name, None)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            self.visit(target)
        self._bind_assignment(node.value, list(node.targets))
        for target in node.targets:
            self._invalidate_alias_target(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.annotation is not None:
            self.visit(node.annotation)
        self.visit(node.target)
        if node.value is not None:
            self.visit(node.value)
        self._bind_assignment(
            node.value, [node.target]
        ) if node.value is not None else self._bind_target(node.target, None)
        self._invalidate_alias_target(node.target)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.target)
        self.visit(node.value)
        self._bind_assignment(node.value, [node.target])
        self._invalidate_alias_target(node.target)

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
            self.active_aliases.pop(node.name, None)
        for statement in node.body:
            self.visit(statement)
        # Python clears ``except ... as name`` at the end of the handler.
        if node.name is not None:
            _clear_reference_path(self.instance_bindings, node.name)
            _clear_reference_path(self.constructor_bindings, node.name)
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
        self._instance_scopes.pop()
        self._constructor_scopes.pop()
        for path in attribute_targets:
            _clear_reference_path(self.instance_bindings, path)
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


def scan_calls(tree: ast.AST, source: str) -> tuple[list[CallSite], list[DynamicImport]]:
    aliases = build_alias_table(tree)
    visitor = _CallVisitor(aliases, source)
    visitor.visit(tree)
    calls = sorted(
        visitor.calls,
        key=lambda item: (item.line, item.qualified_name, item.snippet),
    )
    imports = sorted(
        visitor.dynamic_imports,
        key=lambda item: (item.line, item.module, item.snippet),
    )
    return calls, imports


def _sensitive_env_key(key: str | None) -> bool:
    if key is None:
        return True
    upper = key.upper()
    return any(marker in upper for marker in SENSITIVE_ENV_MARKERS)


def credential_accesses(tree: ast.AST, source: str) -> list[CredentialAccess]:
    aliases = build_alias_table(tree)
    found: list[CredentialAccess] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript):
            qualified = resolve_qualified_name(node.value, aliases)
            if qualified == "os.environ":
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
        elif isinstance(node, ast.Call):
            qualified = resolve_qualified_name(node.func, aliases)
            if qualified in {"os.getenv", "os.environ.get"}:
                key = constant_string(node.args[0]) if node.args else None
                if _sensitive_env_key(key):
                    description = (
                        f"{qualified}({key!r})" if key is not None else f"{qualified}(...)"
                    )
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


def _credential_taint(
    nodes: list[ast.AST], scope_sources: list[CredentialAccess]
) -> tuple[set[str], dict[str, CredentialAccess]]:
    tainted: set[str] = set()
    source_for_name: dict[str, CredentialAccess] = {}
    assignments = [
        node for node in nodes if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
    ]
    changed = True
    while changed:
        changed = False
        for assignment in assignments:
            values, targets = _assignment_parts(assignment)
            matching_source = next(
                (
                    item
                    for item in scope_sources
                    if any(_contains_node(value, item.node) for value in values)
                ),
                None,
            )
            inherited_name = next(
                (name for value in values for name in _loaded_names(value) if name in tainted),
                None,
            )
            if matching_source is None and inherited_name is None:
                continue
            origin = matching_source or source_for_name[inherited_name]  # type: ignore[index]
            for target in targets:
                for name in _assigned_names(target):
                    if name not in tainted:
                        tainted.add(name)
                        source_for_name[name] = origin
                        changed = True
    return tainted, source_for_name


def _payload_origin(
    payload_nodes: list[ast.AST],
    scope_sources: list[CredentialAccess],
    tainted: set[str],
    source_for_name: dict[str, CredentialAccess],
) -> CredentialAccess | None:
    direct = next(
        (
            item
            for item in scope_sources
            if any(_contains_node(payload, item.node) for payload in payload_nodes)
        ),
        None,
    )
    if direct is not None:
        return direct
    tainted_arg = next(
        (name for payload in payload_nodes for name in _loaded_names(payload) if name in tainted),
        None,
    )
    return source_for_name.get(tainted_arg) if tainted_arg is not None else None


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
        parameter_origins: dict[str, set[str]] = {
            parameter.arg: {parameter.arg} for parameter in parameters
        }
        function_nodes = _scope_nodes(function.body)
        assignments = [
            node
            for node in function_nodes
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
        ]
        changed = True
        while changed:
            changed = False
            for assignment in assignments:
                values, targets = _assignment_parts(assignment)
                inherited = {
                    origin
                    for value in values
                    for name in _loaded_names(value)
                    for origin in parameter_origins.get(name, set())
                }
                if not inherited:
                    continue
                for target in targets:
                    for name in _assigned_names(target):
                        previous = parameter_origins.setdefault(name, set())
                        before = len(previous)
                        previous.update(inherited)
                        changed = changed or len(previous) != before

        function_sinks = [
            call for call in network_calls if any(node is call.node for node in function_nodes)
        ]
        for sink in function_sinks:
            payload = list(sink.node.args) + [keyword.value for keyword in sink.node.keywords]
            used = {
                origin
                for node in payload
                for name in _loaded_names(node)
                for origin in parameter_origins.get(name, set())
            }
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
) -> dict[str, CredentialAccess]:
    """Summarize top-level helpers that return a credential-derived value."""

    summaries: dict[str, CredentialAccess] = {}
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
        tainted, source_for_name = _credential_taint(function_nodes, scope_sources)
        for node in function_nodes:
            if not isinstance(node, ast.Return) or node.value is None:
                continue
            origin = _payload_origin([node.value], scope_sources, tainted, source_for_name)
            if origin is not None:
                summaries.setdefault(function.name, origin)
    return summaries


def find_credential_network_flows(tree: ast.Module, source: str) -> list[CredentialFlow]:
    """Find simple same-scope and one-helper credential-to-network flows."""

    all_sources = credential_accesses(tree, source)
    calls, _ = scan_calls(tree, source)
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

        tainted, source_for_name = _credential_taint(nodes, scope_sources)

        for sink in scope_sinks:
            payload_nodes = list(sink.node.args) + [keyword.value for keyword in sink.node.keywords]
            origin = _payload_origin(payload_nodes, scope_sources, tainted, source_for_name)
            if origin is not None:
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
            returned_source = return_sources.get(call.qualified_name)
            if returned_source is not None:
                module_sources.append(
                    CredentialAccess(
                        returned_source.description,
                        returned_source.line,
                        returned_source.snippet,
                        call.node,
                    )
                )
        module_taint, module_source_for_name = _credential_taint(module_nodes, module_sources)
        for sink in (call for call in module_calls if call.category == "network"):
            payload_nodes = list(sink.node.args) + [keyword.value for keyword in sink.node.keywords]
            origin = _payload_origin(
                payload_nodes,
                module_sources,
                module_taint,
                module_source_for_name,
            )
            if origin is not None:
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
                origin = _payload_origin(
                    [argument],
                    module_sources,
                    module_taint,
                    module_source_for_name,
                )
                if origin is not None:
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
