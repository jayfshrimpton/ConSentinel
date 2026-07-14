"""Python tool extraction.

Locates MCP tool definitions in Python source using the :mod:`ast` module only — the
target server is never imported or executed. Two declaration styles are supported:

1. **FastMCP decorator style** — ``@mcp.tool()`` / ``@app.tool()`` (any receiver
   variable) on a function.
2. **Low-level handler style** — a ``@server.list_tools()`` registry plus a
   ``@server.call_tool()`` (or plainly-named ``call_tool``) dispatch handler that
   branches on the tool name. Each per-tool branch body becomes that tool's handler.

Both are normalised into :class:`~consentinel.models.Tool` objects.
"""

from __future__ import annotations

import ast
from pathlib import Path

from consentinel.constants import GATE_PARAM_NAMES, IGNORED_PARAM_NAMES
from consentinel.extract.base import LanguageBackend
from consentinel.models import Param, Tool

# Function names that, even without a decorator, are treated as the dispatch handler.
_CALL_TOOL_NAMES = {"call_tool", "handle_call_tool"}
# Preferred parameter names for the tool-name dispatch variable.
_DISPATCH_VAR_HINTS = ("name", "tool_name", "tool", "tool_id")


def _unparse(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - defensive
        return None


def _decorator_attr(dec: ast.expr) -> str | None:
    """Return the method/name at the decorator's call position (``tool``, ``list_tools``…)."""
    if isinstance(dec, ast.Call):
        dec = dec.func
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Name):
        return dec.id
    return None


def _has_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef, attr: str) -> bool:
    return any(_decorator_attr(dec) == attr for dec in node.decorator_list)


def _call_tail_name(func: ast.expr) -> str | None:
    """Return the trailing name of a call target: ``types.Tool`` -> ``Tool``."""
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _make_param(arg: ast.arg, default: str | None) -> Param:
    return Param(
        name=arg.arg,
        annotation=_unparse(arg.annotation),
        default=default,
        is_gate=arg.arg in GATE_PARAM_NAMES,
    )


def _params_from_func(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[Param]:
    """Extract parameters from a function signature, aligning defaults correctly."""
    a = func.args
    params: list[Param] = []

    positional = list(a.posonlyargs) + list(a.args)
    defaults = list(a.defaults)
    first_default = len(positional) - len(defaults)
    for i, arg in enumerate(positional):
        di = i - first_default
        default = _unparse(defaults[di]) if di >= 0 else None
        params.append(_make_param(arg, default))

    for arg, dnode in zip(a.kwonlyargs, a.kw_defaults):
        params.append(_make_param(arg, _unparse(dnode) if dnode is not None else None))

    return [p for p in params if p.name not in IGNORED_PARAM_NAMES]


def _params_from_schema(schema: dict | None) -> list[Param]:
    """Build params from a low-level tool's JSON inputSchema ``properties``."""
    if not isinstance(schema, dict):
        return []
    props = schema.get("properties")
    if not isinstance(props, dict):
        return []
    params: list[Param] = []
    for pname, pinfo in props.items():
        ann = pinfo.get("type") if isinstance(pinfo, dict) else None
        params.append(
            Param(name=pname, annotation=ann, default=None, is_gate=pname in GATE_PARAM_NAMES)
        )
    return params


def _tool_call_info(call: ast.Call) -> dict:
    """Parse a ``types.Tool(name=..., description=..., inputSchema={...})`` constructor."""
    info: dict = {"name": None, "description": None, "schema": None}
    for kw in call.keywords:
        if kw.arg == "name" and isinstance(kw.value, ast.Constant):
            info["name"] = kw.value.value
        elif kw.arg == "description" and isinstance(kw.value, ast.Constant):
            info["description"] = kw.value.value
        elif kw.arg == "inputSchema":
            try:
                info["schema"] = ast.literal_eval(kw.value)
            except Exception:
                info["schema"] = None
    return info


def _dispatch_var(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Best guess for the parameter holding the tool name in a dispatch handler."""
    names = [a.arg for a in (list(func.args.posonlyargs) + list(func.args.args))]
    names = [n for n in names if n not in IGNORED_PARAM_NAMES]
    for hint in _DISPATCH_VAR_HINTS:
        if hint in names:
            return hint
    return names[0] if names else None


def _match_dispatch(test: ast.expr, var: str | None) -> list[str]:
    """Return the tool-name literal(s) a branch condition dispatches on."""
    results: list[str] = []

    def name_matches(node: ast.expr) -> bool:
        return isinstance(node, ast.Name) and (var is None or node.id == var)

    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        for value in test.values:
            results.extend(_match_dispatch(value, var))
        return results

    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        op = test.ops[0]
        left, right = test.left, test.comparators[0]
        if isinstance(op, ast.Eq):
            if name_matches(left) and isinstance(right, ast.Constant) and isinstance(right.value, str):
                results.append(right.value)
            elif name_matches(right) and isinstance(left, ast.Constant) and isinstance(left.value, str):
                results.append(left.value)
        elif isinstance(op, ast.In) and name_matches(left):
            if isinstance(right, (ast.Tuple, ast.List, ast.Set)):
                for elt in right.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        results.append(elt.value)
    return results


class PythonBackend(LanguageBackend):
    """Extract MCP tools from a Python codebase (both declaration styles)."""

    extensions = (".py",)
    language = "python"

    def __init__(self) -> None:
        self.errors: list[str] = []
        #: file path -> raw source text, populated by :meth:`extract_tools`.
        self.sources: dict[str, str] = {}
        #: file path -> parsed module AST, populated by :meth:`extract_tools`.
        self.trees: dict[str, ast.Module] = {}

    def extract_tools(self, path: Path) -> list[Tool]:
        tools: list[Tool] = []
        for f in self.source_files(Path(path)):
            try:
                src = f.read_text(encoding="utf-8")
            except Exception:
                continue
            try:
                tree = ast.parse(src)
            except SyntaxError as exc:
                self.errors.append(f"{f}: {exc}")
                continue
            rel = str(f)
            self.sources[rel] = src
            self.trees[rel] = tree
            tools.extend(self._extract_fastmcp(tree, rel))
            tools.extend(self._extract_lowlevel(tree, rel))
        return self._dedup(tools)

    # -- FastMCP decorator style -------------------------------------------------

    def _extract_fastmcp(self, tree: ast.Module, file: str) -> list[Tool]:
        out: list[Tool] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _has_decorator(node, "tool"):
                continue
            name = self._fastmcp_name(node, node.name)
            out.append(
                Tool(
                    name=name,
                    description=ast.get_docstring(node),
                    parameters=_params_from_func(node),
                    body=node.body,
                    file=file,
                    line=node.lineno,
                    end_line=getattr(node, "end_lineno", None),
                    style="fastmcp",
                )
            )
        return out

    @staticmethod
    def _fastmcp_name(node: ast.FunctionDef | ast.AsyncFunctionDef, default: str) -> str:
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and _decorator_attr(dec) == "tool":
                for kw in dec.keywords:
                    if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                        return str(kw.value.value)
        return default

    # -- Low-level Server / call_tool style --------------------------------------

    def _extract_lowlevel(self, tree: ast.Module, file: str) -> list[Tool]:
        registry = self._build_registry(tree)
        branches = self._dispatch_branches(tree)
        if not registry and not branches:
            return []

        out: list[Tool] = []
        seen: set[str] = set()

        for name, (info, decl_line) in registry.items():
            branch = branches.get(name)
            body = branch.body if branch else []
            line = branch.lineno if branch else decl_line
            end = getattr(branch, "end_lineno", None) if branch else None
            out.append(
                Tool(
                    name=name,
                    description=info["description"],
                    parameters=_params_from_schema(info["schema"]),
                    body=body,
                    file=file,
                    line=line,
                    end_line=end,
                    style="lowlevel",
                    raw_schema=info["schema"],
                )
            )
            seen.add(name)

        for name, branch in branches.items():
            if name in seen:
                continue
            out.append(
                Tool(
                    name=name,
                    description=None,
                    parameters=[],
                    body=branch.body,
                    file=file,
                    line=branch.lineno,
                    end_line=getattr(branch, "end_lineno", None),
                    style="lowlevel",
                    raw_schema=None,
                )
            )
        return out

    @staticmethod
    def _build_registry(tree: ast.Module) -> dict[str, tuple[dict, int]]:
        """Map tool name -> (info, declaration line) from ``@server.list_tools()``."""
        registry: dict[str, tuple[dict, int]] = {}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _has_decorator(node, "list_tools"):
                continue
            for sub in ast.walk(node):
                if isinstance(sub, ast.Return) and isinstance(sub.value, (ast.List, ast.Tuple)):
                    for elt in sub.value.elts:
                        if isinstance(elt, ast.Call) and _call_tail_name(elt.func) == "Tool":
                            info = _tool_call_info(elt)
                            if info["name"]:
                                registry[info["name"]] = (info, elt.lineno)
        return registry

    @staticmethod
    def _dispatch_branches(tree: ast.Module) -> dict[str, ast.If]:
        """Map tool name -> the ``If`` branch that handles it in the dispatch function."""
        branches: dict[str, ast.If] = {}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            is_dispatch = _has_decorator(node, "call_tool") or node.name in _CALL_TOOL_NAMES
            if not is_dispatch:
                continue
            var = _dispatch_var(node)
            for sub in ast.walk(node):
                if isinstance(sub, ast.If):
                    for name in _match_dispatch(sub.test, var):
                        branches.setdefault(name, sub)
        return branches

    # -- de-duplication ----------------------------------------------------------

    @staticmethod
    def _dedup(tools: list[Tool]) -> list[Tool]:
        """Collapse (file, name) duplicates, preferring the entry with a real body."""
        best: dict[tuple[str, str], Tool] = {}
        for tool in tools:
            key = (tool.file, tool.name)
            existing = best.get(key)
            if existing is None or (not existing.body and tool.body):
                best[key] = tool
        return list(best.values())
