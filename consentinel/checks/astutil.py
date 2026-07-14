"""Reusable AST helpers shared across the check groups.

Kept dependency-free (stdlib :mod:`ast` only) and side-effect free — these functions
never execute target code, they only inspect parsed syntax trees.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Iterator

from consentinel.constants import PII_FIELD_HINTS, WRITE_FILE_MODES
from consentinel.models import Tool


def walk_body(body: Iterable[ast.stmt]) -> Iterator[ast.AST]:
    """Yield every descendant node across a list of statements."""
    for stmt in body:
        yield from ast.walk(stmt)


def iter_calls(body: Iterable[ast.stmt]) -> Iterator[ast.Call]:
    for node in walk_body(body):
        if isinstance(node, ast.Call):
            yield node


def dotted_name(node: ast.expr | None) -> str | None:
    """Return a dotted name for an attribute/name chain: ``os.path.join`` -> that string."""
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def call_dotted_name(call: ast.Call) -> str | None:
    return dotted_name(call.func)


def call_tail_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def string_constants(nodes: Iterable[ast.AST]) -> list[str]:
    """All string literals within the given nodes, including f-string static parts."""
    out: list[str] = []
    for root in nodes:
        for node in ast.walk(root):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                out.append(node.value)
            elif isinstance(node, ast.JoinedStr):
                for part in node.values:
                    if isinstance(part, ast.Constant) and isinstance(part.value, str):
                        out.append(part.value)
    return out


def strip_docstring(body: Iterable[ast.stmt]) -> list[ast.stmt]:
    """Return ``body`` without a leading docstring statement.

    A docstring is documentation, not executable content, so semantic body analysis
    (SQL text, PII fields, injection) must not treat it as a runtime string.
    """
    stmts = list(body)
    if (
        stmts
        and isinstance(stmts[0], ast.Expr)
        and isinstance(stmts[0].value, ast.Constant)
        and isinstance(stmts[0].value.value, str)
    ):
        return stmts[1:]
    return stmts


def body_string_constants(body: Iterable[ast.stmt]) -> list[str]:
    """String literals in the executable body (the leading docstring is excluded)."""
    return string_constants(strip_docstring(body))


def names_used(body: Iterable[ast.stmt]) -> set[str]:
    return {n.id for n in walk_body(body) if isinstance(n, ast.Name)}


def guard_tokens(body: Iterable[ast.stmt]) -> set[str]:
    """Tokens (Name ids and string constants) that appear in a control-flow guard.

    A "guard" is the test of an ``If``/``While``/``IfExp``, the test of an ``Assert``,
    or any standalone ``Compare``/``BoolOp``. String constants are included so gate
    parameters referenced via a dict lookup (``arguments["confirmed"]``) in low-level
    dispatch handlers are recognised too. This is deliberately broad: any conditional
    reference to a gate parameter counts as an enforced gate (fail-safe toward PASS).
    """
    tokens: set[str] = set()
    tests: list[ast.AST] = []
    for node in walk_body(body):
        if isinstance(node, (ast.If, ast.While, ast.IfExp, ast.Assert)):
            tests.append(node.test)
        elif isinstance(node, (ast.Compare, ast.BoolOp)):
            tests.append(node)
    for test in tests:
        for sub in ast.walk(test):
            if isinstance(sub, ast.Name):
                tokens.add(sub.id)
            elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                tokens.add(sub.value)
    return tokens


def open_write_mode(call: ast.Call) -> str | None:
    """If ``call`` is ``open(...)`` in a write mode, return that mode string."""
    if call_tail_name(call) != "open":
        return None
    mode: str | None = None
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
        val = call.args[1].value
        if isinstance(val, str):
            mode = val
    for kw in call.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            mode = kw.value.value
    if mode and any(m in mode for m in WRITE_FILE_MODES):
        return mode
    return None


def has_local_write(body: Iterable[ast.stmt]) -> bool:
    return any(open_write_mode(call) is not None for call in iter_calls(list(body)))


def _returns_collection(body: Iterable[ast.stmt]) -> bool:
    """True if any ``return`` yields a list/tuple/comprehension or a fetch-all result."""
    fetch_names = {"fetchall", "fetchmany", "findall", "all", "list", "values", "scalars"}
    for node in walk_body(body):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        val = node.value
        if isinstance(val, (ast.List, ast.Tuple, ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return True
        if isinstance(val, ast.Call) and call_tail_name(val) in fetch_names:
            return True
    return False


def returns_bulk_pii(tool: Tool) -> bool:
    """Heuristic: does the handler return a *collection* of PII (emails, users, phones)?

    Fires only when both a PII signal and a collection-return are present, to keep the
    false-positive rate low. Feeds both the CS-C003 finding and the Group A blast-radius
    rating.
    """
    texts = [t.lower() for t in body_string_constants(tool.body)]
    has_select = any("select" in t for t in texts)
    mentions_pii = any(any(hint in t for hint in PII_FIELD_HINTS) for t in texts)
    if has_select and mentions_pii and _returns_collection(tool.body):
        return True

    # A comprehension that pulls a PII-ish field also counts.
    for node in walk_body(tool.body):
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            keys = {
                s.value.lower()
                for s in ast.walk(node)
                if isinstance(s, ast.Constant) and isinstance(s.value, str)
            }
            attrs = {a.attr.lower() for a in ast.walk(node) if isinstance(a, ast.Attribute)}
            if (keys | attrs) & PII_FIELD_HINTS:
                return True
    return False


def references_param(node: ast.AST, params: Iterable[str]) -> str | None:
    """Return the first parameter name referenced within ``node``.

    Recognises both FastMCP-style direct names (``cmd``) and low-level dispatch access
    via a string key (``arguments["cmd"]`` / ``arguments.get("cmd")``).
    """
    param_set = set(params)
    if not param_set:
        return None
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in param_set:
            return sub.id
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and sub.value in param_set:
            return sub.value
    return None
