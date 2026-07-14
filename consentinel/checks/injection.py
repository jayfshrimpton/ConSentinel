"""Group D — injection (supporting; intra-procedural, high-confidence only).

Deep interprocedural taint is out of scope (deferred to agent-audit). Only single-
function flows where a tool parameter reaches a sink directly are reported:

* CS-D001 — a tool parameter reaches a shell / eval / exec / subprocess sink.
* CS-D002 — SQL built by f-string / concatenation from a parameter, then executed.
* CS-D003 — a file-path parameter passed to ``open()`` with no path validation.
"""

from __future__ import annotations

import ast

from consentinel.checks.astutil import (
    call_dotted_name,
    call_tail_name,
    iter_calls,
    references_param,
    walk_body,
)
from consentinel.checks.base import Check, ScanContext
from consentinel.constants import SHELL_EXEC_CALLS, SUBPROCESS_MODULE
from consentinel.models import CheckGroup, Finding, Severity, Tool
from consentinel.owasp import owasp_for

_SQL_EXECUTE_TAILS = frozenset({"execute", "executescript", "executemany", "executequery", "raw"})
_VALIDATION_CALLS = frozenset(
    {"abspath", "realpath", "normpath", "basename", "resolve", "commonpath", "relpath", "safe_join"}
)


def _is_exec_sink(call: ast.Call) -> bool:
    dotted = call_dotted_name(call) or ""
    if dotted in SHELL_EXEC_CALLS:
        return True
    if dotted == SUBPROCESS_MODULE or dotted.startswith(SUBPROCESS_MODULE + "."):
        return True
    return False


def _contains_string(node: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Constant) and isinstance(n.value, str) for n in ast.walk(node)
    )


def _has_path_validation(body) -> bool:
    for call in iter_calls(list(body)):
        if (call_tail_name(call) or "") in _VALIDATION_CALLS:
            return True
    # A ".." check or startswith guard also counts as validation.
    for node in walk_body(body):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and ".." in node.value:
            return True
        if isinstance(node, ast.Attribute) and node.attr == "startswith":
            return True
    return False


class InjectionCheck(Check):
    group = CheckGroup.D

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in ctx.tools:
            # Params come from the signature (FastMCP) or the JSON schema (low-level);
            # references_param handles both direct names and arguments["x"] dict access.
            params = [p.name for p in tool.parameters]
            findings.extend(self._command(tool, params))
            findings.extend(self._sql(tool, params))
            findings.extend(self._path(tool, params))
        return findings

    def _command(self, tool: Tool, params: list[str]) -> list[Finding]:
        out: list[Finding] = []
        for call in iter_calls(tool.body):
            if not _is_exec_sink(call):
                continue
            tainted = references_param(call, params)
            if not tainted:
                continue
            sink = call_dotted_name(call) or call_tail_name(call) or "exec"
            out.append(
                Finding(
                    id="CS-D001",
                    severity=Severity.HIGH,
                    tool=tool.name,
                    file=tool.file,
                    line=getattr(call, "lineno", tool.line),
                    description=(
                        f"Tool '{tool.name}' passes parameter '{tainted}' into a command/"
                        f"code-execution sink ({sink}()). A caller-controlled value reaching "
                        f"a shell enables command injection."
                    ),
                    remediation=(
                        "Avoid shell=True and never build commands from input. Pass an "
                        "argument list to subprocess without a shell, or use eval/exec-free "
                        "alternatives."
                    ),
                    owasp=owasp_for("CS-D001"),
                    check_group=CheckGroup.D,
                    extra={"param": tainted, "sink": sink},
                )
            )
        return out

    def _sql(self, tool: Tool, params: list[str]) -> list[Finding]:
        out: list[Finding] = []
        for call in iter_calls(tool.body):
            if (call_tail_name(call) or "").lower() not in _SQL_EXECUTE_TAILS:
                continue
            for arg in call.args:
                tainted = None
                if isinstance(arg, ast.JoinedStr):
                    tainted = references_param(arg, params)
                elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                    if _contains_string(arg):
                        tainted = references_param(arg, params)
                if tainted:
                    out.append(
                        Finding(
                            id="CS-D002",
                            severity=Severity.HIGH,
                            tool=tool.name,
                            file=tool.file,
                            line=getattr(call, "lineno", tool.line),
                            description=(
                                f"Tool '{tool.name}' builds a SQL statement from parameter "
                                f"'{tainted}' via string formatting/concatenation and passes "
                                f"it to .execute(). This is a SQL-injection risk."
                            ),
                            remediation=(
                                "Use a parameterised query: pass values as bind parameters "
                                "(e.g. cur.execute('... WHERE x = ?', (value,))) instead of "
                                "interpolating them into the SQL string."
                            ),
                            owasp=owasp_for("CS-D002"),
                            check_group=CheckGroup.D,
                            extra={"param": tainted},
                        )
                    )
                    break  # one finding per execute call
        return out

    def _path(self, tool: Tool, params: list[str]) -> list[Finding]:
        out: list[Finding] = []
        if _has_path_validation(tool.body):
            return out
        for call in iter_calls(tool.body):
            if (call_tail_name(call) or "") != "open":
                continue
            if not call.args:
                continue
            tainted = references_param(call.args[0], params)
            if not tainted:
                continue
            out.append(
                Finding(
                    id="CS-D003",
                    severity=Severity.MED,
                    tool=tool.name,
                    file=tool.file,
                    line=getattr(call, "lineno", tool.line),
                    description=(
                        f"Tool '{tool.name}' opens a file using parameter '{tainted}' "
                        f"without path validation — a path-traversal risk (e.g. '../' or an "
                        f"absolute path can escape the intended directory)."
                    ),
                    remediation=(
                        "Validate and confine the path: resolve against a fixed base "
                        "directory and reject paths that escape it (e.g. check "
                        "os.path.realpath(...).startswith(base))."
                    ),
                    owasp=owasp_for("CS-D003"),
                    check_group=CheckGroup.D,
                    extra={"param": tainted},
                )
            )
        return out
