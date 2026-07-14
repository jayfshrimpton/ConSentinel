"""Group E — transport (supporting; one check).

CS-E001 — a network transport (HTTP / SSE / streamable-HTTP / WebSocket) is started
with no visible authentication. Purely heuristic and low-severity: we look for a
transport indicator in a file and, if no auth-related token appears anywhere in that
same file, flag it for review.
"""

from __future__ import annotations

import ast

from consentinel.checks.astutil import call_dotted_name, call_tail_name
from consentinel.checks.base import Check, ScanContext
from consentinel.constants import AUTH_HINTS, NETWORK_TRANSPORTS
from consentinel.models import CheckGroup, Finding, Severity
from consentinel.owasp import owasp_for

_TRANSPORT_CLASSES = frozenset(
    {"SseServerTransport", "StreamableHTTPSessionManager", "StreamableHTTPServerTransport"}
)


class TransportCheck(Check):
    group = CheckGroup.E

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path, tree in ctx.trees.items():
            indicator = self._transport_indicator(tree)
            if indicator is None:
                continue
            if self._has_auth_in_code(tree):
                continue  # some auth machinery is referenced in code; don't flag.
            label, line = indicator
            findings.append(
                Finding(
                    id="CS-E001",
                    severity=Severity.LOW,
                    tool="(server transport)",
                    file=path,
                    line=line,
                    description=(
                        f"A network-exposed MCP transport ({label}) is started in {path} "
                        f"with no visible authentication in the module. Unauthenticated "
                        f"HTTP/SSE transports let any local or network client invoke tools."
                    ),
                    remediation=(
                        "Require authentication for network transports (bearer token / "
                        "OAuth / API key middleware), or bind to localhost only for local "
                        "use. Prefer stdio transport when remote access is not needed."
                    ),
                    owasp=owasp_for("CS-E001"),
                    check_group=CheckGroup.E,
                )
            )
        return findings

    @staticmethod
    def _has_auth_in_code(tree: ast.Module) -> bool:
        """True if the module references auth machinery in *code* (not comments/docstrings).

        Scanning identifiers rather than raw text avoids a descriptive comment such as
        "no authentication" suppressing the finding, and biases toward flagging (a
        low-severity false positive) rather than silently missing an unauthenticated
        transport (a false negative).
        """
        identifiers: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                identifiers.add(node.id)
            elif isinstance(node, ast.Attribute):
                identifiers.add(node.attr)
            elif isinstance(node, ast.arg):
                identifiers.add(node.arg)
            elif isinstance(node, ast.keyword) and node.arg:
                identifiers.add(node.arg)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                identifiers.add(node.name)
            elif isinstance(node, ast.alias):
                identifiers.add(node.asname or node.name)
        blob = " ".join(identifiers).lower()
        return any(hint in blob for hint in AUTH_HINTS)

    @staticmethod
    def _transport_indicator(tree: ast.Module) -> tuple[str, int] | None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            dotted = call_dotted_name(node) or ""
            tail = call_tail_name(node) or ""

            if dotted == "uvicorn.run" or tail == "run" and dotted.endswith("uvicorn.run"):
                return ("uvicorn.run", node.lineno)

            if tail in _TRANSPORT_CLASSES:
                return (tail, node.lineno)

            if tail == "run":
                for kw in node.keywords:
                    if (
                        kw.arg == "transport"
                        and isinstance(kw.value, ast.Constant)
                        and str(kw.value.value).lower() in NETWORK_TRANSPORTS
                    ):
                        return (f'transport="{kw.value.value}"', node.lineno)
        return None
