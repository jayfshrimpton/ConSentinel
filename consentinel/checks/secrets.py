"""Group C — credentials & data exposure (supporting).

* CS-C001 — hardcoded secrets (provider-pattern regex + Shannon-entropy scoring on
  string literals; env reads / placeholders / UUIDs excluded).
* CS-C002 — secrets / credential values written to logs or returned in tool output.
* CS-C003 — tools returning bulk PII (feeds the Group A blast-radius rating too).

Implemented with :mod:`re` and :mod:`math` only — no external dependency.
"""

from __future__ import annotations

import ast
import math
import re
from collections import Counter

from consentinel.checks.astutil import call_tail_name, dotted_name, returns_bulk_pii, walk_body
from consentinel.checks.base import Check, ScanContext
from consentinel.constants import (
    ENTROPY_MIN_LENGTH,
    ENTROPY_THRESHOLD,
    SECRET_NAME_HINTS,
    SECRET_PATTERNS,
    SECRET_PLACEHOLDERS,
)
from consentinel.models import CheckGroup, Finding, Severity, Tool
from consentinel.owasp import owasp_for

_COMPILED_PATTERNS = {name: re.compile(pat) for name, pat in SECRET_PATTERNS.items()}
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_STRONG_SECRET_NAMES = frozenset(
    {"password", "passwd", "pwd", "secret", "secret_key", "api_key", "apikey",
     "token", "access_token", "auth_token", "private_key", "client_secret"}
)
_LOG_TAILS = frozenset({"print", "debug", "info", "warning", "warn", "error", "exception", "critical", "log"})


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_placeholder(value: str) -> bool:
    low = value.lower()
    return any(p in low for p in SECRET_PLACEHOLDERS) or bool(_UUID_RE.match(value))


def _looks_secret_name(name: str | None) -> bool:
    if not name:
        return False
    low = name.lower()
    return low in SECRET_NAME_HINTS or any(h in low for h in _STRONG_SECRET_NAMES)


def _provider_match(value: str) -> str | None:
    for pname, rx in _COMPILED_PATTERNS.items():
        if rx.search(value):
            return pname
    return None


class SecretsCheck(Check):
    group = CheckGroup.C

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._hardcoded(ctx))
        findings.extend(self._secret_in_output(ctx))
        findings.extend(self._bulk_pii(ctx))
        return findings

    # -- CS-C001: hardcoded secrets ---------------------------------------------

    def _hardcoded(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()

        for path, tree in ctx.trees.items():
            for name, value, lineno in self._string_assignments(tree):
                if not isinstance(value, str) or not value:
                    continue
                key = (path, lineno, value)
                if key in seen:
                    continue

                provider = _provider_match(value)
                reason: str | None = None
                severity = Severity.HIGH

                if provider:
                    reason = f"matches a known {provider} credential pattern"
                elif _looks_secret_name(name) and not _is_placeholder(value) and len(value) >= 12:
                    reason = f"assigned to secret-like name '{name}'"
                elif (
                    len(value) >= ENTROPY_MIN_LENGTH
                    and shannon_entropy(value) >= ENTROPY_THRESHOLD
                    and not _is_placeholder(value)
                    and not _UUID_RE.match(value)
                    and " " not in value
                ):
                    reason = f"high-entropy string literal ({shannon_entropy(value):.1f} bits/char)"
                    severity = Severity.MED

                if reason is None:
                    continue

                seen.add(key)
                tool = self._enclosing_tool(ctx, path, lineno)
                findings.append(
                    Finding(
                        id="CS-C001",
                        severity=severity,
                        tool=tool or "(module)",
                        file=path,
                        line=lineno,
                        description=(
                            f"Hardcoded secret at {path}:{lineno} — {reason}. "
                            f"Credentials embedded in source are exposed to anyone who can "
                            f"read the code or the packaged server."
                        ),
                        remediation=(
                            "Load the secret from an environment variable or secrets "
                            "manager (e.g. os.environ / os.getenv) and rotate the exposed "
                            "credential."
                        ),
                        owasp=owasp_for("CS-C001"),
                        check_group=CheckGroup.C,
                    )
                )
        return findings

    @staticmethod
    def _string_assignments(tree: ast.Module):
        """Yield (name, value, lineno) for string-literal assignments and kwargs."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                if isinstance(node.value.value, str):
                    for tgt in node.targets:
                        name = dotted_name(tgt)
                        yield (name or "", node.value.value, node.value.lineno)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.value, ast.Constant):
                if isinstance(node.value.value, str):
                    name = dotted_name(node.target)
                    yield (name or "", node.value.value, node.value.lineno)
            elif isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        yield (kw.arg, kw.value.value, kw.value.lineno)

    @staticmethod
    def _enclosing_tool(ctx: ScanContext, path: str, lineno: int) -> str | None:
        for tool in ctx.tools:
            if tool.file != path:
                continue
            end = tool.end_line or tool.line
            if tool.line <= lineno <= end:
                return tool.name
        return None

    # -- CS-C002: secrets in logs / output --------------------------------------

    def _secret_in_output(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in ctx.tools:
            hit = self._find_secret_egress(tool)
            if hit:
                kind, name = hit
                strong = _looks_secret_name(name) and any(h in name.lower() for h in _STRONG_SECRET_NAMES)
                findings.append(
                    Finding(
                        id="CS-C002",
                        severity=Severity.HIGH if strong else Severity.MED,
                        tool=tool.name,
                        file=tool.file,
                        line=tool.line,
                        description=(
                            f"Tool '{tool.name}' {kind} a credential-like value "
                            f"('{name}'). Secrets reaching logs or tool output are "
                            f"disclosed to log sinks and to the calling agent/model."
                        ),
                        remediation=(
                            "Do not log or return secrets. Redact credential values before "
                            "they reach logs or the tool response."
                        ),
                        owasp=owasp_for("CS-C002"),
                        check_group=CheckGroup.C,
                    )
                )
        return findings

    @staticmethod
    def _find_secret_egress(tool: Tool) -> tuple[str, str] | None:
        for node in walk_body(tool.body):
            if isinstance(node, ast.Call):
                tail = (call_tail_name(node) or "").lower()
                if tail in _LOG_TAILS:
                    name = SecretsCheck._secret_name_in(node)
                    if name:
                        return ("logs", name)
            elif isinstance(node, ast.Return) and node.value is not None:
                name = SecretsCheck._secret_name_in(node.value)
                if name:
                    return ("returns", name)
        return None

    @staticmethod
    def _secret_name_in(node: ast.AST) -> str | None:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and _looks_secret_name(sub.id):
                return sub.id
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and _looks_secret_name(sub.value):
                # e.g. a dict key like {"api_key": ...}
                return sub.value
        return None

    # -- CS-C003: bulk PII return ------------------------------------------------

    def _bulk_pii(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in ctx.tools:
            if returns_bulk_pii(tool):
                findings.append(
                    Finding(
                        id="CS-C003",
                        severity=Severity.MED,
                        tool=tool.name,
                        file=tool.file,
                        line=tool.line,
                        description=(
                            f"Tool '{tool.name}' returns a bulk collection of PII (e.g. "
                            f"user records / emails / phone numbers). A single call can "
                            f"exfiltrate many records; this also raises the tool's "
                            f"blast-radius rating."
                        ),
                        remediation=(
                            "Constrain the query (pagination, row limits, field allow-list), "
                            "return only what the caller needs, and consider a confirmation "
                            "gate for bulk exports."
                        ),
                        owasp=owasp_for("CS-C003"),
                        check_group=CheckGroup.C,
                    )
                )
        return findings
