"""Group B — tool-poisoning surface (supporting, shallow).

Only the cheap, objective, low-false-positive checks live here; semantic poisoning
detection is deferred to mcp-scan. Two checks:

* CS-B001 — invisible / zero-width / bidi control characters anywhere in the tool
  schema (name, description, parameter names, defaults, enums).
* CS-B002 — imperative-injection phrases in the description / docstring.
"""

from __future__ import annotations

from consentinel.checks.base import Check, ScanContext
from consentinel.constants import (
    INJECTION_PHRASES_HIGH,
    INJECTION_PHRASES_LOW,
    INVISIBLE_CODEPOINTS,
)
from consentinel.models import CheckGroup, Finding, Severity, Tool
from consentinel.owasp import owasp_for


def _iter_schema_strings(obj) -> list[str]:
    """Recursively collect every string in a JSON schema (keys and values)."""
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                out.append(k)
            out.extend(_iter_schema_strings(v))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            out.extend(_iter_schema_strings(item))
    elif isinstance(obj, str):
        out.append(obj)
    return out


def _tool_text_fields(tool: Tool) -> list[tuple[str, str]]:
    """Return (field-label, text) pairs to scan for a tool."""
    fields: list[tuple[str, str]] = [("name", tool.name)]
    if tool.description:
        fields.append(("description", tool.description))
    for p in tool.parameters:
        fields.append((f"param:{p.name}", p.name))
        if p.default:
            fields.append((f"default:{p.name}", p.default))
    if tool.raw_schema:
        for s in _iter_schema_strings(tool.raw_schema):
            fields.append(("schema", s))
    return fields


def _invisible_codepoints(text: str) -> list[str]:
    return sorted({f"U+{ord(c):04X}" for c in text if ord(c) in INVISIBLE_CODEPOINTS})


class PoisoningCheck(Check):
    group = CheckGroup.B

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in ctx.tools:
            findings.extend(self._invisible(tool))
            findings.extend(self._imperative(tool))
        return findings

    def _invisible(self, tool: Tool) -> list[Finding]:
        hits: dict[str, list[str]] = {}
        for label, text in _tool_text_fields(tool):
            cps = _invisible_codepoints(text)
            if cps:
                hits.setdefault(label, [])
                for cp in cps:
                    if cp not in hits[label]:
                        hits[label].append(cp)
        if not hits:
            return []
        where = "; ".join(f"{label} ({', '.join(cps)})" for label, cps in hits.items())
        return [
            Finding(
                id="CS-B001",
                severity=Severity.MED,
                tool=tool.name,
                file=tool.file,
                line=tool.line,
                description=(
                    f"Tool '{tool.name}' contains invisible / zero-width / bidi control "
                    f"characters in its schema — {where}. These are unreadable to a human "
                    f"reviewer but seen by the model, a classic tool-poisoning vector."
                ),
                remediation=(
                    "Remove the non-printing characters from the tool name, description, "
                    "parameter names, defaults, and enum values."
                ),
                owasp=owasp_for("CS-B001"),
                check_group=CheckGroup.B,
                extra={"locations": hits},
            )
        ]

    def _imperative(self, tool: Tool) -> list[Finding]:
        text = (tool.description or "").lower()
        if not text:
            return []
        high = [p for p in INJECTION_PHRASES_HIGH if p in text]
        low = [p for p in INJECTION_PHRASES_LOW if p in text]
        if not high and not low:
            return []
        severity = Severity.MED if high else Severity.LOW
        matched = high + low
        return [
            Finding(
                id="CS-B002",
                severity=severity,
                tool=tool.name,
                file=tool.file,
                line=tool.line,
                description=(
                    f"Tool '{tool.name}' description contains imperative-injection "
                    f"phrasing directed at the model: {', '.join(repr(p) for p in matched)}. "
                    f"Descriptions that instruct the agent (override, exfiltrate, or "
                    f"force-call) are a tool-poisoning risk."
                ),
                remediation=(
                    "Rewrite the description to plainly state what the tool does. Remove "
                    "instructions aimed at the model (e.g. 'always call', 'ignore "
                    "previous', 'do not tell the user')."
                ),
                owasp=owasp_for("CS-B002"),
                check_group=CheckGroup.B,
                extra={"phrases": matched},
            )
        ]
