"""Group A — blast radius & excessive agency (the core check, and the whole point).

Two responsibilities:

1. **Classify** each tool's blast radius: ``READ_ONLY`` / ``REVERSIBLE_WRITE`` /
   ``IRREVERSIBLE_OR_EXTERNAL``. This annotates every tool (``tool.blast_radius``) so
   the reporters and downstream checks can read it.
2. **Verify the safeguard** on every genuinely irreversible/external tool: does it have
   a human-in-the-loop gate parameter that is *actually branched on* in the handler's
   control flow — not merely present in the signature?

The second point is Consentinel's differentiator. Other scanners detect the dangerous
capability; this verifies the enforced gate.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from consentinel.checks.astutil import (
    call_dotted_name,
    call_tail_name,
    guard_tokens,
    has_local_write,
    iter_calls,
    returns_bulk_pii,
    string_constants,
)
from consentinel.checks.base import Check, ScanContext
from consentinel.constants import (
    DESTRUCTIVE_SQL_KEYWORDS,
    DESTRUCTIVE_VERBS,
    EMAIL_SEND_METHODS,
    FS_DESTRUCTION_CALLS,
    FS_DESTRUCTION_METHODS,
    HTTP_WRITE_METHODS,
    METHOD_NAME_VERBS,
    ORM_DESTRUCTIVE_METHODS,
    SHELL_EXEC_CALLS,
    SUBPROCESS_MODULE,
)
from consentinel.models import BlastRadius, CheckGroup, Finding, Severity, Tool
from consentinel.owasp import owasp_for


@dataclass
class AgencyAnalysis:
    """The result of classifying one tool."""

    blast_radius: BlastRadius
    has_action_signal: bool
    signals: list[str] = field(default_factory=list)


def _shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _name_verb(text: str) -> str | None:
    """Match any destructive/external verb as a substring of a tool name."""
    low = text.lower()
    for verb in DESTRUCTIVE_VERBS:
        if verb in low:
            return verb
    return None


def _tokens(name: str) -> set[str]:
    """Split an identifier into lowercase word tokens (snake_case and camelCase)."""
    tokens: set[str] = set()
    for part in re.split(r"[_\s]+", name):
        for tok in re.findall(r"[A-Z]?[a-z]+|[A-Z]+|\d+", part):
            tokens.add(tok.lower())
    return tokens


def _method_verb(tail: str) -> str | None:
    """Match an action verb as a whole token in a (non-constructor) called method name."""
    if not tail or tail[0].isupper():  # e.g. EmailMessage(), TextContent() — constructors.
        return None
    toks = _tokens(tail)
    for verb in METHOD_NAME_VERBS:
        if verb in toks:
            return verb
    return None


def collect_action_signals(tool: Tool) -> list[str]:
    """Human-readable side-effect signals found in the handler body / tool name.

    An "action signal" means the tool genuinely *does* something irreversible or
    external. Bulk-PII exposure is handled separately (it raises the display rating but
    is not, by itself, an action to gate).
    """
    signals: list[str] = []

    verb = _name_verb(tool.name)
    if verb:
        signals.append(f"tool name contains destructive/external verb '{verb}'")

    for call in iter_calls(tool.body):
        dotted = call_dotted_name(call) or ""
        tail = (call_tail_name(call) or "").lower()
        matched_specific = False

        if tail in HTTP_WRITE_METHODS:
            signals.append(f"network write via {dotted or tail}()")
            matched_specific = True
        if tail in EMAIL_SEND_METHODS:
            signals.append(f"email send via {dotted or tail}()")
            matched_specific = True
        if dotted in FS_DESTRUCTION_CALLS or tail in FS_DESTRUCTION_METHODS:
            signals.append(f"filesystem destruction via {dotted or tail}()")
            matched_specific = True
        if dotted in SHELL_EXEC_CALLS or tail in {"system", "popen"}:
            signals.append(f"code/command execution via {dotted or tail}()")
            matched_specific = True
        if dotted == SUBPROCESS_MODULE or dotted.startswith(SUBPROCESS_MODULE + "."):
            signals.append(f"subprocess execution via {dotted}()")
            matched_specific = True
        if _shell_true(call):
            signals.append("subprocess called with shell=True")
            matched_specific = True
        if tail in ORM_DESTRUCTIVE_METHODS:
            signals.append(f"ORM state change via .{tail}()")
            matched_specific = True
        if tail == "execute":
            sql = " ".join(string_constants([call])).upper()
            if any(kw in sql for kw in DESTRUCTIVE_SQL_KEYWORDS):
                signals.append("destructive SQL passed to .execute()")
                matched_specific = True

        # A destructive verb as the name of a called method (e.g. client.delete_all()),
        # only when a more specific API signal did not already fire for this call.
        if not matched_specific:
            called_verb = _method_verb(tail)
            if called_verb:
                signals.append(f"calls method with destructive verb '{called_verb}' (.{tail}())")

    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for s in signals:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    return unique


def analyze_tool(tool: Tool) -> AgencyAnalysis:
    """Classify a tool's blast radius (and record why)."""
    signals = collect_action_signals(tool)
    has_action = bool(signals)

    if has_action:
        radius = BlastRadius.IRREVERSIBLE_OR_EXTERNAL
    elif has_local_write(tool.body):
        radius = BlastRadius.REVERSIBLE_WRITE
    else:
        radius = BlastRadius.READ_ONLY

    # Bulk-PII return raises exposure (fail-safe) but is not an action to gate.
    if returns_bulk_pii(tool) and radius.rank < BlastRadius.IRREVERSIBLE_OR_EXTERNAL.rank:
        radius = BlastRadius.IRREVERSIBLE_OR_EXTERNAL
        signals = [*signals, "returns bulk PII (data-exposure surface)"]

    return AgencyAnalysis(blast_radius=radius, has_action_signal=has_action, signals=signals)


class AgencyCheck(Check):
    group = CheckGroup.A

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for tool in ctx.tools:
            analysis = analyze_tool(tool)
            tool.blast_radius = analysis.blast_radius

            # The enforced-gate check applies only to genuinely irreversible/external
            # ACTIONS — not to tools merely rated up for bulk-PII exposure.
            if not analysis.has_action_signal:
                continue

            findings.extend(self._gate_findings(tool, analysis))

        return findings

    def _gate_findings(self, tool: Tool, analysis: AgencyAnalysis) -> list[Finding]:
        gate_params = tool.gate_params
        signal_summary = "; ".join(analysis.signals) or "irreversible/external action"

        if not gate_params:
            return [
                Finding(
                    id="CS-A001",
                    severity=Severity.HIGH,
                    tool=tool.name,
                    file=tool.file,
                    line=tool.line,
                    description=(
                        f"Tool '{tool.name}' performs an irreversible or externally "
                        f"side-effecting action ({signal_summary}) but has no "
                        f"human-in-the-loop safeguard: no confirmation/approval "
                        f"parameter is present in its signature."
                    ),
                    remediation=(
                        "Add a confirmation gate parameter (e.g. confirmed: bool = "
                        "False or a dry_run preview) and branch on it before the "
                        "side-effecting call so the action cannot fire un-approved."
                    ),
                    owasp=owasp_for("CS-A001"),
                    check_group=CheckGroup.A,
                    extra={"blast_radius": tool.blast_radius.value, "signals": analysis.signals},
                )
            ]

        # A gate parameter exists — is it actually enforced in the control flow?
        tokens = guard_tokens(tool.body)
        enforced = [p for p in gate_params if p.name in tokens]

        if enforced:
            return [
                Finding(
                    id="CS-A003",
                    severity=Severity.INFO,
                    tool=tool.name,
                    file=tool.file,
                    line=tool.line,
                    description=(
                        f"Tool '{tool.name}' is irreversible/external and its gate "
                        f"parameter(s) {', '.join(p.name for p in enforced)} are "
                        f"branched on in the handler — the safeguard appears enforced."
                    ),
                    remediation="No action required. Keep the gate branch ahead of the side effect.",
                    owasp=owasp_for("CS-A003"),
                    check_group=CheckGroup.A,
                    extra={"blast_radius": tool.blast_radius.value},
                )
            ]

        # The flagship finding: the false safeguard.
        names = ", ".join(p.name for p in gate_params)
        return [
            Finding(
                id="CS-A002",
                severity=Severity.HIGH,
                tool=tool.name,
                file=tool.file,
                line=tool.line,
                description=(
                    f"Tool '{tool.name}' performs an irreversible or externally "
                    f"side-effecting action ({signal_summary}) and DECLARES a gate "
                    f"parameter ({names}), but never references it in any conditional "
                    f"or guard in the handler body. The safeguard is unenforced — the "
                    f"side effect fires regardless of the gate value (false safeguard)."
                ),
                remediation=(
                    f"Branch on '{gate_params[0].name}' before the side-effecting call, "
                    f"e.g. `if not {gate_params[0].name}: return ...` at the top of the "
                    f"handler, so the action is actually gated."
                ),
                owasp=owasp_for("CS-A002"),
                check_group=CheckGroup.A,
                extra={"blast_radius": tool.blast_radius.value, "gate_params": [p.name for p in gate_params]},
            )
        ]
