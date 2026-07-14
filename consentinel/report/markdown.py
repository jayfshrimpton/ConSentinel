"""Markdown reporter — a self-contained audit report suitable for `--output report.md`."""

from __future__ import annotations

import os

from consentinel import DISCLAIMER, __version__
from consentinel.checks.base import ScanResult
from consentinel.models import BlastRadius, Severity
from consentinel.report.json_report import severity_counts

_BLAST_LABEL = {
    BlastRadius.IRREVERSIBLE_OR_EXTERNAL: "IRREVERSIBLE / EXTERNAL",
    BlastRadius.REVERSIBLE_WRITE: "REVERSIBLE WRITE",
    BlastRadius.READ_ONLY: "READ-ONLY",
}


def _loc(file: str, line: int) -> str:
    return f"`{os.path.basename(file)}:{line}`"


def build_markdown(result: ScanResult, target: str, generated_at: str | None = None) -> str:
    lines: list[str] = []
    lines.append("# Consentinel audit report")
    lines.append("")
    lines.append(
        "> Consentinel finds MCP tools that perform irreversible or externally "
        "side-effecting actions and lack an enforced human-in-the-loop safeguard."
    )
    lines.append("")
    lines.append(f"- **Target:** `{target}`")
    lines.append(f"- **Consentinel version:** {__version__}")
    if generated_at:
        lines.append(f"- **Generated:** {generated_at}")
    lines.append(f"- **Tools analysed:** {len(result.tools)}")
    lines.append(f"- **Findings:** {len(result.findings)}")
    lines.append("")

    counts = severity_counts(result)
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in Severity:
        lines.append(f"| {sev.value} | {counts[sev.value]} |")
    lines.append("")

    lines.append("## Tools by blast radius")
    lines.append("")
    lines.append("| Tool | Style | Blast radius | Findings |")
    lines.append("| --- | --- | --- | --- |")
    order = {BlastRadius.IRREVERSIBLE_OR_EXTERNAL: 0, BlastRadius.REVERSIBLE_WRITE: 1, BlastRadius.READ_ONLY: 2}
    for tool in sorted(result.tools, key=lambda t: (order[t.blast_radius], t.name)):
        n = sum(1 for f in result.findings if f.tool == tool.name)
        lines.append(f"| `{tool.name}` | {tool.style} | {_BLAST_LABEL[tool.blast_radius]} | {n} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not result.findings:
        lines.append("_No findings._")
    for f in result.findings:
        lines.append(f"### {f.id} · {f.severity.value} · `{f.tool}`")
        lines.append("")
        lines.append(f"- **Location:** {_loc(f.file, f.line)}")
        lines.append(f"- **Check group:** {f.check_group.value}")
        lines.append(f"- **OWASP:** {f.owasp}")
        lines.append("")
        lines.append(f"{f.description}")
        lines.append("")
        lines.append(f"**Remediation:** {f.remediation}")
        lines.append("")

    if result.errors:
        lines.append("## Parse errors")
        lines.append("")
        for err in result.errors:
            lines.append(f"- {err}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(f"_{DISCLAIMER}_")
    lines.append("")
    return "\n".join(lines)
