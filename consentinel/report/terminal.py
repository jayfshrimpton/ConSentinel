"""Terminal reporter — a rich per-tool table followed by the findings."""

from __future__ import annotations

import os

from rich.console import Console
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from consentinel import DISCLAIMER
from consentinel.checks.base import ScanResult
from consentinel.models import BlastRadius, Severity

_SEVERITY_STYLE = {
    Severity.HIGH: "bold red",
    Severity.MED: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
_BLAST_STYLE = {
    BlastRadius.IRREVERSIBLE_OR_EXTERNAL: "bold red",
    BlastRadius.REVERSIBLE_WRITE: "yellow",
    BlastRadius.READ_ONLY: "green",
}
_BLAST_LABEL = {
    BlastRadius.IRREVERSIBLE_OR_EXTERNAL: "IRREVERSIBLE/EXTERNAL",
    BlastRadius.REVERSIBLE_WRITE: "REVERSIBLE WRITE",
    BlastRadius.READ_ONLY: "READ-ONLY",
}


def _loc(file: str, line: int) -> str:
    return f"{os.path.basename(file)}:{line}"


def render_terminal(console: Console, result: ScanResult, target: str) -> None:
    console.print()
    console.rule("[bold]Consentinel[/bold] - MCP excessive-agency & safeguard audit")
    console.print(f"[dim]Target:[/dim] {target}    [dim]Tools:[/dim] {len(result.tools)}    "
                  f"[dim]Findings:[/dim] {len(result.findings)}")
    console.print()

    _render_tool_table(console, result)
    console.print()
    _render_findings(console, result)

    if result.errors:
        console.print()
        console.print(f"[dim]{len(result.errors)} file(s) could not be parsed and were skipped.[/dim]")

    console.print()
    console.print(Text(DISCLAIMER, style="dim italic"))


def _render_tool_table(console: Console, result: ScanResult) -> None:
    table = Table(title="Tools by blast radius", title_style="bold", header_style="bold")
    table.add_column("Tool")
    table.add_column("Style")
    table.add_column("Blast radius")
    table.add_column("Findings", justify="right")
    table.add_column("Top severity")

    order = {BlastRadius.IRREVERSIBLE_OR_EXTERNAL: 0, BlastRadius.REVERSIBLE_WRITE: 1, BlastRadius.READ_ONLY: 2}
    for tool in sorted(result.tools, key=lambda t: (order[t.blast_radius], t.name)):
        tool_findings = [f for f in result.findings if f.tool == tool.name]
        top = max((f.severity for f in tool_findings), default=None)
        top_text = Text(top.value, style=_SEVERITY_STYLE[top]) if top else Text("-", style="dim")
        table.add_row(
            tool.name,
            tool.style,
            Text(_BLAST_LABEL[tool.blast_radius], style=_BLAST_STYLE[tool.blast_radius]),
            str(len(tool_findings)),
            top_text,
        )
    console.print(table)


def _render_findings(console: Console, result: ScanResult) -> None:
    if not result.findings:
        console.print("[green]No findings.[/green]")
        return

    console.print(f"[bold]Findings[/bold] ({len(result.findings)})")
    console.print()
    for f in result.findings:
        header = Text()
        header.append(f"{f.severity.value:<4}", style=_SEVERITY_STYLE[f.severity])
        header.append(f"  {f.id}", style="bold")
        header.append(f"  {f.tool}  ")
        header.append(f"{_loc(f.file, f.line)}  [group {f.check_group.value}]", style="dim")
        console.print(header)

        detail = Text()
        detail.append(f.description)
        detail.append("\nFix: ", style="bold dim")
        detail.append(f.remediation, style="dim")
        detail.append("\nOWASP: ", style="bold dim")
        detail.append(f.owasp, style="dim")
        console.print(Padding(detail, (0, 1, 1, 4)))
