"""Render a screenshot-friendly Consentinel scan to assets/consentinel-demo.svg.

Produces the colored terminal capture used as the README hero image. Run with:

    python scripts/render_demo.py
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.padding import Padding
from rich.text import Text

from consentinel import DISCLAIMER
from consentinel.checks.base import scan_path
from consentinel.report.terminal import (
    _SEVERITY_STYLE,
    _render_tool_table,
    _loc,
)

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    result = scan_path(ROOT / "examples" / "vulnerable_server")
    console = Console(record=True, width=96)

    console.print()
    console.rule("[bold]Consentinel[/bold] - MCP excessive-agency & safeguard audit")
    console.print("[dim]$ consentinel scan ./examples/vulnerable_server[/dim]")
    console.print(
        f"[dim]Tools:[/dim] {len(result.tools)}    [dim]Findings:[/dim] {len(result.findings)}"
    )
    console.print()

    _render_tool_table(console, result)
    console.print()

    flagships = [
        f
        for tool, fid in (("send_reply", "CS-A001"), ("delete_records", "CS-A002"))
        for f in result.findings
        if f.tool == tool and f.id == fid
    ]
    console.print(
        f"[bold]Findings[/bold] ({len(result.findings)}) "
        "[dim]— showing the 2 flagship excessive-agency findings[/dim]"
    )
    console.print()
    for f in flagships:
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
        console.print(Padding(detail, (0, 1, 1, 4)))

    remaining = len(result.findings) - len(flagships)
    console.print(
        f"[dim]... plus {remaining} more across groups B-E "
        "(poisoning, secrets, injection, transport).[/dim]"
    )
    console.print()
    console.print(Text(DISCLAIMER, style="dim italic"))

    out = ROOT / "assets" / "consentinel-demo.svg"
    out.parent.mkdir(parents=True, exist_ok=True)
    console.save_svg(str(out), title="consentinel scan")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
