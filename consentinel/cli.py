"""Consentinel CLI (typer): ``consentinel scan <path> [options]``."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console


def _force_utf8_stdio() -> None:
    """Make stdout/stderr tolerate non-ASCII output on legacy Windows codepages.

    Terminal output should never crash the audit; reconfigure to UTF-8 and replace any
    character the terminal cannot encode rather than raising UnicodeEncodeError.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


_force_utf8_stdio()

from consentinel import __version__
from consentinel.checks.base import scan_path
from consentinel.models import Severity
from consentinel.report.json_report import to_payload
from consentinel.report.markdown import build_markdown
from consentinel.report.terminal import render_terminal

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Consentinel — find MCP tools that perform irreversible or externally "
    "side-effecting actions and lack an enforced human-in-the-loop safeguard.",
)


class OutputFormat(str, Enum):
    table = "table"
    json = "json"
    md = "md"


class FailOn(str, Enum):
    high = "high"
    med = "med"
    low = "low"
    none = "none"


_FAIL_THRESHOLD = {
    FailOn.high: Severity.HIGH,
    FailOn.med: Severity.MED,
    FailOn.low: Severity.LOW,
    FailOn.none: None,
}


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"consentinel {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """Static safeguard-enforcement auditor for MCP servers."""


@app.command()
def scan(
    path: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to the MCP server codebase (file or directory)."
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.table, "--format", "-f", help="Output format."
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write the report (JSON or Markdown) to this file."
    ),
    fail_on: FailOn = typer.Option(
        FailOn.high, "--fail-on", help="Minimum severity that makes the command exit non-zero (CI gate)."
    ),
) -> None:
    """Scan an MCP server codebase and report excessive-agency & safeguard risks."""
    console = Console()
    result = scan_path(path)
    target = str(path)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if output_format is OutputFormat.table:
        render_terminal(console, result, target)
        if output is not None:
            payload = to_payload(result, target, generated_at)
            output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            console.print(f"[dim]JSON report written to {output}[/dim]")
    elif output_format is OutputFormat.json:
        text = json.dumps(to_payload(result, target, generated_at), indent=2)
        if output is not None:
            output.write_text(text, encoding="utf-8")
            console.print(f"[dim]JSON report written to {output}[/dim]")
        else:
            typer.echo(text)
    else:  # markdown
        md = build_markdown(result, target, generated_at)
        if output is not None:
            output.write_text(md, encoding="utf-8")
            console.print(f"[dim]Markdown report written to {output}[/dim]")
        else:
            typer.echo(md)

    threshold = _FAIL_THRESHOLD[fail_on]
    if threshold is not None:
        worst = max((f.severity for f in result.findings), default=None)
        if worst is not None and worst.rank >= threshold.rank:
            raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
