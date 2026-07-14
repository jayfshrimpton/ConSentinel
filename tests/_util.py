"""Shared test helpers."""

from __future__ import annotations

from consentinel.checks.base import ScanContext, ScanResult
from consentinel.checks.agency import AgencyCheck
from consentinel.extract.python_ast import PythonBackend
from consentinel.models import Tool


def ids_for_tool(result: ScanResult, tool: str) -> set[str]:
    return {f.id for f in result.findings if f.tool == tool}


def findings_by_id(result: ScanResult, finding_id: str):
    return [f for f in result.findings if f.id == finding_id]


def tool_by_name(tools: list[Tool], name: str) -> Tool:
    for t in tools:
        if t.name == name:
            return t
    raise AssertionError(f"tool {name!r} not extracted (have: {[t.name for t in tools]})")


def tools_from_source(src: str, tmp_path) -> list[Tool]:
    """Extract tools from an inline source string (written to a temp file)."""
    f = tmp_path / "snippet.py"
    f.write_text(src, encoding="utf-8")
    return PythonBackend().extract_tools(f)


def agency_findings_from_source(src: str, tmp_path):
    """Run Group A over an inline source string and return its findings + tools."""
    tools = tools_from_source(src, tmp_path)
    ctx = ScanContext(tools=tools)
    return AgencyCheck().run(ctx), tools
