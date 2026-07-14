"""Extraction layer: both FastMCP decorator style and low-level dispatch style."""

from __future__ import annotations

from _util import tool_by_name


def test_no_parse_errors(result):
    assert result.errors == []


def test_both_styles_and_all_tools_found(tools):
    names = {t.name for t in tools}
    # FastMCP decorator style
    assert {
        "get_ticket",
        "send_reply",
        "delete_records",
        "purge_cache",
        "run_command",
        "query_users",
        "list_open_tickets",
        "read_attachment",
        "get_debug_info",
    } <= names
    # Low-level Server / call_tool dispatch style
    assert {"get_asset", "delete_asset"} <= names


def test_fastmcp_style_and_params(tools):
    send = tool_by_name(tools, "send_reply")
    assert send.style == "fastmcp"
    assert [p.name for p in send.parameters] == ["ticket_id", "body"]
    assert send.file.endswith("fastmcp_server.py")
    assert send.line > 0 and send.end_line is not None and send.end_line >= send.line


def test_gate_params_flagged(tools):
    delete = tool_by_name(tools, "delete_records")
    gate = {p.name for p in delete.gate_params}
    assert gate == {"confirmed"}

    purge = tool_by_name(tools, "purge_cache")
    assert {p.name for p in purge.gate_params} == {"confirmed"}

    # A tool with no gate parameter reports none.
    assert tool_by_name(tools, "send_reply").gate_params == []


def test_lowlevel_dispatch_extraction(tools):
    get_asset = tool_by_name(tools, "get_asset")
    delete_asset = tool_by_name(tools, "delete_asset")

    assert get_asset.style == "lowlevel"
    assert delete_asset.style == "lowlevel"

    # Description and params come from the list_tools() schema registry.
    assert delete_asset.description and "delete" in delete_asset.description.lower()
    assert [p.name for p in delete_asset.parameters] == ["tag"]
    assert delete_asset.raw_schema is not None

    # The per-tool dispatch branch body was actually captured (non-empty).
    assert delete_asset.body, "delete_asset branch body should be extracted"
    assert get_asset.body, "get_asset branch body should be extracted"


def test_dispatch_bodies_are_distinct(tools):
    import ast

    delete_asset = tool_by_name(tools, "delete_asset")
    # The delete_asset branch should contain the os.remove call, not get_asset's lookup.
    calls = {
        node.func.attr
        for stmt in delete_asset.body
        for node in ast.walk(stmt)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "remove" in calls
