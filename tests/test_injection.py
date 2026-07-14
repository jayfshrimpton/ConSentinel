"""Group D — injection (command, SQL, path traversal)."""

from __future__ import annotations

from _util import ids_for_tool


def test_command_injection_flagged(result):
    ids = ids_for_tool(result, "run_command")
    assert "CS-D001" in ids
    finding = [f for f in result.findings if f.id == "CS-D001"][0]
    assert finding.extra.get("param") == "cmd"
    assert finding.severity.value == "HIGH"


def test_sql_injection_flagged(result):
    ids = ids_for_tool(result, "query_users")
    assert "CS-D002" in ids
    finding = [f for f in result.findings if f.id == "CS-D002" and f.tool == "query_users"][0]
    assert finding.extra.get("param") == "name"


def test_path_traversal_flagged(result):
    ids = ids_for_tool(result, "read_attachment")
    assert "CS-D003" in ids


def test_parameterised_query_not_flagged(result):
    # delete_records uses a bind-parameter query, so it must NOT be a SQL-injection hit.
    assert "CS-D002" not in ids_for_tool(result, "delete_records")


def test_clean_tool_has_no_injection_findings(result):
    ids = ids_for_tool(result, "get_ticket")
    assert not any(i.startswith("CS-D") for i in ids)
