"""Group B — poisoning surface (invisible chars + imperative phrases)."""

from __future__ import annotations

from _util import findings_by_id, ids_for_tool


def test_invisible_char_flagged(result):
    ids = ids_for_tool(result, "list_open_tickets")
    assert "CS-B001" in ids
    finding = [f for f in result.findings if f.id == "CS-B001"][0]
    assert "U+200B" in finding.extra["locations"].get("description", [])


def test_imperative_phrases_flagged(result):
    ids = ids_for_tool(result, "list_open_tickets")
    assert "CS-B002" in ids
    finding = [f for f in result.findings if f.id == "CS-B002" and f.tool == "list_open_tickets"][0]
    phrases = set(finding.extra["phrases"])
    assert "ignore previous" in phrases  # a high-weight override phrase
    assert finding.severity.value == "MED"


def test_clean_tool_not_flagged(result):
    ids = ids_for_tool(result, "get_ticket")
    assert "CS-B001" not in ids
    assert "CS-B002" not in ids


def test_poisoning_only_on_expected_tool(result):
    b_findings = findings_by_id(result, "CS-B001") + findings_by_id(result, "CS-B002")
    assert {f.tool for f in b_findings} == {"list_open_tickets"}
