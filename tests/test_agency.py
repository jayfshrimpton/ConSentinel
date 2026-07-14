"""Group A — the differentiator. Blast radius + enforced-gate verification.

The critical assertions (per spec): send_reply and delete_records are HIGH, purge_cache
passes the enforced-gate check, and get_ticket produces no agency findings.
"""

from __future__ import annotations

from _util import agency_findings_from_source, ids_for_tool, tool_by_name
from consentinel.models import BlastRadius


# -- Blast-radius classification --------------------------------------------------

def test_blast_radius_classification(tools):
    def br(name):
        return tool_by_name(tools, name).blast_radius

    # NOTE: classification is populated by the scan; ensure it ran by scanning.
    from consentinel.checks.agency import AgencyCheck
    from consentinel.checks.base import ScanContext

    AgencyCheck().run(ScanContext(tools=tools))

    assert br("get_ticket") is BlastRadius.READ_ONLY
    assert br("get_asset") is BlastRadius.READ_ONLY
    assert br("send_reply") is BlastRadius.IRREVERSIBLE_OR_EXTERNAL
    assert br("delete_records") is BlastRadius.IRREVERSIBLE_OR_EXTERNAL
    assert br("purge_cache") is BlastRadius.IRREVERSIBLE_OR_EXTERNAL
    assert br("run_command") is BlastRadius.IRREVERSIBLE_OR_EXTERNAL
    assert br("delete_asset") is BlastRadius.IRREVERSIBLE_OR_EXTERNAL


# -- The flagship findings --------------------------------------------------------

def test_send_reply_is_high_no_gate(result):
    """The real-world case: an email tool with no confirmation gate at all."""
    assert "CS-A001" in ids_for_tool(result, "send_reply")
    high = [f for f in result.findings if f.tool == "send_reply" and f.id == "CS-A001"]
    assert high and high[0].severity.value == "HIGH"


def test_delete_records_is_high_unenforced_gate(result):
    """The false-safeguard case: declares `confirmed` but never branches on it."""
    ids = ids_for_tool(result, "delete_records")
    assert "CS-A002" in ids
    assert "CS-A001" not in ids  # it HAS a gate param, so A001 must not fire
    finding = [f for f in result.findings if f.id == "CS-A002" and f.tool == "delete_records"][0]
    assert finding.severity.value == "HIGH"


def test_purge_cache_passes_enforced_gate(result):
    """The correct pattern: `if not confirmed: return` — must NOT be flagged HIGH."""
    ids = ids_for_tool(result, "purge_cache")
    assert "CS-A001" not in ids
    assert "CS-A002" not in ids
    # It is still irreversible, so it may emit the informational PASS marker.
    assert "CS-A003" in ids


def test_get_ticket_has_no_agency_findings(result):
    ids = ids_for_tool(result, "get_ticket")
    assert not any(i.startswith("CS-A") for i in ids)


def test_run_command_and_delete_asset_high_no_gate(result):
    assert "CS-A001" in ids_for_tool(result, "run_command")
    assert "CS-A001" in ids_for_tool(result, "delete_asset")


def test_bulk_pii_tool_not_treated_as_gated_action(result):
    """query_users is rated up for bulk PII but is a read: no gate finding should fire."""
    ids = ids_for_tool(result, "query_users")
    assert "CS-A001" not in ids
    assert "CS-A002" not in ids


# -- Precision of the enforced-gate check (synthetic, control-flow specific) -------

_UNENFORCED = '''
from mcp.server.fastmcp import FastMCP
import os
mcp = FastMCP("x")

@mcp.tool()
def wipe_dir(path: str, confirmed: bool = False) -> str:
    """Wipe a directory."""
    log_flag = confirmed          # referenced, but NOT in any guard
    os.rmdir(path)
    return "done"
'''

_ENFORCED = '''
from mcp.server.fastmcp import FastMCP
import os
mcp = FastMCP("x")

@mcp.tool()
def wipe_dir(path: str, confirmed: bool = False) -> str:
    """Wipe a directory."""
    if not confirmed:
        return "refused"
    os.rmdir(path)
    return "done"
'''


def test_gate_referenced_but_not_branched_is_unenforced(tmp_path):
    findings, _ = agency_findings_from_source(_UNENFORCED, tmp_path)
    ids = {f.id for f in findings}
    assert "CS-A002" in ids  # merely assigning the gate value is not enforcement
    assert "CS-A001" not in ids


def test_gate_branched_is_enforced(tmp_path):
    findings, _ = agency_findings_from_source(_ENFORCED, tmp_path)
    ids = {f.id for f in findings}
    assert "CS-A002" not in ids
    assert "CS-A001" not in ids
    assert "CS-A003" in ids
