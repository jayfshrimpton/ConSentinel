"""Group C — credentials & data exposure."""

from __future__ import annotations

from _util import findings_by_id, ids_for_tool
from consentinel.checks.secrets import _is_placeholder, _provider_match, shannon_entropy


def test_hardcoded_secret_flagged(result):
    c001 = findings_by_id(result, "CS-C001")
    assert c001, "expected a hardcoded-secret finding"
    assert any("github" in f.description.lower() for f in c001)
    assert all(f.severity.value == "HIGH" for f in c001)


def test_secret_in_output_flagged(result):
    ids = ids_for_tool(result, "get_debug_info")
    assert "CS-C002" in ids


def test_bulk_pii_flagged(result):
    ids = ids_for_tool(result, "query_users")
    assert "CS-C003" in ids
    assert "CS-C003" not in ids_for_tool(result, "get_ticket")


def test_clean_tool_has_no_secret_findings(result):
    ids = ids_for_tool(result, "get_ticket")
    assert not any(i.startswith("CS-C") for i in ids)


# -- unit-level guards against false positives ------------------------------------

def test_provider_pattern_matches_github_token():
    assert _provider_match("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")
    assert _provider_match("AKIAIOSFODNN7EXAMPLZ")  # AWS access key id shape


def test_placeholders_are_excluded():
    assert _is_placeholder("your_api_key_here")
    assert _is_placeholder("CHANGEME")
    assert _is_placeholder("123e4567-e89b-12d3-a456-426614174000")  # a UUID
    assert not _is_placeholder("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")


def test_entropy_ranks_random_above_words():
    assert shannon_entropy("aaaaaaaaaa") < shannon_entropy("A1b2C3d4E5f6G7h8I9j0")
