"""OWASP mapping table.

Maps each Consentinel check id to an OWASP category. The primary framing is the OWASP
Agentic AI Top 10 (Excessive Agency / Tool Misuse is Consentinel's centre of gravity);
where a finding also aligns with the widely-cited OWASP Top 10 for LLM Applications
(prompt injection, insecure output handling, sensitive information disclosure) that is
noted in the same human-readable string.
"""

from __future__ import annotations

# Canonical category strings (human-readable; cross-referenced to the LLM Top 10).
EXCESSIVE_AGENCY = "Excessive Agency / Tool Misuse (OWASP Agentic AI; LLM06 Excessive Agency)"
PROMPT_INJECTION = "Prompt Injection (OWASP Agentic AI; LLM01 Prompt Injection)"
INSECURE_OUTPUT = "Insecure Output Handling (LLM02 Insecure Output Handling)"
SENSITIVE_INFO = "Sensitive Information Disclosure (LLM06/LLM02; OWASP Agentic AI data exposure)"
INSECURE_TRANSPORT = "Excessive Agency / Insecure Transport (OWASP Agentic AI; unauthenticated exposure)"

OWASP_MAP: dict[str, str] = {
    # Group A — excessive agency (core)
    "CS-A001": EXCESSIVE_AGENCY,
    "CS-A002": EXCESSIVE_AGENCY,
    "CS-A003": EXCESSIVE_AGENCY,
    # Group B — poisoning surface
    "CS-B001": PROMPT_INJECTION,
    "CS-B002": PROMPT_INJECTION,
    # Group C — credentials & data exposure
    "CS-C001": SENSITIVE_INFO,
    "CS-C002": SENSITIVE_INFO + " + " + INSECURE_OUTPUT,
    "CS-C003": SENSITIVE_INFO,
    # Group D — injection
    "CS-D001": PROMPT_INJECTION + " + " + INSECURE_OUTPUT,
    "CS-D002": PROMPT_INJECTION + " + " + INSECURE_OUTPUT,
    "CS-D003": INSECURE_OUTPUT,
    # Group E — transport
    "CS-E001": INSECURE_TRANSPORT,
}


def owasp_for(check_id: str) -> str:
    """Return the OWASP category for a check id, or a sensible default."""
    return OWASP_MAP.get(check_id, EXCESSIVE_AGENCY)
