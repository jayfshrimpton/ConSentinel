"""Consentinel — a static safeguard-enforcement auditor for MCP servers.

Consentinel finds MCP tools that perform irreversible or externally side-effecting
actions and lack an enforced human-in-the-loop safeguard.

Static analysis only: Consentinel never imports or executes the target server. It
parses source with the :mod:`ast` module and reports *risks* / *missing safeguards*,
never confirmed exploits.
"""

__version__ = "0.1.0"

DISCLAIMER = (
    "Consentinel verifies declared, in-code safeguards, not runtime behaviour. By "
    "design it will not catch output-side / runtime-conditional poisoning (the "
    '"advanced tool poisoning" / ATPA class). Findings describe risks and missing '
    "safeguards, not confirmed exploits."
)

__all__ = ["__version__", "DISCLAIMER"]
