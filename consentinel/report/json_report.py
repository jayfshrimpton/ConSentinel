"""JSON report: a stable, machine-readable payload for CI and tooling."""

from __future__ import annotations

from collections import Counter

from consentinel import DISCLAIMER, __version__
from consentinel.checks.base import ScanResult
from consentinel.models import Severity


def severity_counts(result: ScanResult) -> dict[str, int]:
    counts = Counter(f.severity.value for f in result.findings)
    return {sev.value: counts.get(sev.value, 0) for sev in Severity}


def blast_counts(result: ScanResult) -> dict[str, int]:
    counts = Counter(t.blast_radius.value for t in result.tools)
    return dict(counts)


def to_payload(result: ScanResult, target: str, generated_at: str | None = None) -> dict:
    """Build the JSON payload. ``generated_at`` is injected by the caller (testable)."""
    tools = [
        {
            "name": t.name,
            "style": t.style,
            "blast_radius": t.blast_radius.value,
            "file": t.file,
            "line": t.line,
            "parameters": [p.name for p in t.parameters],
            "gate_params": [p.name for p in t.gate_params],
            "finding_count": sum(1 for f in result.findings if f.tool == t.name),
        }
        for t in result.tools
    ]
    payload = {
        "tool": "consentinel",
        "version": __version__,
        "target": target,
        "disclaimer": DISCLAIMER,
        "summary": {
            "tools": len(result.tools),
            "findings": len(result.findings),
            "by_severity": severity_counts(result),
            "by_blast_radius": blast_counts(result),
        },
        "tools": tools,
        "findings": [f.to_dict() for f in result.findings],
    }
    if result.errors:
        payload["parse_errors"] = result.errors
    if generated_at is not None:
        payload["generated_at"] = generated_at
    return payload
