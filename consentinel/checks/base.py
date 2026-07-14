"""Check ABC, scan context, orchestrator, and the ordered check registry.

Group A (agency) always runs first because it sets each tool's blast radius, which the
reporters and other checks may read.
"""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from consentinel.extract.base import LanguageBackend
from consentinel.extract.python_ast import PythonBackend
from consentinel.models import CheckGroup, Finding, Tool


@dataclass
class ScanContext:
    """Everything a check needs: the tools plus the raw sources / parsed trees."""

    tools: list[Tool]
    sources: dict[str, str] = field(default_factory=dict)
    trees: dict[str, ast.Module] = field(default_factory=dict)


@dataclass
class ScanResult:
    tools: list[Tool]
    findings: list[Finding]
    errors: list[str] = field(default_factory=list)


class Check(ABC):
    """A single check group. Instances are cheap and stateless."""

    group: CheckGroup

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]:
        raise NotImplementedError


def _ordered_checks() -> list[Check]:
    """Instantiate checks in run order. Agency (Group A) MUST be first."""
    from consentinel.checks.agency import AgencyCheck
    from consentinel.checks.injection import InjectionCheck
    from consentinel.checks.poisoning import PoisoningCheck
    from consentinel.checks.secrets import SecretsCheck
    from consentinel.checks.transport import TransportCheck

    return [
        AgencyCheck(),
        PoisoningCheck(),
        SecretsCheck(),
        InjectionCheck(),
        TransportCheck(),
    ]


def scan_path(path: str | Path, backend: LanguageBackend | None = None) -> ScanResult:
    """Extract tools from ``path`` and run every check group against them."""
    backend = backend or PythonBackend()
    tools = backend.extract_tools(Path(path))
    sources = getattr(backend, "sources", {})
    trees = getattr(backend, "trees", {})
    ctx = ScanContext(tools=tools, sources=sources, trees=trees)

    findings: list[Finding] = []
    for check in _ordered_checks():
        findings.extend(check.run(ctx))

    findings.sort(key=lambda f: (-f.severity.rank, f.id, f.tool, f.line))
    return ScanResult(tools=tools, findings=findings, errors=list(getattr(backend, "errors", [])))
