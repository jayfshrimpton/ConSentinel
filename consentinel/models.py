"""Core data models: Tool, Param, Finding, and the Severity / BlastRadius / CheckGroup enums.

These are the shared vocabulary between the extraction layer (:mod:`consentinel.extract`),
the checks (:mod:`consentinel.checks`), and the reporters (:mod:`consentinel.report`).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Finding severity, ordered HIGH > MED > LOW > INFO."""

    HIGH = "HIGH"
    MED = "MED"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Higher rank == more severe. Used for sorting and ``--fail-on`` thresholds."""
        return _SEVERITY_RANK[self]

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MED: 2,
    Severity.HIGH: 3,
}


class BlastRadius(str, Enum):
    """How much damage a tool's handler can do if invoked without a safeguard."""

    READ_ONLY = "READ_ONLY"
    REVERSIBLE_WRITE = "REVERSIBLE_WRITE"
    IRREVERSIBLE_OR_EXTERNAL = "IRREVERSIBLE_OR_EXTERNAL"

    @property
    def rank(self) -> int:
        return _BLAST_RANK[self]


_BLAST_RANK: dict[BlastRadius, int] = {
    BlastRadius.READ_ONLY: 0,
    BlastRadius.REVERSIBLE_WRITE: 1,
    BlastRadius.IRREVERSIBLE_OR_EXTERNAL: 2,
}


class CheckGroup(str, Enum):
    """Which family of checks a finding belongs to."""

    A = "A"  # Blast radius & excessive agency (core)
    B = "B"  # Tool-poisoning surface
    C = "C"  # Credentials & data exposure
    D = "D"  # Injection
    E = "E"  # Transport


@dataclass
class Param:
    """A single tool parameter."""

    name: str
    annotation: str | None = None
    default: str | None = None
    is_gate: bool = False


@dataclass
class Tool:
    """A normalised MCP tool definition, independent of how it was declared.

    ``body`` is the list of AST statements of the handler (for a low-level dispatch
    tool this is the matched branch body). ``raw_schema`` holds the JSON input schema
    for low-level tools so poisoning checks can scan param names / enums.
    """

    name: str
    description: str | None
    parameters: list[Param]
    body: list[ast.stmt]
    file: str
    line: int
    end_line: int | None = None
    style: str = "fastmcp"  # "fastmcp" | "lowlevel"
    raw_schema: dict | None = None
    # Set by Group A after classification; other checks may read it.
    blast_radius: BlastRadius = BlastRadius.READ_ONLY

    @property
    def gate_params(self) -> list[Param]:
        return [p for p in self.parameters if p.is_gate]


@dataclass
class Finding:
    """A single audit finding with a stable, machine-readable schema."""

    id: str
    severity: Severity
    tool: str
    file: str
    line: int
    description: str
    remediation: str
    owasp: str
    check_group: CheckGroup
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity.value,
            "tool": self.tool,
            "file": self.file,
            "line": self.line,
            "description": self.description,
            "remediation": self.remediation,
            "owasp": self.owasp,
            "check_group": self.check_group.value,
            **({"extra": self.extra} if self.extra else {}),
        }
