"""LanguageBackend ABC — the extension seam for future language backends.

A backend takes a codebase path and returns normalised :class:`~consentinel.models.Tool`
objects. v1 implements only :class:`~consentinel.extract.python_ast.PythonBackend`; a
TypeScript backend could be added later by implementing this same interface (it is
intentionally *not* built in v1).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from consentinel.models import Tool


class LanguageBackend(ABC):
    """Extract MCP tool definitions from a codebase in one source language."""

    #: File extensions this backend understands, e.g. ``(".py",)``.
    extensions: tuple[str, ...] = ()

    #: Short human-readable language name.
    language: str = ""

    @abstractmethod
    def extract_tools(self, path: Path) -> list[Tool]:
        """Return every tool discovered under ``path`` (a file or directory)."""
        raise NotImplementedError

    def source_files(self, path: Path) -> list[Path]:
        """Enumerate candidate source files under ``path`` for this backend."""
        path = Path(path)
        if path.is_file():
            return [path] if path.suffix in self.extensions else []
        files: list[Path] = []
        for ext in self.extensions:
            files.extend(sorted(path.rglob(f"*{ext}")))
        # Skip common noise directories.
        skip = {".git", ".venv", "venv", "__pycache__", "node_modules", ".tox", "build", "dist"}
        return [f for f in files if not any(part in skip for part in f.parts)]
