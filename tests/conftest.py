"""Pytest fixtures: scan the bundled vulnerable example server once per session."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the shared helper module importable as `_util`.
sys.path.insert(0, str(Path(__file__).parent))

from consentinel.checks.base import ScanResult, scan_path  # noqa: E402
from consentinel.extract.python_ast import PythonBackend  # noqa: E402
from consentinel.models import Tool  # noqa: E402

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_server"


@pytest.fixture(scope="session")
def examples_path() -> Path:
    assert EXAMPLES.is_dir(), f"example server not found at {EXAMPLES}"
    return EXAMPLES


@pytest.fixture(scope="session")
def result(examples_path: Path) -> ScanResult:
    return scan_path(examples_path)


@pytest.fixture(scope="session")
def tools(examples_path: Path) -> list[Tool]:
    return PythonBackend().extract_tools(examples_path)
