"""Reporters: rich terminal table, JSON, and Markdown audit report."""

from consentinel.report.json_report import to_payload
from consentinel.report.markdown import build_markdown
from consentinel.report.terminal import render_terminal

__all__ = ["to_payload", "build_markdown", "render_terminal"]
