"""Group E — transport without authentication."""

from __future__ import annotations

from _util import findings_by_id


def test_unauthenticated_transport_flagged(result):
    e001 = findings_by_id(result, "CS-E001")
    assert e001, "expected an unauthenticated-transport finding"
    assert all(f.severity.value == "LOW" for f in e001)
    # It should point at the low-level server that starts the SSE transport.
    assert any(f.file.endswith("lowlevel_server.py") for f in e001)


def test_stdio_server_not_flagged(result):
    # fastmcp_server uses the default stdio transport (mcp.run()) — no E001 there.
    e001 = findings_by_id(result, "CS-E001")
    assert not any(f.file.endswith("fastmcp_server.py") for f in e001)


def test_auth_present_suppresses_finding(tmp_path):
    """A network transport with auth machinery referenced in code must not be flagged."""
    from consentinel.checks.base import ScanContext
    from consentinel.checks.transport import TransportCheck
    from consentinel.extract.python_ast import PythonBackend

    src = '''
import uvicorn
from starlette.applications import Starlette
from starlette.middleware.authentication import AuthenticationMiddleware

def main():
    app = Starlette()
    app.add_middleware(AuthenticationMiddleware, backend=None)
    uvicorn.run(app, host="127.0.0.1", port=8000)
'''
    f = tmp_path / "authed.py"
    f.write_text(src, encoding="utf-8")
    be = PythonBackend()
    be.extract_tools(f)
    ctx = ScanContext(tools=[], sources=be.sources, trees=be.trees)
    findings = TransportCheck().run(ctx)
    assert not findings
