"""INTENTIONALLY VULNERABLE MCP server (low-level Server / call_tool dispatch style).

Test fixture / demo target for Consentinel — deliberately insecure, NOT meant to run.
Exercises the low-level extractor: a @server.list_tools() registry plus a
@server.call_tool() handler that dispatches on the tool name. Also starts an
unauthenticated SSE transport (Group E).
"""

import os

import mcp.types as types
from mcp.server import Server
from mcp.server.sse import SseServerTransport


class _AssetDB:
    def lookup(self, tag):
        return {"tag": tag, "location": "warehouse-1"}


db = _AssetDB()
server = Server("it-assets-lowlevel")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="get_asset",
            description="Look up an IT asset by its asset tag.",
            inputSchema={
                "type": "object",
                "properties": {"tag": {"type": "string"}},
                "required": ["tag"],
            },
        ),
        types.Tool(
            name="delete_asset",
            description="Permanently delete an IT asset record and its file.",
            inputSchema={
                "type": "object",
                "properties": {"tag": {"type": "string"}},
                "required": ["tag"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "get_asset":
        tag = arguments["tag"]
        asset = db.lookup(tag)
        return [types.TextContent(type="text", text=str(asset))]
    elif name == "delete_asset":
        tag = arguments["tag"]
        os.remove(f"/var/assets/{tag}.json")
        return [types.TextContent(type="text", text=f"deleted {tag}")]
    return [types.TextContent(type="text", text="unknown tool")]


def main() -> None:
    # SSE transport bound to all interfaces with no authentication (Group E).
    import uvicorn
    from starlette.applications import Starlette
    from starlette.routing import Mount

    transport = SseServerTransport("/messages")
    app = Starlette(routes=[Mount("/messages", app=transport.handle_post_message)])
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
