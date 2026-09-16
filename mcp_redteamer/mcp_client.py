"""MCP client wrapper for talking to target containers."""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class MCPClientWrapper:
    """Wrap MCP stdio client with auto-discovery and timeout guards."""

    def __init__(self, command: str, args: list[str], timeout: float = 10.0) -> None:
        self.params = StdioServerParameters(command=command, args=args)
        self.timeout = timeout
        self._stack: AsyncExitStack | None = None
        self.session: ClientSession | None = None

    async def connect(self) -> None:
        self._stack = AsyncExitStack()
        transport = await self._stack.enter_async_context(stdio_client(self.params))
        read, write = transport
        self.session = await self._stack.enter_async_context(ClientSession(read, write))
        await asyncio.wait_for(self.session.initialize(), timeout=self.timeout)

    async def list_tools(self) -> list[dict[str, Any]]:
        if self.session is None:
            raise RuntimeError("Not connected")
        result = await asyncio.wait_for(self.session.list_tools(), timeout=self.timeout)
        # ponytail: mcp 2.x returns ListToolsResult with .tools list of Tool objects
        return [{"name": t.name, "description": t.description, "schema": t.inputSchema} for t in result.tools]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> list[dict[str, Any]]:
        if self.session is None:
            raise RuntimeError("Not connected")
        result = await asyncio.wait_for(self.session.call_tool(name, arguments), timeout=self.timeout)
        return [{"type": c.type, "text": getattr(c, "text", None)} for c in result.content]

    async def list_resources(self) -> list[dict[str, Any]]:
        if self.session is None:
            raise RuntimeError("Not connected")
        result = await asyncio.wait_for(self.session.list_resources(), timeout=self.timeout)
        return [{"uri": r.uri, "name": r.name} for r in result.resources]

    async def close(self) -> None:
        if self._stack is not None:
            await self._stack.aclose()
            self._stack = None
            self.session = None

    async def __aenter__(self) -> MCPClientWrapper:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
