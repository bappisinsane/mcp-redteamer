"""Unit tests for MCPClientWrapper (mocked transport)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_redteamer.mcp_client import MCPClientWrapper


def _mock_tool(name: str) -> MagicMock:
    t = MagicMock()
    t.name = name
    t.description = f"desc {name}"
    t.inputSchema = {"type": "object"}
    return t


async def _run() -> None:
    with patch("mcp_redteamer.mcp_client.stdio_client") as mock_stdio, patch(
        "mcp_redteamer.mcp_client.ClientSession"
    ) as mock_session_cls:
        mock_session = AsyncMock()
        mock_session.initialize = AsyncMock()
        mock_session.list_tools = AsyncMock(return_value=MagicMock(tools=[_mock_tool("read_file")]))
        mock_session.list_resources = AsyncMock(return_value=MagicMock(resources=[]))
        mock_session.call_tool = AsyncMock(
            return_value=MagicMock(content=[MagicMock(type="text", text="hello")])
        )
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        mock_stdio.return_value.__aenter__ = AsyncMock(return_value=(AsyncMock(), AsyncMock()))
        mock_stdio.return_value.__aexit__ = AsyncMock(return_value=False)

        async with MCPClientWrapper("python", ["server.py"], timeout=5) as client:
            tools = await client.list_tools()
            assert tools == [{"name": "read_file", "description": "desc read_file", "schema": {"type": "object"}}]
            res = await client.call_tool("read_file", {"path": "/a"})
            assert res == [{"type": "text", "text": "hello"}]
            assert await client.list_resources() == []


def test_mcp_client_wrapper() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    test_mcp_client_wrapper()
    print("OK")
