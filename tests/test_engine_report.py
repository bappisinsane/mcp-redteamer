"""Unit tests for AttackEngine and report exporters."""

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

from mcp_redteamer.engine import AttackEngine
from mcp_redteamer.evaluator import Evaluator
from mcp_redteamer.mcp_client import MCPClientWrapper
from mcp_redteamer.report import export_html, export_markdown
from mcp_redteamer.tui import TUIDashboard


class FakeSynth:
    async def generate_all(self, tools: list[dict]) -> list[dict]:
        return [{"tool": t["name"], "attack_type": "path_traversal", "payload": {}} for t in tools]

    async def close(self) -> None: ...


def test_engine_full_pipeline() -> None:
    async def run() -> None:
        client = AsyncMock(spec=MCPClientWrapper)
        client.list_tools = AsyncMock(
            return_value=[{"name": "read_file", "description": "d", "schema": {}}]
        )
        client.call_tool = AsyncMock(
            return_value=[{"type": "text", "text": "MOCK_FLAG{test_payload_token_123}"}]
        )
        dash = TUIDashboard()
        engine = AttackEngine(client, synthesizer=FakeSynth(), dashboard=dash)  # type: ignore[arg-type]
        results = await engine.run()
        assert len(results) == 1 and results[0].breached
        assert dash.summary()["CRITICAL"] == 1
        client.connect.assert_awaited_once()
        client.close.assert_awaited_once()

    asyncio.run(run())


def test_report_exporters() -> None:
    findings = [
        {"severity": "CRITICAL", "rule": "mock_flag_leak", "tool": "read_file",
         "attack_type": "path_traversal", "evidence": "MOCK_FLAG{x}", "payload": {"p": 1},
         "description": "d"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        md = export_markdown(findings, Path(tmp) / "r.md")
        html = export_html(findings, Path(tmp) / "r.html")
        text = md.read_text(encoding="utf-8")
        assert "| CRITICAL | 1 |" in text
        assert "mock_flag_leak" in text
        assert "Remediation" in text
        assert "<html>" in html.read_text(encoding="utf-8")


if __name__ == "__main__":
    test_engine_full_pipeline()
    test_report_exporters()
    print("OK")
