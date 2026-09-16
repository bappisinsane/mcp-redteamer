"""Attack orchestration: target -> discover -> synthesize -> execute -> evaluate."""

from __future__ import annotations

from typing import Any

from mcp_redteamer.attacker.synthesizer import Synthesizer
from mcp_redteamer.evaluator import EvalResult, Evaluator
from mcp_redteamer.mcp_client import MCPClientWrapper
from mcp_redteamer.tui import TUIDashboard


class AttackEngine:
    """Drive the full red-team pipeline over a live MCP target."""

    def __init__(
        self,
        client: MCPClientWrapper,
        synthesizer: Synthesizer | None = None,
        evaluator: Evaluator | None = None,
        dashboard: TUIDashboard | None = None,
    ) -> None:
        self.client = client
        self.synthesizer = synthesizer or Synthesizer()
        self.evaluator = evaluator or Evaluator()
        self.dash = dashboard or TUIDashboard()

    async def run(self) -> list[EvalResult]:
        await self.client.connect()
        try:
            tools = await self.client.list_tools()
            self.dash.log(f"Discovered {len(tools)} tools: {', '.join(t['name'] for t in tools)}")
            attacks = await self.synthesizer.generate_all(tools)
            self.dash.log(f"Generated {len(attacks)} attack payloads")
            results: list[EvalResult] = []
            for atk in attacks:
                self.dash.log(f"[>] {atk['attack_type']} on {atk['tool']}: {atk['payload']}")
                try:
                    response = await self.client.call_tool(atk["tool"], atk["payload"])
                except Exception as exc:
                    self.dash.log(f"[!] tool error: {exc}")
                    continue
                res = self.evaluator.evaluate(atk["tool"], atk["attack_type"], atk["payload"], response)
                results.append(res)
                for f in res.findings:
                    self.dash.add_finding(f.__dict__)
                    self.dash.log(f"[BREACH:{f.severity}] {f.rule} on {f.tool}")
                self.dash.render()
            return results
        finally:
            await self.client.close()
