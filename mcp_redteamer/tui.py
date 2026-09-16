"""Rich TUI dashboard for live attack progression and final scorecard."""

from __future__ import annotations

import time
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_redteamer.evaluator import SEVERITIES

SEV_COLORS = {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "yellow", "LOW": "blue"}


class TUIDashboard:
    """Minimal live dashboard: attack log + scorecard."""

    def __init__(self) -> None:
        self.console = Console()
        self.events: list[str] = []
        self.findings: list[dict[str, Any]] = []
        self.started = time.time()

    def log(self, msg: str) -> None:
        self.events.append(msg)
        if len(self.events) > 12:
            self.events.pop(0)

    def add_finding(self, finding: dict[str, Any]) -> None:
        self.findings.append(finding)

    def _attack_table(self) -> Panel:
        t = Table(title=f"Attacks ({time.time() - self.started:.0f}s)", expand=True)
        t.add_column("Log")
        for line in self.events[-12:]:
            t.add_row(line)
        return Panel(t, title="[bold]mcp-redteamer[/bold]")

    def _scorecard(self) -> Panel:
        t = Table(title="Findings")
        t.add_column("Severity", style="bold")
        t.add_column("Rule")
        t.add_column("Tool")
        t.add_column("Evidence")
        for f in self.findings:
            t.add_row(
                Text(f["severity"], style=SEV_COLORS.get(f["severity"], "white")),
                f["rule"], f["tool"], f["evidence"][:40],
            )
        return Panel(t, title="Scorecard")

    def render(self) -> None:
        from rich.columns import Columns
        self.console.print(Columns([self._attack_table(), self._scorecard()]))

    def summary(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            counts[f["severity"]] += 1
        return counts

    def print_summary(self) -> None:
        counts = self.summary()
        line = "  ".join(f"[{SEV_COLORS[s]}]{s}: {counts[s]}[/{SEV_COLORS[s]}]" for s in SEVERITIES)
        self.console.print(Panel(line, title="Final Scorecard"))
