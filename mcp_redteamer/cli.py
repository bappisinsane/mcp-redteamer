"""CLI entry point for mcp-redteamer."""

import asyncio
from pathlib import Path

import typer
from rich.console import Console

from mcp_redteamer.engine import AttackEngine
from mcp_redteamer.mcp_client import MCPClientWrapper
from mcp_redteamer.report import export_html, export_markdown
from mcp_redteamer.attacker.synthesizer import Synthesizer
from mcp_redteamer.target_manager import TargetManager
from mcp_redteamer.tui import TUIDashboard

app = typer.Typer(help="mcp-redteamer: Automated MCP security auditing")
console = Console()


@app.command()
def audit(
    target: str = typer.Option(..., help="Path to target MCP server directory containing Dockerfile"),
    llm_url: str = typer.Option("http://localhost:11434", help="Ollama/vLLM base URL"),
    model: str = typer.Option("qwen2.5-coder", help="LLM model name"),
    report_dir: str = typer.Option("reports", help="Directory for exported reports"),
    server_cmd: str = typer.Option("python /app/server.py", help="Command to launch MCP server inside container"),
) -> None:
    """Full red-team audit: spin up target, synthesize attacks, evaluate, report."""
    asyncio.run(_audit(target, llm_url, model, Path(report_dir), server_cmd.split()))


async def _audit(target: str, llm_url: str, model: str, report_dir: Path, server_cmd: list[str]) -> None:
    tm = TargetManager()
    dash = TUIDashboard()
    container = None
    try:
        container = await tm.start(target)
        dash.log(f"Target started: {container.short_id}")
        # ponytail: docker-exec stdio bridge needs the docker CLI on host; swap for
        # an attach-socket transport if the daemon API is the only available path
        client = MCPClientWrapper("docker", ["exec", "-i", container.id, *server_cmd])
        engine = AttackEngine(client, Synthesizer(base_url=llm_url, model=model), dashboard=dash)
        results = await engine.run()
        counts = dash.summary()
        dash.print_summary()
        findings = [f.__dict__ for r in results for f in r.findings]
        report_dir.mkdir(parents=True, exist_ok=True)
        md = export_markdown(findings, report_dir / "report.md")
        export_html(findings, report_dir / "report.html")
        console.print(f"[green]Reports written:[/green] {md}, report.html")
    finally:
        if container:
            await tm.stop(container.id)
            dash.log("Target torn down.")


if __name__ == "__main__":
    app()
