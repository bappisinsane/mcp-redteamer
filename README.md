# mcp-redteamer

Autonomous Model Context Protocol (MCP) Exploitation & AI Red-Teamer.

An automated security auditing tool designed to test MCP servers and LLM agents for vulnerabilities, including indirect prompt injection, tool hijacking, and unauthorized file access.

## Key Features

* **Isolated Target Execution:** Automated lifecycle management (spin-up, health check, teardown) of target MCP servers in ephemeral, isolated Docker containers.
* **Dynamic Attack Synthesis:** Local LLM-driven payload generation targeting specific MCP tool schemas.
* **MCP Protocol Driver:** Native communication with targets over stdio/SSE using the official Python SDK.
* **Automated Response Evaluation:** Real-time analysis of agent/tool responses to detect security breaches or out-of-bounds tool calls.
* **Rich TUI Dashboard:** Terminal dashboard displaying real-time attack trees, payload logs, and vulnerability scorecards.

## Quick Start

```bash
# Install dependencies
pip install .

# Run a security audit
mcp-redteamer run --target ./targets/my-mcp-server --config config.yaml
```

## Architecture

* **Engine:** Orchestrates the attack lifecycle.
* **Attacker:** Generates malicious prompts/inputs based on target schemas.
* **MCP Client:** Communicates with the target MCP server.
* **Evaluator:** Analyzes responses to determine if an attack succeeded.
* **TUI:** Displays progress and results in the terminal.
