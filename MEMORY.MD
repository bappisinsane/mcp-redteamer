# Project Memory & State Tracker

## Current Project Status
* **Active Phase:** Phase 2 (MCP Client Protocol Integration)
* **Status:** Phase 1 complete. Python package, CLI (Typer), TargetManager (Docker SDK), and sample vulnerable MCP server are implemented and tested.

## Completed Work
* `pyproject.toml` with CLI entry point `mcp-redteamer`
* `mcp_redteamer/cli.py` — Typer CLI with `run` command
* `mcp_redteamer/target_manager.py` — Docker lifecycle (build, run, stop, exec) with cgroup/cap limits
* `targets/sample_mcp_server/server.py` — Dummy MCP server with vulnerable `read_file`, `write_file`, `list_directory`, `exec_command`
* `targets/sample_mcp_server/Dockerfile` — Slim Python image, non-root user, dropped caps
* `tests/test_phase1.py` — Mock-based unit tests for TargetManager + smoke tests

## Architectural Decisions
* Chosen Python `mcp` SDK (v2.1.1) to ensure full specification compliance for stdio and SSE transport mechanisms.
* Sandboxing strategy relies on Docker containers running with constrained resource limits and dummy target files (`MOCK_FLAG{...}`).
* Local LLM communication configured for Ollama / vLLM HTTP API (`qwen2.5-coder` or `llama3.1`).
* `MCPServer` (mcp v2.x) used for sample target; `ClientSession` + `stdio_client` used for attacker driver.

## Risks & Considerations
* Target MCP servers may freeze or block on malformed input; robust timeout handlers must be enforced on all Docker stdio streams.
