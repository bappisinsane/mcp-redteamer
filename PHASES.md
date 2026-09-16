# Implementation Phases

## Phase 1: CLI Harness & Target Docker Manager
- [ ] Set up Python package structure with `pyproject.toml` and CLI entry point via Typer.
- [ ] Implement `TargetManager` using Docker SDK to spin up/tear down test containers.
- [ ] Build a simple dummy C/Python MCP server in `targets/sample_mcp_server/` for testing.

## Phase 2: MCP Client Protocol Integration
- [ ] Implement `MCPClientWrapper` using the Python `mcp` SDK over container stdio transport.
- [ ] Implement auto-discovery of tools, arguments, and resources exposed by the container.

## Phase 3: Local LLM Attack Synthesizer
- [ ] Build Ollama / LiteLLM HTTP client module in `mcp_redteamer/attacker/synthesizer.py`.
- [ ] Design attack prompt templates for indirect prompt injection and parameter manipulation based on tool JSON schemas.

## Phase 4: Response Evaluator & Scoring Engine
- [ ] Implement heuristic and LLM-assisted evaluation logic in `evaluator.py`.
- [ ] Add detection rules for mock data leaks, unauthorized tool calls, and unexpected exception crashes.

## Phase 5: Rich TUI & Security Report Generator
- [ ] Implement real-time Rich TUI layout showing attack tree progression.
- [ ] Implement HTML/Markdown report exporter summarizing discovered security vulnerabilities and remediation advice.