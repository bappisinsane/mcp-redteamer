# MCP Redteamer — Autonomous MCP Security Audit & AI Red-Teaming Tool

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=flat-square)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-Protocol-46318C.svg?style=flat-square)](https://modelcontextprotocol.io/)
[![Ollama](https://img.shields.io/badge/Ollama-Local%20LLM-9B6799.svg?style=flat-square)](https://ollama.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

An autonomous security auditing tool that tests Model Context Protocol (MCP) servers and LLM agents for vulnerabilities — indirect prompt injection, tool hijacking, unauthorized file access, and parameter manipulation — by probing them inside isolated Docker containers with locally-generated attack payloads.

**Spin up a target. Synthesize attacks. Evaluate responses. Get a vulnerability scorecard. All local. All automated.**

---

## Table of Contents

- [The Threat Model](#the-threat-model)
- [How It Works](#how-it-works)
- [Features](#features)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Attack Types](#attack-types)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [License](#license)

---

## The Threat Model

MCP servers and tool-using LLM agents expose a surface area that traditional security tooling doesn't cover:

- **Indirect Prompt Injection** — An attacker embeds malicious instructions in data the agent processes (file contents, web pages, API responses), causing the agent to misbehave.
- **Tool Hijacking** — The agent is manipulated into calling tools it shouldn't — reading files outside its sandbox, calling internal APIs, or modifying state.
- **Unauthorized File Access** — The agent is coerced into accessing files, directories, or resources beyond its authorized scope.
- **Parameter Manipulation** — Tool arguments are crafted to bypass validation, trigger edge cases, or leak information through error messages.

MCP Redteamer automates the discovery and exploitation of these vulnerabilities against your MCP server before it ships to production.

---

## How It Works

```
[Attacker Local Engine]
Local Attacker LLM (Ollama / vLLM)
         |
         v
[Payload Synthesizer] ---> Generates indirect prompt injections / rogue params
         |
         v
[MCP Protocol Adapter] ---> Sends JSON-RPC over stdio/SSE to target container
         |
-------------------------------------------------------------------------
[Target Container Boundary (Docker)]
         |
         v
[Target MCP Server] ---> Processes request against mock filesystem/tools
         |
-------------------------------------------------------------------------
         |
         v
[Response Evaluator] <--- Inspects response, tool call outputs, error codes
         |
         +---> Evaluates Success / Breach Criteria
         |
[Rich TUI Dashboard / Report Generator]
```

1. **Target Management** — The engine spins up the target MCP server inside an ephemeral, isolated Docker container. Performs health checks. Tears it down when done.
2. **Attack Synthesis** — A local LLM (Ollama + `qwen2.5-coder` or similar) receives the target's tool schemas and generates malicious payloads: indirect prompt injections, rogue parameter values, and boundary-crossing inputs.
3. **MCP Protocol Communication** — The engine communicates with the target over stdio or SSE using the official Python `mcp` SDK. It auto-discovers available tools, their argument schemas, and resources.
4. **Response Evaluation** — Every response is inspected for breach indicators: leaked mock environment data, unauthorized tool calls, unexpected exceptions, or out-of-bounds behavior.
5. **Reporting** — Results flow into a real-time Rich TUI dashboard and can be exported as HTML/Markdown reports with vulnerability severity scores and remediation advice.

---

## Features

- **Isolated Target Execution** — Automated lifecycle management (spin-up, health check, teardown) of target MCP servers in ephemeral, isolated Docker containers. Nothing touches the host.
- **Dynamic Attack Synthesis** — Local LLM-driven payload generation targeting specific MCP tool schemas. No hardcoded attack corpus — attacks adapt to the target's exposed interface.
- **Native MCP Protocol Driver** — Communicates with targets over stdio or SSE using the official Python `mcp` SDK. Auto-discovers tools, arguments, and resources.
- **Automated Response Evaluation** — Real-time analysis of agent/tool responses. Detects jailbreaks, sensitive data leaks, unauthorized tool calls, and unexpected crashes.
- **Rich TUI Dashboard** — Terminal UI showing real-time attack tree progression, payload logs, and final vulnerability scorecards.
- **Report Export** — HTML and Markdown report generation summarizing discovered vulnerabilities with severity ratings and remediation guidance.
- **Local-Only** — Everything runs locally. No cloud API calls. No attack data leaving the machine.

---

## Quick Start

### Install

```bash
pip install .
```

### Run a Security Audit

```bash
mcp-redteamer run \
  --target ./targets/my-mcp-server \
  --config config.yaml
```

### Run with Defaults

```bash
# Uses the bundled sample target and default config
mcp-redteamer run
```

---

## Usage

### CLI

```bash
# Full audit with custom target and config
mcp-redteamer run --target ./targets/my-mcp-server --config config.yaml

# Run with a specific attack profile
mcp-redteamer run --target ./targets/my-mcp-server --profile prompt-injection

# Export report in a specific format
mcp-redteamer run --target ./targets/my-mcp-server --report-format html
```

### Configuration File (`config.yaml`)

```yaml
target:
  docker_image: my-mcp-server:latest
  command: ["python", "server.py"]
  health_check:
    endpoint: http://localhost:8080/health
    timeout: 30

attacker:
  model: qwen2.5-coder:7b
  ollama_url: http://localhost:11434
  max_attacks_per_tool: 20

evaluation:
  mock_data:
    - jwt_tokens
    - api_keys
    - internal_ips
  breach_rules:
    - unauthorized_file_read
    - tool_hijacking
    - prompt_injection_success

report:
  format: markdown
  output_path: ./reports/
```

---

## Attack Types

| Attack | Description | Target |
|--------|-------------|--------|
| **Indirect Prompt Injection** | Embed malicious instructions in tool input data (file contents, API responses) to manipulate agent behavior | Any tool that processes external data |
| **Tool Hijacking** | Craft inputs that cause the agent to call tools outside its intended workflow or with untrusted parameters | Tool-calling agents |
| **Unauthorized File Access** | Manipulate file path arguments to read files outside the authorized sandbox | File-reading tools |
| **Parameter Manipulation** | Supply edge-case, boundary, or malformed parameter values to trigger validation bypass, errors, or information leakage | All tools |
| **Jailbreak Attempts** | Systemic prompt crafting to override agent safety constraints | Chat/instruct agents |

---

## Architecture

### Component Breakdown

| Component | Module | Responsibility |
|-----------|--------|----------------|
| Engine | `mcp_redteamer/engine/` | Orchestrates the full attack lifecycle — target management, attack dispatch, evaluation, reporting |
| Attacker / Synthesizer | `mcp_redteamer/attacker/synthesizer.py` | Local LLM client (Ollama / LiteLLM). Generates attack payloads from tool JSON schemas using prompt templates |
| MCP Client | `mcp_redteamer/client/` | Wraps the Python `mcp` SDK. Communicates over stdio/SSE. Auto-discovers tools, args, resources |
| Evaluator | `mcp_redteamer/evaluator/` | Heuristic + LLM-assisted evaluation. Checks responses for breach indicators against defined rules |
| TUI | `mcp_redteamer/tui/` | Rich terminal dashboard — attack tree, payload logs, live scorecard |
| Target Manager | `mcp_redteamer/target/` | Docker SDK-based container lifecycle — spin-up, health check, teardown |

### Data Flow

```
Tool Schema (from MCP server)
        |
        v
[Payload Synthesizer] --> Attack Prompt Templates
        |
        v
[Indirect Injection / Rogue Param / Boundary Value]
        |
        v
[MCP Client] --> JSON-RPC --> [Target MCP Server in Docker]
        |
        v
[Response] --> [Evaluator] --> Breach? Yes/No
        |
        v
[TUI Dashboard] + [Report]
```

---

## Project Structure

```
mcp-redteamer/
├── mcp_redteamer/
│   ├── engine/              # Attack lifecycle orchestration
│   ├── attacker/
│   │   └── synthesizer.py   # Local LLM payload generation
│   ├── client/              # MCP protocol wrapper (stdio/SSE)
│   ├── evaluator/           # Response analysis & scoring
│   ├── tui/                 # Rich terminal dashboard
│   └── target/              # Docker container lifecycle
├── targets/
│   └── sample_mcp_server/   # Dummy MCP server for testing
├── tests/
├── probes/
│   └── probe_mcp.py         # Standalone MCP connectivity probe
├── pyproject.toml
├── ARCHITECTURE.md
├── PRD.md
├── PHASES.md
├── rules.md
├── MEMORY.md
└── README.md
```

---

## Roadmap

### Phase 1 — CLI Harness & Target Docker Manager
- [ ] Python package structure with `pyproject.toml` and Typer CLI entry point
- [ ] `TargetManager` — Docker SDK spin-up/tear-down of test containers
- [ ] Dummy C/Python MCP server in `targets/sample_mcp_server/` for testing

### Phase 2 — MCP Client Protocol Integration
- [ ] `MCPClientWrapper` using the Python `mcp` SDK over container stdio transport
- [ ] Auto-discovery of tools, arguments, and resources exposed by the container

### Phase 3 — Local LLM Attack Synthesizer
- [ ] Ollama / LiteLLM HTTP client in `mcp_redteamer/attacker/synthesizer.py`
- [ ] Attack prompt templates for indirect prompt injection and parameter manipulation based on tool JSON schemas

### Phase 4 — Response Evaluator & Scoring Engine
- [ ] Heuristic + LLM-assisted evaluation in `evaluator.py`
- [ ] Detection rules for mock data leaks, unauthorized tool calls, and unexpected crashes

### Phase 5 — Rich TUI & Security Report Generator
- [ ] Real-time Rich TUI showing attack tree progression
- [ ] HTML/Markdown report exporter with vulnerability summaries and remediation advice

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

**Built for AI security engineers, red-teamers, and developers who want to benchmark MCP server security before production deployment.**
