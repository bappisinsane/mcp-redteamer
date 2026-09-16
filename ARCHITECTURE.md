# System Architecture Specification

## Data Flow Diagram

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