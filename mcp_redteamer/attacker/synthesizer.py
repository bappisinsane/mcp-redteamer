"""LLM-driven attack payload synthesizer (Ollama / vLLM / LiteLLM-compatible OpenAI API)."""

from __future__ import annotations

import json
from typing import Any

import httpx

PROMPT_TEMPLATE = """You are an AI red-teamer generating ONE malicious test payload for an MCP tool.
Tool name: {name}
Tool description: {description}
Tool JSON schema: {schema}

Attack type: {attack_type}
Generate ONLY a JSON object of arguments for this tool that attempts the attack.
Rules: synthetic dummy data only, no real credentials, keep under 500 bytes."""

ATTACK_TYPES = [
    "indirect_prompt_injection",  # embed instructions in a parameter
    "path_traversal",             # escape mock filesystem
    "parameter_manipulation",     # type confusion / extra params
    "command_injection",          # via shell-like tools
]


class Synthesizer:
    """Generate attack payloads from tool schemas via a local LLM."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "qwen2.5-coder", timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)

    async def generate(self, tool: dict[str, Any], attack_type: str) -> dict[str, Any] | None:
        prompt = PROMPT_TEMPLATE.format(
            name=tool["name"],
            description=tool.get("description", ""),
            schema=json.dumps(tool.get("schema", {})),
            attack_type=attack_type,
        )
        try:
            resp = await self._client.post(
                f"{self.base_url}/v1/chat/completions",
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.8,
                },
            )
            resp.raise_for_status()
            text = resp.json()["choices"][0]["message"]["content"].strip()
            return json.loads(_extract_json(text))
        except Exception:  # ponytail: LLM is external, any failure = skip this payload
            return None

    async def generate_all(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Generate one payload per attack type per tool; skips LLM failures."""
        attacks = []
        for tool in tools:
            for atype in ATTACK_TYPES:
                payload = await self.generate(tool, atype)
                if payload is not None:
                    attacks.append({"tool": tool["name"], "attack_type": atype, "payload": payload})
        return attacks

    async def close(self) -> None:
        await self._client.aclose()


def _extract_json(text: str) -> str:
    """Pull first JSON object out of LLM output."""
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        raise json.JSONDecodeError("no json", text, 0)
    return text[start : end + 1]
