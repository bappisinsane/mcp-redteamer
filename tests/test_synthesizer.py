"""Unit tests for attack Synthesizer (mocked LLM HTTP)."""

import asyncio
import json
from unittest.mock import AsyncMock, patch

from mcp_redteamer.attacker.synthesizer import Synthesizer, _extract_json


def test_extract_json() -> None:
    assert _extract_json('blah {"a": 1} tail') == '{"a": 1}'
    try:
        _extract_json("no json here")
        assert False
    except json.JSONDecodeError:
        pass


async def _run() -> None:
    s = Synthesizer(base_url="http://x", model="m")
    tool = {"name": "read_file", "description": "read", "schema": {"type": "object"}}

    # Test all attack types get generated
    for atype in Synthesizer.ATTACK_TYPES:
        fake_resp = MagicResponse()
        s._client.post = AsyncMock(return_value=fake_resp)

        payload = await s.generate(tool, atype)
        assert payload is not None, f"Attack type {atype} returned None"
        assert isinstance(payload, dict), f"Attack type {atype} did not return dict"
        # Verify the payload contains the tool name key
        assert "tool" in payload or atype in str(payload), (
            f"Attack type {atype} payload missing expected structure: {payload}"
        )

    # LLM failure returns None for each attack type
    for atype in Synthesizer.ATTACK_TYPES:
        s._client.post = AsyncMock(side_effect=Exception("down"))
        payload = await s.generate(tool, atype)
        assert payload is None, f"Attack type {atype} should return None on failure"
    await s.close()


class MagicResponse:
    def raise_for_status(self) -> None: ...
    def json(self) -> dict:
        return {"choices": [{"message": {"content": '{"path": "../../../../etc/passwd"}'}}}]


def test_synthesizer() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    test_extract_json()
    test_synthesizer()
    print("OK")