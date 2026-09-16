"""Minimal unit tests for Phase 1 components."""

import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "targets" / "sample_mcp_server"))

from mcp_redteamer.target_manager import TargetManager


def test_target_manager_ensure_network_creates_when_missing() -> None:
    with patch("mcp_redteamer.target_manager.docker.from_env") as mock_from_env:
        mock_client = MagicMock()
        mock_client.networks.list.return_value = []
        mock_from_env.return_value = mock_client

        tm = TargetManager(network_name="test-net")
        mock_client.networks.create.assert_called_once_with("test-net", internal=True, driver="bridge")
        assert tm.network_name == "test-net"


def test_target_manager_ensure_network_skips_when_exists() -> None:
    with patch("mcp_redteamer.target_manager.docker.from_env") as mock_from_env:
        mock_client = MagicMock()
        mock_net = MagicMock()
        mock_net.name = "test-net"
        mock_client.networks.list.return_value = [mock_net]
        mock_from_env.return_value = mock_client

        tm = TargetManager(network_name="test-net")
        mock_client.networks.create.assert_not_called()
        assert tm.network_name == "test-net"


def test_sample_server_imports() -> None:
    """Smoke test that the dummy MCP server can be imported without syntax errors."""
    import server as sample_server
    assert sample_server.MOCK_FLAG == "MOCK_FLAG{test_payload_token_123}"


def test_cli_imports() -> None:
    from mcp_redteamer.cli import app
    assert app is not None


if __name__ == "__main__":
    test_target_manager_ensure_network_creates_when_missing()
    test_target_manager_ensure_network_skips_when_exists()
    test_sample_server_imports()
    test_cli_imports()
    print("OK")
