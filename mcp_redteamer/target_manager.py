"""Docker lifecycle manager for target MCP servers."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import docker
from docker.models.containers import Container

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10
CPU_LIMIT = "0.5"
MEM_LIMIT = "256m"


class TargetManager:
    """Spin up / tear down ephemeral Docker containers for MCP targets."""

    def __init__(self, network_name: str = "mcp-rt-isolated") -> None:
        self.network_name = network_name
        self.client = docker.from_env()
        self._ensure_network()

    def _ensure_network(self) -> None:
        nets = [n for n in self.client.networks.list(names=[self.network_name]) if n.name == self.network_name]
        if not nets:
            self.client.networks.create(self.network_name, internal=True, driver="bridge")
            logger.info("Created isolated network %s", self.network_name)

    async def start(self, build_context: str, image_tag: str = "mcp-rt-target:latest") -> Container:
        """Build image from *build_context* and run container on isolated network."""
        loop = asyncio.get_running_loop()
        image, _ = await loop.run_in_executor(
            None, lambda: self.client.images.build(path=build_context, tag=image_tag, rm=True)
        )
        container = await loop.run_in_executor(
            None,
            lambda: self.client.containers.run(
                image.id,
                detach=True,
                network=self.network_name,
                mem_limit=MEM_LIMIT,
                nano_cpus=int(float(CPU_LIMIT) * 1e9),
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                auto_remove=True,
                stdin_open=True,
                stdout=True,
                stderr=True,
            ),
        )
        logger.info("Started container %s", container.short_id)
        return container  # type: ignore[return-value]

    async def stop(self, container_id: str, timeout: int = DEFAULT_TIMEOUT) -> None:
        """Stop and remove container."""
        loop = asyncio.get_running_loop()
        try:
            container = await loop.run_in_executor(None, self.client.containers.get, container_id)
            await loop.run_in_executor(None, container.stop, timeout)
            logger.info("Stopped container %s", container_id[:12])
        except docker.errors.NotFound:
            logger.warning("Container %s not found", container_id[:12])

    async def exec(self, container_id: str, cmd: list[str], timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
        """Execute a command inside the container and return result."""
        loop = asyncio.get_running_loop()
        container = await loop.run_in_executor(None, self.client.containers.get, container_id)
        result = await loop.run_in_executor(None, lambda: container.exec_run(cmd, demux=True))
        return {"exit_code": result.exit_code, "output": result.output}
