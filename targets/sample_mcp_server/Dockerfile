FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir mcp>=2.1
COPY server.py /app/server.py

RUN groupadd -r mcp && useradd -r -g mcp mcp
RUN mkdir -p /mnt/mock && chown mcp:mcp /mnt/mock
USER mcp

# Container stays alive; the MCP session runs via `docker exec -i <id> python /app/server.py`
CMD ["sleep", "infinity"]
