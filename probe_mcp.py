from mcp.server.mcpserver import MCPServer
m = MCPServer("test")
print([a for a in dir(m) if not a.startswith('_')])
