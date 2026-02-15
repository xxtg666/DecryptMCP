from mcp.server.fastmcp import FastMCP
from tools import register_all

mcp = FastMCP("DecryptMCP")
register_all(mcp)

if __name__ == "__main__":
    mcp.run()
