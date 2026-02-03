"""
Entry point for the ACT Data Query MCP Server.

Run with: uv run python -m mcp_servers.act_data_query.main
"""

import logging
import sys

# Configure logging to stderr (NEVER use print in MCP STDIO servers!)
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)


def main() -> None:
    """Run the MCP server."""
    logger.info("Starting ACT Data Query MCP Server")

    from mcp_servers.act_data_query.server import mcp

    mcp.run()


if __name__ == "__main__":
    main()
