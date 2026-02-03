"""
FastMCP server for querying AWS IAM authorization data.

This module initializes the MCP server and loads IAM data for tools to query.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

# Configure logging to stderr (NEVER use print in MCP STDIO servers!)
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

# Create the MCP server instance
mcp = FastMCP("ACT Data Query Server")

# Module-level variable to store loaded IAM data
iam_data: dict[str, Any] = {}


def load_iam_data() -> None:
    """
    Load IAM authorization data from the sample data file.

    Loads data from data/sample_act_data/get-account-authorization-details.json
    and stores it in the module-level iam_data variable for tools to access.

    Raises:
        FileNotFoundError: If the data file does not exist.
        json.JSONDecodeError: If the data file contains invalid JSON.
    """
    global iam_data

    # Determine the path to the data file relative to the project root
    # The server module is at mcp_servers/act_data_query/server.py
    # The data file is at data/sample_act_data/get-account-authorization-details.json
    project_root = Path(__file__).parent.parent.parent
    data_file = project_root / "data" / "sample_act_data" / "get-account-authorization-details.json"

    logger.info(f"Loading IAM data from: {data_file}")

    if not data_file.exists():
        logger.error(f"IAM data file not found: {data_file}")
        raise FileNotFoundError(f"IAM data file not found: {data_file}")

    with open(data_file, "r") as f:
        iam_data = json.load(f)

    # Log summary of loaded data
    user_count = len(iam_data.get("UserDetailList", []))
    group_count = len(iam_data.get("GroupDetailList", []))
    role_count = len(iam_data.get("RoleDetailList", []))
    policy_count = len(iam_data.get("Policies", []))

    logger.info(
        f"Loaded IAM data: {user_count} users, {group_count} groups, "
        f"{role_count} roles, {policy_count} policies"
    )


def get_iam_data() -> dict[str, Any]:
    """
    Get the loaded IAM data.

    Returns:
        The loaded IAM authorization data dictionary.

    Raises:
        RuntimeError: If IAM data has not been loaded yet.
    """
    if not iam_data:
        raise RuntimeError("IAM data not loaded. Call load_iam_data() first.")
    return iam_data


# Load IAM data when module is imported
try:
    load_iam_data()
except Exception as e:
    logger.error(f"Failed to load IAM data on startup: {e}")


# Import and register tools after MCP instance is created
from mcp_servers.act_data_query.tools import kms_access  # noqa: E402, F401
