#!/usr/bin/env python3
"""
Test script to verify MCP server functionality.

This script connects to the MCP server and tests the get_kms_privileged_entities tool
with various parameters, similar to what the MCP Inspector does.
"""

import asyncio
import json
import sys
from datetime import datetime

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def test_mcp_server():
    """Test the MCP server by calling tools and verifying responses."""
    results = {
        "test_date": datetime.now().isoformat(),
        "server": "ACT Data Query Server",
        "tests": [],
    }

    server_params = StdioServerParameters(
        command="uv",
        args=["run", "python", "-m", "mcp_servers.act_data_query.main"],
    )

    print("Connecting to MCP server...", file=sys.stderr)

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the session
            await session.initialize()
            print("Session initialized successfully", file=sys.stderr)

            # List available tools
            print("\n=== Listing Available Tools ===", file=sys.stderr)
            tools_response = await session.list_tools()
            tools = [tool.name for tool in tools_response.tools]
            print(f"Available tools: {tools}", file=sys.stderr)

            results["available_tools"] = tools

            # Test 1: Call with no parameters (all permissions)
            print("\n=== Test 1: All KMS Permissions ===", file=sys.stderr)
            result1 = await session.call_tool(
                "get_kms_privileged_entities",
                arguments={},
            )
            data1 = json.loads(result1.content[0].text)
            print(f"Filter: {data1.get('permission_level_filter')}", file=sys.stderr)
            print(f"Summary: {data1.get('summary')}", file=sys.stderr)
            results["tests"].append({
                "name": "All KMS Permissions (no parameters)",
                "parameters": {},
                "permission_level_filter": data1.get("permission_level_filter"),
                "summary": data1.get("summary"),
                "user_count": len(data1.get("users", [])),
                "group_count": len(data1.get("groups", [])),
                "role_count": len(data1.get("roles", [])),
                "sample_users": [u.get("entity_name") for u in data1.get("users", [])[:3]],
                "sample_roles": [r.get("entity_name") for r in data1.get("roles", [])[:3]],
            })

            # Test 2: Call with permission_level="admin"
            print("\n=== Test 2: Admin Permissions Only ===", file=sys.stderr)
            result2 = await session.call_tool(
                "get_kms_privileged_entities",
                arguments={"permission_level": "admin"},
            )
            data2 = json.loads(result2.content[0].text)
            print(f"Filter: {data2.get('permission_level_filter')}", file=sys.stderr)
            print(f"Summary: {data2.get('summary')}", file=sys.stderr)
            results["tests"].append({
                "name": "Admin Permissions Only",
                "parameters": {"permission_level": "admin"},
                "permission_level_filter": data2.get("permission_level_filter"),
                "summary": data2.get("summary"),
                "user_count": len(data2.get("users", [])),
                "group_count": len(data2.get("groups", [])),
                "role_count": len(data2.get("roles", [])),
                "users_with_admin": [u.get("entity_name") for u in data2.get("users", [])],
                "roles_with_admin": [r.get("entity_name") for r in data2.get("roles", [])],
            })

            # Test 3: Call with permission_level="encrypt_decrypt"
            print("\n=== Test 3: Encrypt/Decrypt Permissions ===", file=sys.stderr)
            result3 = await session.call_tool(
                "get_kms_privileged_entities",
                arguments={"permission_level": "encrypt_decrypt"},
            )
            data3 = json.loads(result3.content[0].text)
            print(f"Filter: {data3.get('permission_level_filter')}", file=sys.stderr)
            print(f"Summary: {data3.get('summary')}", file=sys.stderr)
            results["tests"].append({
                "name": "Encrypt/Decrypt Permissions",
                "parameters": {"permission_level": "encrypt_decrypt"},
                "permission_level_filter": data3.get("permission_level_filter"),
                "summary": data3.get("summary"),
                "user_count": len(data3.get("users", [])),
                "group_count": len(data3.get("groups", [])),
                "role_count": len(data3.get("roles", [])),
                "sample_entities": (
                    [u.get("entity_name") for u in data3.get("users", [])[:2]] +
                    [r.get("entity_name") for r in data3.get("roles", [])[:2]]
                ),
            })

            # Test 4: Call with permission_level="read_only"
            print("\n=== Test 4: Read-Only Permissions ===", file=sys.stderr)
            result4 = await session.call_tool(
                "get_kms_privileged_entities",
                arguments={"permission_level": "read_only"},
            )
            data4 = json.loads(result4.content[0].text)
            print(f"Filter: {data4.get('permission_level_filter')}", file=sys.stderr)
            print(f"Summary: {data4.get('summary')}", file=sys.stderr)
            results["tests"].append({
                "name": "Read-Only Permissions",
                "parameters": {"permission_level": "read_only"},
                "permission_level_filter": data4.get("permission_level_filter"),
                "summary": data4.get("summary"),
                "user_count": len(data4.get("users", [])),
                "group_count": len(data4.get("groups", [])),
                "role_count": len(data4.get("roles", [])),
                "sample_entities": (
                    [u.get("entity_name") for u in data4.get("users", [])[:2]] +
                    [r.get("entity_name") for r in data4.get("roles", [])[:2]]
                ),
            })

            # Get detailed output for one entity (for documentation)
            print("\n=== Sample Detailed Output ===", file=sys.stderr)
            if data2.get("users"):
                sample_user = data2["users"][0]
                results["sample_detailed_user"] = sample_user
                print(f"Sample user with admin: {json.dumps(sample_user, indent=2)}", file=sys.stderr)

            if data2.get("roles"):
                sample_role = data2["roles"][0]
                results["sample_detailed_role"] = sample_role
                print(f"Sample role with admin: {json.dumps(sample_role, indent=2)}", file=sys.stderr)

    print("\n=== All Tests Completed Successfully ===", file=sys.stderr)
    return results


if __name__ == "__main__":
    results = asyncio.run(test_mcp_server())
    # Output JSON results to stdout for capture
    print(json.dumps(results, indent=2))
