# ACTT Agent - Project Configuration for Claude Code

## Project Purpose
Audit assistant using MCP (Model Context Protocol) to query AWS IAM configuration data.
Phase 1 POC focused on AWS IAM privileged access testing.

## Critical Rules

### 1. Environment Management
- **Use `uv` for Python environment management** - never pip directly
- Virtual environment is in `.venv/`
- Add dependencies with `uv add <package>`

### 2. MCP Server Development
- MCP servers follow the **FastMCP pattern**
- Server code lives in `/mcp_servers/act_data_query/`

### 3. CRITICAL: Logging in MCP STDIO Servers
**NEVER use `print()` in MCP STDIO servers!**
- Print statements corrupt the JSON-RPC protocol over STDIO
- Always use `logging` module configured to write to **stderr**
- Example:
  ```python
  import logging
  import sys

  logging.basicConfig(
      level=logging.DEBUG,
      format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
      stream=sys.stderr
  )
  logger = logging.getLogger(__name__)
  ```

### 4. Code Documentation
- All functions need clear docstrings
- Document parameters, return values, and any side effects

### 5. Development Process
- Use tight feedback loops - correct immediately if going off track
- Test early and often with `pytest`
- Keep commits atomic and well-described

## Project Structure
```
/CLAUDE.md              - This file (project configuration)
/data/sample_act_data/  - Mock AWS IAM authorization data
/mcp_servers/act_data_query/
    server.py           - FastMCP server definition
    main.py             - Server entry point
    tools/              - MCP tool implementations
/work_plans/            - Audit control procedure definitions
/docs/                  - Documentation
```

## Running Tests
```bash
uv run pytest
```

## Running the MCP Server
```bash
uv run python -m mcp_servers.act_data_query.main
```
