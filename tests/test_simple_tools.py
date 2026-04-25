"""Tests for the simplified MCP tool registration."""

from pathlib import Path

import pytest
from fastmcp import FastMCP

from nist_mcp.config import Config
from nist_mcp.index import IndexManager
from nist_mcp.kev import KEVClient
from nist_mcp.nvd import NVDClient
from nist_mcp.tools.simple import register_tools


@pytest.mark.asyncio
async def test_registers_small_tool_surface(tmp_path: Path):
    app = FastMCP("test")
    config = Config(data_dir=tmp_path)
    index_mgr = IndexManager(config)

    register_tools(app, index_mgr, config, NVDClient(), KEVClient(tmp_path))

    tools = await app.list_tools()
    assert {tool.name for tool in tools} == {
        "database_status",
        "get_cve",
        "get_nist_record",
        "read_publication",
        "search_nist",
        "search_nvd",
        "update_database",
    }


@pytest.mark.asyncio
async def test_database_status_call(tmp_path: Path):
    app = FastMCP("test")
    config = Config(data_dir=tmp_path)
    index_mgr = IndexManager(config)

    register_tools(app, index_mgr, config, NVDClient(), KEVClient(tmp_path))

    result = await app.call_tool("database_status", {})
    text = result.content[0].text
    assert "NIST Database Status" in text
    assert str(index_mgr.db_path) in text
