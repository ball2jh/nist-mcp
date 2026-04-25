"""FastMCP server entry point for nist-mcp."""

from __future__ import annotations

import logging
import sys

from fastmcp import FastMCP

from nist_mcp import __version__
from nist_mcp.config import get_config
from nist_mcp.index import IndexManager
from nist_mcp.kev import KEVClient
from nist_mcp.nvd import NVDClient
from nist_mcp.tools.simple import register_tools


mcp = FastMCP(
    name="nist-mcp",
    instructions=(
        "Local NIST cybersecurity catalog server. Use search_nist for local "
        "NIST publications, SP 800-53 controls, CSF, glossary, CMVP, NCP, "
        "and NICE data. Use get_nist_record for a specific local record, "
        "read_publication for document content, and search_nvd/get_cve for "
        "live vulnerability data."
    ),
)


def _register_about_resource(index_mgr: IndexManager) -> None:
    @mcp.resource(
        "nist://about",
        annotations={"readOnlyHint": True, "idempotentHint": True},
    )
    def about() -> str:
        """Server version, database status, and tool guide."""
        info = index_mgr.status()
        return (
            "# NIST MCP Server\n\n"
            f"- **Server version:** {__version__}\n"
            f"- **Database available:** {'Yes' if info['exists'] else 'No'}\n"
            f"- **Database built:** {info.get('built_at', 'never')}\n"
            f"- **Database path:** `{info['path']}`\n\n"
            "## Tools\n\n"
            "- `search_nist` - search local NIST catalog data\n"
            "- `get_nist_record` - fetch one local NIST record\n"
            "- `read_publication` - read cached publication content\n"
            "- `search_nvd` - search live CVE/CPE data\n"
            "- `get_cve` - fetch one CVE\n"
            "- `database_status` / `update_database` - manage the local index\n"
        )


def main() -> None:
    """Configure and run the NIST MCP server over stdio."""
    logging.basicConfig(stream=sys.stderr)

    config = get_config()
    index_mgr = IndexManager(config)
    nvd_client = NVDClient(api_key=config.nvd_api_key)
    kev_client = KEVClient(cache_dir=config.data_dir)

    register_tools(mcp, index_mgr, config, nvd_client, kev_client)
    _register_about_resource(index_mgr)

    mcp.run(transport="stdio")
