"""MCP tools for server administration and database management."""

from __future__ import annotations

from typing import TYPE_CHECKING

from mcp.types import ToolAnnotations

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from nist_mcp.index import IndexManager


def _format_size(size_bytes: int | None) -> str:
    """Convert a byte count to a human-readable string (e.g. '12.3 MB')."""
    if size_bytes is None:
        return "unknown"
    for unit in ("B", "KB", "MB", "GB"):
        if abs(size_bytes) < 1024:
            if unit == "B":
                return f"{size_bytes} {unit}"
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024  # type: ignore[assignment]
    return f"{size_bytes:.1f} TB"  # type: ignore[str-format]


def register_admin_tools(mcp: FastMCP, index_mgr: IndexManager) -> None:
    """Register database administration tools on *mcp*."""

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False))
    async def update_database() -> str:
        """Force refresh the NIST metadata index from GitHub Releases.
        Downloads the latest pre-built database. Use this if you need
        the most current publication or control data."""
        tag = await index_mgr.force_update()
        return f"Database updated to version: {tag}"

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def database_status() -> str:
        """Show the current NIST metadata index status: version, build date,
        last update check, database size, and file path. Use this to verify
        the database is available and check data freshness."""
        info = index_mgr.status()
        lines = [
            "## NIST Database Status",
            f"- **Available:** {'Yes' if info['exists'] else 'No'}",
            f"- **Version:** {info.get('current_tag', 'unknown')}",
            f"- **Last check:** {info.get('last_check', 'never')}",
            f"- **Size:** {_format_size(info.get('db_size_bytes'))}",
            f"- **Path:** `{info['path']}`",
        ]
        return "\n".join(lines)
