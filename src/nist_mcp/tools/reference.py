"""MCP tools for NIST glossary, NICE framework, and reference data."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated

from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from nist_mcp import db

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from nist_mcp.index import IndexManager

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _format_glossary_entry(entry: dict, detail_level: str = "standard") -> str:
    """Format a glossary entry as Markdown."""
    term = entry.get("term", "?")
    definition = entry.get("definition", "")
    source = entry.get("source", "")
    see_also = entry.get("see_also", "")

    lines = [f"### {term}\n"]
    lines.append(definition)

    if source:
        lines.append(f"\n**Source:** {source}")

    if see_also:
        lines.append(f"**See also:** {see_also}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_reference_tools(mcp: "FastMCP", index_mgr: "IndexManager") -> None:
    """Register glossary and reference lookup tools on *mcp*."""

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def lookup_glossary(
        term: Annotated[
            str | None,
            Field(description="Exact term to look up, e.g. 'Access Control'"),
        ] = None,
        query: Annotated[
            str | None,
            Field(description="Keyword search across term and definition"),
        ] = None,
        limit: Annotated[
            int,
            Field(description="Maximum number of results", ge=1, le=50),
        ] = 10,
    ) -> str:
        """Look up NIST cybersecurity/privacy terms. Use 'term' for exact match,
        'query' for keyword search. Returns definition, authoritative source, and related terms."""
        db_path = await index_mgr.ensure_index()

        if not term and not query:
            raise ToolError("Please provide either 'term' for exact lookup or 'query' for keyword search.")

        if term:
            # Exact match by primary key
            entry = db.get_by_id(db_path, "glossary", term)
            if entry is None:
                # Try case-insensitive fallback via direct query
                conn = db.get_connection(db_path)
                try:
                    row = conn.execute(
                        "SELECT * FROM glossary WHERE lower(term) = lower(?)", (term,)
                    ).fetchone()
                    entry = dict(row) if row else None
                finally:
                    conn.close()

            if entry is None:
                return (
                    f"Term **'{term}'** not found in the NIST glossary.\n\n"
                    f"_Tip: Use 'query' parameter for keyword search._"
                )

            return _format_glossary_entry(entry)

        # query-based FTS search
        results, total = db.search_fts(db_path, "glossary", query, limit=limit)

        if not results:
            return f"No glossary terms found for query: '{query}'."

        lines = [f"**{total} glossary terms matching '{query}'**\n"]

        for entry in results:
            lines.append(_format_glossary_entry(entry))
            lines.append("")

        if total > limit:
            lines.append(
                f"_Showing first {min(limit, len(results))} of {total} results. "
                f"Use a more specific query to narrow results._"
            )

        return "\n".join(lines)
