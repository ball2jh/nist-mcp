"""MCP tools for NIST Cybersecurity Framework and other NIST frameworks."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated

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


def _mapping_count(db_path, entry_id: str) -> int:
    """Return the number of mappings where entry_id appears as source or target."""
    conn = db.get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT count(*) FROM mappings WHERE source_id = ? OR target_id = ?",
            (entry_id, entry_id),
        ).fetchone()
        return row[0] if row else 0
    except Exception:
        return 0
    finally:
        conn.close()


def _format_csf_entry(entry: dict, mapping_count: int, detail_level: str) -> str:
    """Format a single CSF entry as Markdown."""
    level = entry.get("level", "")
    eid = entry.get("id", "?")
    title = entry.get("title", "")
    fn_name = entry.get("function_name", "")
    cat_name = entry.get("category_name", "")

    map_note = f" ({mapping_count} mappings)" if mapping_count else ""

    if level == "function":
        return f"- **{eid}** — {fn_name}{map_note}"
    elif level == "category":
        return f"- **{eid}** — {cat_name}{map_note}"
    else:
        # subcategory
        if detail_level == "summary":
            return f"- **{eid}**{map_note} — {title}"
        else:
            return f"- **{eid}**{map_note}\n  {title}"


def _format_mapping(m: dict) -> str:
    source = f"{m['source_framework']}:{m['source_id']}"
    target = f"{m['target_framework']}:{m['target_id']}"
    rel = m.get("relationship", "related")
    return f"- {source} → {target} ({rel})"


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_framework_tools(mcp: "FastMCP", index_mgr: "IndexManager") -> None:
    """Register CSF and cross-framework mapping tools on *mcp*."""

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_csf_data(
        function: Annotated[
            str | None,
            Field(description="CSF function ID, e.g. 'PR', 'ID', 'GV'"),
        ] = None,
        category: Annotated[
            str | None,
            Field(description="CSF category ID, e.g. 'PR.AC', 'ID.AM'"),
        ] = None,
        query: Annotated[
            str | None,
            Field(description="Full-text search across CSF entries"),
        ] = None,
        detail_level: Annotated[
            str,
            Field(description="Output verbosity: summary, standard, or full"),
        ] = "summary",
    ) -> str:
        """Browse/search the NIST CSF 2.0 framework hierarchy.
        No args = list all 6 functions. function="PR" = Protect categories.
        category="PR.AC" = subcategories. query="risk" = full-text search.
        Includes count of mapped SP 800-53 controls per entry."""
        db_path = await index_mgr.ensure_index()

        conn = db.get_connection(db_path)
        try:
            if query:
                # FTS search
                results, total = db.search_fts(db_path, "csf", query, limit=30)
                if not results:
                    return f"No CSF entries found for query: '{query}'."
                lines = [f"**{total} CSF entries matching '{query}'**\n"]
                for entry in results:
                    mc = _mapping_count(db_path, entry["id"])
                    lines.append(_format_csf_entry(entry, mc, detail_level))
                return "\n".join(lines)

            elif category:
                # Show subcategories for a given category
                cat_upper = category.upper()
                rows = conn.execute(
                    "SELECT * FROM csf WHERE category_id = ? AND level = 'subcategory' ORDER BY id",
                    (cat_upper,),
                ).fetchall()
                entries = [dict(r) for r in rows]

                # Also fetch the category row itself for context
                cat_row = conn.execute(
                    "SELECT * FROM csf WHERE id = ? AND level = 'category'",
                    (cat_upper,),
                ).fetchone()

                if not entries and cat_row is None:
                    return f"CSF category '{category}' not found."

                header_parts = [f"**CSF Category {cat_upper}**"]
                if cat_row:
                    cat_data = dict(cat_row)
                    header_parts.append(
                        f" — {cat_data.get('category_name', '')} "
                        f"(Function: {cat_data.get('function_id', '')} {cat_data.get('function_name', '')})"
                    )
                lines = ["".join(header_parts) + "\n"]

                for entry in entries:
                    mc = _mapping_count(db_path, entry["id"])
                    lines.append(_format_csf_entry(entry, mc, detail_level))

                if not entries:
                    lines.append("_No subcategories found for this category._")

                return "\n".join(lines)

            elif function:
                # Show categories for a given function
                fn_upper = function.upper()
                rows = conn.execute(
                    "SELECT * FROM csf WHERE function_id = ? AND level = 'category' ORDER BY id",
                    (fn_upper,),
                ).fetchall()
                entries = [dict(r) for r in rows]

                # Also fetch the function row for context
                fn_row = conn.execute(
                    "SELECT * FROM csf WHERE id = ? AND level = 'function'",
                    (fn_upper,),
                ).fetchone()

                if not entries and fn_row is None:
                    return f"CSF function '{function}' not found."

                fn_name = dict(fn_row).get("function_name", fn_upper) if fn_row else fn_upper
                lines = [f"**CSF Function {fn_upper} — {fn_name}** ({len(entries)} categories)\n"]

                for entry in entries:
                    mc = _mapping_count(db_path, entry["id"])
                    lines.append(_format_csf_entry(entry, mc, detail_level))

                return "\n".join(lines)

            else:
                # No args: list all 6 functions
                rows = conn.execute(
                    "SELECT * FROM csf WHERE level = 'function' ORDER BY id"
                ).fetchall()
                entries = [dict(r) for r in rows]

                lines = ["**NIST CSF 2.0 — 6 Core Functions**\n"]
                for entry in entries:
                    mc = _mapping_count(db_path, entry["id"])
                    lines.append(_format_csf_entry(entry, mc, detail_level))

                lines.append(
                    "\n_Use function='GV' to see categories, or category='GV.OC' for subcategories._"
                )
                return "\n".join(lines)
        finally:
            conn.close()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_framework_mappings(
        source_id: Annotated[
            str,
            Field(description="Control or CSF ID, e.g. 'ac-1', 'PR.AC-01', 'cm-8'"),
        ],
        target_framework: Annotated[
            str | None,
            Field(
                description="Filter results by framework, e.g. 'CSF.2.0', 'SP.800-53.r5', 'CSF.1.1'"
            ),
        ] = None,
    ) -> str:
        """Cross-reference frameworks. 'What CSF maps to AC-1?' or 'What 800-53 controls implement PR.AC?'
        Bidirectional lookup in the mappings table."""
        db_path = await index_mgr.ensure_index()

        # Try both raw and normalized versions of the ID
        normalized = db.normalize_control_id(source_id)
        lookup_ids = list({source_id, normalized, source_id.upper(), source_id.lower()})

        conn = db.get_connection(db_path)
        try:
            all_rows: list[dict] = []
            for lid in lookup_ids:
                rows = conn.execute(
                    "SELECT * FROM mappings WHERE source_id = ? OR target_id = ?",
                    (lid, lid),
                ).fetchall()
                for r in rows:
                    row_dict = dict(r)
                    if row_dict not in all_rows:
                        all_rows.append(row_dict)
        finally:
            conn.close()

        if not all_rows:
            return (
                f"No framework mappings found for '{source_id}'.\n\n"
                f"_Tried variants: {', '.join(lookup_ids)}_"
            )

        # Apply target_framework filter if provided
        if target_framework:
            tf_upper = target_framework.upper()
            filtered = [
                m for m in all_rows
                if m.get("target_framework", "").upper() == tf_upper
                or m.get("source_framework", "").upper() == tf_upper
            ]
            if not filtered:
                return (
                    f"No mappings found for '{source_id}' involving framework '{target_framework}'.\n\n"
                    f"Available frameworks in results: "
                    + ", ".join(
                        sorted({m.get("source_framework", "") for m in all_rows}
                               | {m.get("target_framework", "") for m in all_rows})
                    )
                )
            all_rows = filtered

        lines = [f"**Framework mappings for '{source_id}' ({len(all_rows)} total)**\n"]

        # Group by framework direction
        as_source = [m for m in all_rows if m["source_id"].lower() in [i.lower() for i in lookup_ids]]
        as_target = [m for m in all_rows if m["target_id"].lower() in [i.lower() for i in lookup_ids]]

        if as_source:
            lines.append(f"**As source ({len(as_source)}):**")
            for m in as_source:
                lines.append(_format_mapping(m))
            lines.append("")

        if as_target:
            lines.append(f"**As target ({len(as_target)}):**")
            for m in as_target:
                lines.append(_format_mapping(m))

        return "\n".join(lines)
