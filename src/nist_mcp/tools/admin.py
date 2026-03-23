"""MCP tools for server administration and database management."""

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


def register_meta_search_tool(mcp: "FastMCP", index_mgr: "IndexManager") -> None:
    """Register the search_nist meta-search tool on *mcp*."""

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def search_nist(
        query: Annotated[str, Field(description="Search keywords")],
        scope: Annotated[
            str | None,
            Field(
                description=(
                    "Limit search to one data type: publications, controls, csf, "
                    "glossary, cmvp, checklists, nice"
                )
            ),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=50)] = 10,
    ) -> str:
        """Search across ALL NIST data: publications, SP 800-53 controls, CSF framework,
        glossary, CMVP modules, checklists, and NICE roles. Results grouped by type.

        Use this as a starting point when you're not sure which specific tool to use.
        For targeted searches, use domain-specific tools (search_publications,
        search_controls, etc.).

        scope options: publications, controls, csf, glossary, cmvp, checklists, nice"""
        db_path = await index_mgr.ensure_index()

        # Map scope names to (table, label, format_fn) tuples.
        # Each format_fn takes a dict row and returns a one-line string.
        def _fmt_pub(row: dict) -> str:
            return f"**{row.get('id', '?')}** — {row.get('title', 'Untitled')} ({row.get('pub_date', '')})"

        def _fmt_ctrl(row: dict) -> str:
            label = row.get("label", row.get("id", "?"))
            title = row.get("title", "")
            withdrawn = " _(withdrawn)_" if row.get("is_withdrawn") else ""
            return f"**{label}**{withdrawn} — {title}"

        def _fmt_csf(row: dict) -> str:
            eid = row.get("id", "?")
            title = row.get("title", "") or row.get("category_name", "") or row.get("function_name", "")
            level = row.get("level", "")
            return f"**{eid}** [{level}] — {title}"

        def _fmt_glossary(row: dict) -> str:
            term = row.get("term", "?")
            defn = row.get("definition", "")
            if len(defn) > 120:
                defn = defn[:117] + "..."
            return f"**{term}** — {defn}"

        def _fmt_cmvp(row: dict) -> str:
            cert = row.get("cert_number", "?")
            vendor = row.get("vendor", "")
            name = row.get("module_name", "")
            level = row.get("fips_level", "")
            return f"**Cert #{cert}** — {vendor} {name} (Level {level})"

        def _fmt_checklist(row: dict) -> str:
            cid = row.get("id", "?")
            name = row.get("name", "")
            product = row.get("product", "")
            return f"**{cid}** — {name} ({product})"

        def _fmt_nice(row: dict) -> str:
            role_id = row.get("id", "?")
            name = row.get("name", "")
            category = row.get("category", "")
            return f"**{role_id}** — {name} [{category}]"

        ALL_SCOPES: list[tuple[str, str, str, object]] = [
            # (scope_key, table, display_label, format_fn)
            ("publications", "publications", "Publications", _fmt_pub),
            ("controls", "controls", "SP 800-53 Controls", _fmt_ctrl),
            ("csf", "csf", "CSF Framework", _fmt_csf),
            ("glossary", "glossary", "Glossary", _fmt_glossary),
            ("cmvp", "cmvp", "CMVP Modules", _fmt_cmvp),
            ("checklists", "checklists", "Checklists", _fmt_checklist),
            ("nice", "nice_roles", "NICE Work Roles", _fmt_nice),
        ]

        # Select scopes to search
        if scope:
            scope_lower = scope.lower().strip()
            selected = [(k, t, lbl, fn) for k, t, lbl, fn in ALL_SCOPES if k == scope_lower]
            if not selected:
                valid = ", ".join(k for k, *_ in ALL_SCOPES)
                return f"Unknown scope '{scope}'. Valid values: {valid}"
        else:
            selected = list(ALL_SCOPES)

        # Distribute limit across scopes: top 2-3 per section
        per_scope = max(2, limit // max(1, len(selected)))

        sections: list[str] = []
        total_found = 0

        for scope_key, table, label, fmt_fn in selected:
            try:
                if table == "nice_roles":
                    # nice_roles has no FTS table — use LIKE search instead
                    conn = db.get_connection(db_path)
                    try:
                        like_val = f"%{query}%"
                        count_sql = (
                            "SELECT count(*) FROM nice_roles WHERE "
                            "name LIKE ? OR description LIKE ? OR id LIKE ?"
                        )
                        total = conn.execute(count_sql, [like_val, like_val, like_val]).fetchone()[0]
                        rows = conn.execute(
                            "SELECT * FROM nice_roles WHERE "
                            "name LIKE ? OR description LIKE ? OR id LIKE ? "
                            "ORDER BY category, name LIMIT ?",
                            [like_val, like_val, like_val, per_scope],
                        ).fetchall()
                        results = [dict(r) for r in rows]
                    finally:
                        conn.close()
                else:
                    results, total = db.search_fts(db_path, table, query, limit=per_scope)
            except Exception as exc:
                log.debug("search_nist: search error on table %s: %s", table, exc)
                continue

            if not results:
                continue

            total_found += len(results)
            lines = [f"### {label} ({total} total)\n"]
            for row in results:
                lines.append(f"- {fmt_fn(row)}")  # type: ignore[operator]

            if total > per_scope:
                lines.append(
                    f"\n_...and {total - per_scope} more. "
                    f"Use the domain-specific tool for more results._"
                )
            sections.append("\n".join(lines))

        if not sections:
            return f"No results found for '{query}' across any NIST data source."

        header = f"## NIST Search: '{query}'\n\n_{total_found} results shown across {len(sections)} data source(s)_\n"
        return header + "\n\n".join(sections)
