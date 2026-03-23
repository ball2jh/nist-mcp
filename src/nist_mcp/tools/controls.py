"""MCP tools for querying SP 800-53 controls and enhancements."""

from __future__ import annotations

import logging
import re
from pathlib import Path
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


def _format_control_summary(ctrl: dict) -> str:
    """Format a control for summary detail level (~50 tokens)."""
    label = ctrl.get("label", ctrl.get("id", "?"))
    title = ctrl.get("title", "Untitled")
    withdrawn = " _(withdrawn)_" if ctrl.get("is_withdrawn") else ""
    return f"- **{label}** {title}{withdrawn}"


def _format_control_standard(ctrl: dict) -> str:
    """Format a control for standard detail level (~200 tokens)."""
    lines: list[str] = []
    label = ctrl.get("label", ctrl.get("id", "?"))
    title = ctrl.get("title", "Untitled")
    withdrawn = " _(withdrawn)_" if ctrl.get("is_withdrawn") else ""
    lines.append(f"### {label} {title}{withdrawn}")

    statement = ctrl.get("statement")
    if statement:
        lines.append(f"\n{statement}\n")

    baselines = ctrl.get("baselines")
    if baselines:
        lines.append(f"**Baselines:** {baselines}")

    return "\n".join(lines)


def _format_control_full(ctrl: dict) -> str:
    """Format a control with all available fields (~500+ tokens)."""
    lines: list[str] = []
    label = ctrl.get("label", ctrl.get("id", "?"))
    title = ctrl.get("title", "Untitled")
    withdrawn = " _(withdrawn)_" if ctrl.get("is_withdrawn") else ""
    lines.append(f"### {label} {title}{withdrawn}")

    if ctrl.get("is_withdrawn") and ctrl.get("withdrawn_to"):
        lines.append(f"\n_Withdrawn. Incorporated into: {ctrl['withdrawn_to']}_\n")

    statement = ctrl.get("statement")
    if statement:
        lines.append(f"\n**Statement:**\n{statement}\n")

    guidance = ctrl.get("guidance")
    if guidance:
        lines.append(f"**Supplemental Guidance:**\n{guidance}\n")

    parameters = ctrl.get("parameters")
    if parameters and parameters != "[]":
        lines.append(f"**Parameters:** {parameters}\n")

    baselines = ctrl.get("baselines")
    if baselines:
        lines.append(f"**Baselines:** {baselines}")

    related = ctrl.get("related_controls")
    if related:
        lines.append(f"**Related Controls:** {related}")

    return "\n".join(lines)


def _format_control_detail(ctrl: dict, detail_level: str) -> str:
    """Dispatch to the appropriate formatter."""
    if detail_level == "full":
        return _format_control_full(ctrl)
    elif detail_level == "standard":
        return _format_control_standard(ctrl)
    return _format_control_summary(ctrl)


def _format_control_complete(ctrl: dict, mappings: list[dict]) -> str:
    """Format a single control with everything including mappings."""
    lines: list[str] = []
    label = ctrl.get("label", ctrl.get("id", "?"))
    title = ctrl.get("title", "Untitled")
    family = ctrl.get("family_name", "")
    withdrawn = " _(withdrawn)_" if ctrl.get("is_withdrawn") else ""

    lines.append(f"# {label} {title}{withdrawn}")
    lines.append(f"**Family:** {family} ({ctrl.get('family_id', '').upper()})\n")

    if ctrl.get("is_enhancement"):
        lines.append(f"**Enhancement of:** {ctrl.get('parent_id', '?').upper()}\n")

    if ctrl.get("is_withdrawn") and ctrl.get("withdrawn_to"):
        lines.append(f"_Withdrawn. Incorporated into: {ctrl['withdrawn_to']}_\n")

    statement = ctrl.get("statement")
    if statement:
        lines.append(f"## Statement\n\n{statement}\n")

    guidance = ctrl.get("guidance")
    if guidance:
        lines.append(f"## Supplemental Guidance\n\n{guidance}\n")

    parameters = ctrl.get("parameters")
    if parameters and parameters != "[]":
        lines.append(f"## Parameters\n\n{parameters}\n")

    baselines = ctrl.get("baselines")
    if baselines:
        lines.append(f"**Baselines:** {baselines}")

    related = ctrl.get("related_controls")
    if related:
        lines.append(f"**Related Controls:** {related}")

    if mappings:
        lines.append("\n## Cross-Framework Mappings\n")
        for m in mappings:
            source = f"{m['source_framework']}:{m['source_id']}"
            target = f"{m['target_framework']}:{m['target_id']}"
            rel = m.get("relationship", "related")
            lines.append(f"- {source} -> {target} ({rel})")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


def _get_mappings_for_control(db_path: Path, control_id: str) -> list[dict]:
    """Fetch cross-framework mappings involving *control_id*."""
    conn = db.get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM mappings WHERE source_id = ? OR target_id = ?",
            (control_id, control_id),
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []
    finally:
        conn.close()


def _get_enhancements(db_path: Path, parent_id: str) -> list[dict]:
    """Fetch all enhancement controls for a given parent control."""
    conn = db.get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM controls WHERE parent_id = ? ORDER BY id",
            (parent_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []
    finally:
        conn.close()


def _search_controls_with_baseline(
    db_path: Path,
    query: str | None,
    filters: dict,
    baseline: str | None,
    limit: int,
    offset: int,
) -> tuple[list[dict], int]:
    """Search controls, optionally filtering by baseline via LIKE.

    The ``baselines`` column stores comma-separated values like
    ``"HIGH,LOW,MODERATE"`` so we need a LIKE filter, which
    ``db.search_fts`` does not support.  When a baseline filter is
    needed, we run a direct query.
    """
    if not baseline and query:
        return db.search_fts(
            db_path, "controls", query, filters=filters,
            limit=limit, offset=offset,
        )

    # Build a custom query for baseline filtering and/or no FTS query.
    conn = db.get_connection(db_path)
    try:
        where_parts: list[str] = []
        params: list = []

        if query:
            expanded = db.expand_query_with_synonyms(db_path, query)
            expanded = db.sanitize_fts_query(expanded)
            where_parts.append("controls_fts MATCH ?")
            params.append(expanded)

        for col, val in filters.items():
            db._validate_identifier(col)
            where_parts.append(f"controls.{col} = ?")
            params.append(val)

        if baseline:
            where_parts.append("controls.baselines LIKE ?")
            params.append(f"%{baseline.upper()}%")

        where_sql = " AND ".join(where_parts) if where_parts else "1=1"

        if query:
            # Join through FTS.
            base_sql = (
                "FROM controls_fts "
                "JOIN controls ON controls.rowid = controls_fts.rowid "
                f"WHERE {where_sql}"
            )
            order = "ORDER BY controls_fts.rank"
        else:
            base_sql = f"FROM controls WHERE {where_sql}"
            order = "ORDER BY controls.id"

        count_sql = f"SELECT count(*) {base_sql}"
        total = conn.execute(count_sql, params).fetchone()[0]

        result_sql = f"SELECT controls.* {base_sql} {order} LIMIT ? OFFSET ?"
        rows = conn.execute(result_sql, [*params, limit, offset]).fetchall()

        return [dict(r) for r in rows], total
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_control_tools(mcp: FastMCP, index_mgr: IndexManager) -> None:
    """Register SP 800-53 control query tools on *mcp*."""

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def search_controls(
        query: Annotated[
            str | None, Field(description="Search keywords")
        ] = None,
        family: Annotated[
            str | None,
            Field(description="Control family ID, e.g. 'ac', 'ia', 'sc'"),
        ] = None,
        baseline: Annotated[
            str | None,
            Field(description="Baseline level: LOW, MODERATE, HIGH"),
        ] = None,
        include_withdrawn: Annotated[
            bool, Field(description="Include withdrawn controls")
        ] = False,
        detail_level: Annotated[
            str, Field(description="summary, standard, or full")
        ] = "summary",
        limit: Annotated[int, Field(ge=1, le=50)] = 20,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> str:
        """Search NIST SP 800-53 Rev 5 security and privacy controls by keyword, family,
        or baseline. Accepts flexible ID formats (AC-2, ac-2, AC2 all work).

        summary: label + title (~50 tokens/result)
        standard: + statement text + baselines (~200 tokens/result)
        full: + guidance + parameters + related controls (~500+ tokens/result)

        Use get_control for the complete detail of a specific control including enhancements."""
        db_path = await index_mgr.ensure_index()

        if not query and not family and not baseline:
            return (
                "Please provide at least one of: `query`, `family`, or `baseline` "
                "to search controls."
            )

        # If the query looks like a control ID, normalize it.
        fts_query = query
        if query:
            normalized = db.normalize_control_id(query)
            # Check if it looks like a control ID (letters followed by hyphen and digits).
            if re.match(r"^[a-z]{2}-\d", normalized):
                fts_query = normalized

        filters: dict = {}
        if family:
            filters["family_id"] = family.lower()
        if not include_withdrawn:
            filters["is_withdrawn"] = 0

        results, total = _search_controls_with_baseline(
            db_path,
            fts_query,
            filters,
            baseline,
            limit,
            offset,
        )

        if not results:
            return "No controls found matching your criteria."

        start = offset + 1
        end = offset + len(results)
        page = (offset // limit) + 1
        total_pages = (total + limit - 1) // limit

        lines = [
            f"**Showing {start}-{end} of {total} controls (page {page}/{total_pages})**\n"
        ]

        for ctrl in results:
            lines.append(_format_control_detail(ctrl, detail_level))
            if detail_level != "summary":
                lines.append("")

        if end < total:
            lines.append(f"\n_Use offset={end} to see the next page._")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_control(
        control_id: Annotated[
            str,
            Field(description="Control ID, e.g. 'AC-2', 'ac-2', 'IA-5(1)'"),
        ],
        include_enhancements: Annotated[
            bool, Field(description="Include all enhancements")
        ] = False,
    ) -> str:
        """Get complete details for a specific SP 800-53 Rev 5 control: statement,
        guidance, parameters, related controls, baselines, and cross-framework mappings.

        Set include_enhancements=True to also get all enhancement sub-controls.
        Do NOT use this for searching -- use search_controls to find controls first."""
        db_path = await index_mgr.ensure_index()

        normalized = db.normalize_control_id(control_id)
        ctrl = db.get_by_id(db_path, "controls", normalized)

        if ctrl is None:
            return f"Control **{control_id}** (normalized: {normalized}) not found."

        mappings = _get_mappings_for_control(db_path, normalized)
        md = _format_control_complete(ctrl, mappings)

        if include_enhancements:
            enhancements = _get_enhancements(db_path, normalized)
            if enhancements:
                md += f"\n\n## Enhancements ({len(enhancements)})\n"
                for enh in enhancements:
                    md += "\n" + _format_control_full(enh) + "\n"
            else:
                md += "\n\n_No enhancements for this control._"

        return md
