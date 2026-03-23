"""MCP tools for compliance mapping and gap analysis."""

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


def _format_cmvp_entry(entry: dict) -> str:
    """Format a CMVP module entry as Markdown."""
    cert = entry.get("cert_number", "?")
    vendor = entry.get("vendor", "")
    module_name = entry.get("module_name", "")
    module_type = entry.get("module_type", "")
    fips_level = entry.get("fips_level", "")
    status = entry.get("status", "")
    validation_date = entry.get("validation_date", "")
    expiration_date = entry.get("expiration_date", "")
    algorithms = entry.get("algorithms", "")
    description = entry.get("description", "")

    lines = [f"### Cert #{cert} — {module_name}"]
    lines.append(f"**Vendor:** {vendor} | **Type:** {module_type} | **FIPS Level:** {fips_level}")

    status_line = f"**Status:** {status}"
    if validation_date:
        status_line += f" | **Validated:** {validation_date}"
    if expiration_date:
        status_line += f" | **Expires:** {expiration_date}"
    lines.append(status_line)

    if algorithms:
        lines.append(f"**Algorithms:** {algorithms}")

    if description:
        lines.append(f"\n{description}")

    return "\n".join(lines)


def _format_checklist_entry(entry: dict) -> str:
    """Format a checklist entry as Markdown."""
    cid = entry.get("id", "?")
    name = entry.get("name", "")
    product = entry.get("product", "")
    version = entry.get("version", "")
    authority = entry.get("authority", "")
    target_audience = entry.get("target_audience", "")
    fmt = entry.get("format", "")
    description = entry.get("description", "")
    download_url = entry.get("download_url", "")

    lines = [f"### {name}"]
    lines.append(f"**ID:** {cid} | **Product:** {product} {version}".strip())

    meta_parts = []
    if authority:
        meta_parts.append(f"Authority: {authority}")
    if target_audience:
        meta_parts.append(f"Audience: {target_audience}")
    if fmt:
        meta_parts.append(f"Format: {fmt}")
    if meta_parts:
        lines.append(" | ".join(meta_parts))

    if description:
        lines.append(f"\n{description}")

    if download_url:
        lines.append(f"\n[Download]({download_url})")

    return "\n".join(lines)


def _format_nice_role(entry: dict) -> str:
    """Format a NICE Framework work role as Markdown."""
    role_id = entry.get("id", "?")
    name = entry.get("name", "")
    category = entry.get("category", "")
    description = entry.get("description", "")

    lines = [f"### {role_id} — {name}"]
    if category:
        lines.append(f"**Category:** {category}")
    if description:
        lines.append(f"\n{description}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_compliance_tools(mcp: "FastMCP", index_mgr: "IndexManager") -> None:
    """Register CMVP, checklist, and NICE Framework tools on *mcp*."""

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def search_cmvp(
        vendor: Annotated[
            str | None,
            Field(description="Vendor/company name substring, e.g. 'Google', 'OpenSSL'"),
        ] = None,
        module_name: Annotated[
            str | None,
            Field(description="Module name substring, e.g. 'BoringCrypto', 'OpenSSL'"),
        ] = None,
        fips_level: Annotated[
            int | None,
            Field(description="FIPS validation level: 1, 2, or 3"),
        ] = None,
        algorithm: Annotated[
            str | None,
            Field(description="Algorithm name, e.g. 'AES', 'RSA', 'SHA-256'"),
        ] = None,
        status: Annotated[
            str,
            Field(description="Validation status: Active, Historical, Revoked"),
        ] = "Active",
        limit: Annotated[int, Field(ge=1, le=50)] = 20,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> str:
        """Search FIPS 140-2/3 validated cryptographic modules. 'Is OpenSSL FIPS validated?'
        or 'Which modules support AES-256-GCM at Level 2?'"""
        db_path = await index_mgr.ensure_index()

        # Build search terms for FTS if any text params are given
        fts_terms = []
        if vendor:
            fts_terms.append(vendor)
        if module_name:
            fts_terms.append(module_name)
        if algorithm:
            fts_terms.append(algorithm)

        conn = db.get_connection(db_path)
        try:
            where_parts: list[str] = []
            params: list = []

            if fts_terms:
                query_str = " ".join(fts_terms)
                expanded = db.expand_query_with_synonyms(db_path, query_str)
                expanded = db.sanitize_fts_query(expanded)
                where_parts.append("cmvp_fts MATCH ?")
                params.append(expanded)

            if status:
                where_parts.append("cmvp.status = ?")
                params.append(status)

            if fips_level is not None:
                where_parts.append("cmvp.fips_level = ?")
                params.append(str(fips_level))

            where_sql = " AND ".join(where_parts) if where_parts else "1=1"

            if fts_terms:
                base_sql = (
                    "FROM cmvp_fts "
                    "JOIN cmvp ON cmvp.rowid = cmvp_fts.rowid "
                    f"WHERE {where_sql}"
                )
                order_sql = "ORDER BY cmvp_fts.rank"
            else:
                base_sql = f"FROM cmvp WHERE {where_sql}"
                order_sql = "ORDER BY cmvp.validation_date DESC"

            count_sql = f"SELECT count(*) {base_sql}"
            total = conn.execute(count_sql, params).fetchone()[0]

            result_sql = f"SELECT cmvp.* {base_sql} {order_sql} LIMIT ? OFFSET ?"
            rows = conn.execute(result_sql, [*params, limit, offset]).fetchall()
            results = [dict(r) for r in rows]
        finally:
            conn.close()

        if not results:
            criteria_parts = []
            if vendor:
                criteria_parts.append(f"vendor='{vendor}'")
            if module_name:
                criteria_parts.append(f"module='{module_name}'")
            if fips_level is not None:
                criteria_parts.append(f"level={fips_level}")
            if algorithm:
                criteria_parts.append(f"algorithm='{algorithm}'")
            if status:
                criteria_parts.append(f"status='{status}'")
            criteria = ", ".join(criteria_parts) if criteria_parts else "given criteria"
            return f"No CMVP modules found matching {criteria}."

        start = offset + 1
        end = offset + len(results)
        page = (offset // limit) + 1
        total_pages = max(1, (total + limit - 1) // limit)

        lines = [
            f"**Showing {start}-{end} of {total} CMVP modules (page {page}/{total_pages})**\n"
        ]

        for entry in results:
            lines.append(_format_cmvp_entry(entry))
            lines.append("")

        if end < total:
            lines.append(f"_Use offset={end} to see the next page._")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def search_checklists(
        product: Annotated[
            str | None,
            Field(description="Product name, e.g. 'Windows Server 2022', 'Ubuntu'"),
        ] = None,
        format: Annotated[
            str | None,
            Field(description="Checklist format: XCCDF, OVAL, PDF, etc."),
        ] = None,
        authority: Annotated[
            str | None,
            Field(description="Issuing authority, e.g. 'DISA', 'CIS', 'NIST'"),
        ] = None,
        query: Annotated[
            str | None,
            Field(description="Full-text search across name, product, and description"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=50)] = 20,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> str:
        """Search NCP security configuration checklists. 'SCAP checklists for Windows Server 2022'
        or 'CIS benchmarks for Ubuntu'."""
        db_path = await index_mgr.ensure_index()

        # Compose a search query from text parameters
        fts_terms = []
        if query:
            fts_terms.append(query)
        if product:
            fts_terms.append(product)

        conn = db.get_connection(db_path)
        try:
            where_parts: list[str] = []
            params: list = []

            if fts_terms:
                query_str = " ".join(fts_terms)
                expanded = db.expand_query_with_synonyms(db_path, query_str)
                expanded = db.sanitize_fts_query(expanded)
                where_parts.append("checklists_fts MATCH ?")
                params.append(expanded)

            if format:
                where_parts.append("checklists.format = ?")
                params.append(format.upper())

            if authority:
                where_parts.append("checklists.authority LIKE ?")
                params.append(f"%{authority}%")

            where_sql = " AND ".join(where_parts) if where_parts else "1=1"

            if fts_terms:
                base_sql = (
                    "FROM checklists_fts "
                    "JOIN checklists ON checklists.rowid = checklists_fts.rowid "
                    f"WHERE {where_sql}"
                )
                order_sql = "ORDER BY checklists_fts.rank"
            else:
                base_sql = f"FROM checklists WHERE {where_sql}"
                order_sql = "ORDER BY checklists.name"

            count_sql = f"SELECT count(*) {base_sql}"
            total = conn.execute(count_sql, params).fetchone()[0]

            result_sql = f"SELECT checklists.* {base_sql} {order_sql} LIMIT ? OFFSET ?"
            rows = conn.execute(result_sql, [*params, limit, offset]).fetchall()
            results = [dict(r) for r in rows]
        finally:
            conn.close()

        if not results:
            return "No checklists found matching your criteria."

        start = offset + 1
        end = offset + len(results)
        page = (offset // limit) + 1
        total_pages = max(1, (total + limit - 1) // limit)

        lines = [
            f"**Showing {start}-{end} of {total} checklists (page {page}/{total_pages})**\n"
        ]

        for entry in results:
            lines.append(_format_checklist_entry(entry))
            lines.append("")

        if end < total:
            lines.append(f"_Use offset={end} to see the next page._")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def search_nice_roles(
        query: Annotated[
            str | None,
            Field(description="Search terms, e.g. 'incident response', 'penetration testing'"),
        ] = None,
        category: Annotated[
            str | None,
            Field(
                description=(
                    "NICE category: 'Analyze', 'Collect and Operate', 'Investigate', "
                    "'Operate and Maintain', 'Oversee and Govern', "
                    "'Protect and Defend', 'Securely Provision'"
                )
            ),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=50)] = 20,
    ) -> str:
        """Search NICE Framework work roles. 'What role handles incident response?'"""
        db_path = await index_mgr.ensure_index()

        conn = db.get_connection(db_path)
        try:
            where_parts: list[str] = []
            params: list = []

            if category:
                where_parts.append("nice_roles.category LIKE ?")
                params.append(f"%{category}%")

            if query:
                # nice_roles has no FTS table — use LIKE on name + description.
                # Split query into words so "penetration testing" matches roles
                # containing either word individually.
                words = query.strip().split()
                word_clauses = []
                for word in words:
                    like_val = f"%{word}%"
                    word_clauses.append(
                        "(nice_roles.name LIKE ? OR nice_roles.description LIKE ? "
                        "OR nice_roles.id LIKE ?)"
                    )
                    params.extend([like_val, like_val, like_val])
                where_parts.append(f"({' OR '.join(word_clauses)})")

            where_sql = " AND ".join(where_parts) if where_parts else "1=1"

            count_sql = f"SELECT count(*) FROM nice_roles WHERE {where_sql}"
            total = conn.execute(count_sql, params).fetchone()[0]

            result_sql = (
                f"SELECT * FROM nice_roles WHERE {where_sql} "
                f"ORDER BY nice_roles.category, nice_roles.name LIMIT ?"
            )
            rows = conn.execute(result_sql, [*params, limit]).fetchall()
            results = [dict(r) for r in rows]
        finally:
            conn.close()

        if not results:
            return "No NICE Framework work roles found matching your criteria."

        lines = [f"**{total} NICE work roles found**\n"]

        for entry in results:
            lines.append(_format_nice_role(entry))
            lines.append("")

        if total > limit:
            lines.append(
                f"_Showing first {limit} of {total} roles. Use a more specific query to narrow results._"
            )

        return "\n".join(lines)
