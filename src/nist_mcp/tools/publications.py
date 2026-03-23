"""MCP tools for searching and retrieving NIST publications."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

from mcp.types import ToolAnnotations
from pydantic import Field

from nist_mcp import db
from nist_mcp.convert import (
    convert_to_markdown,
    download_file,
    get_pdf_section,
    get_pdf_toc,
)

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from nist_mcp.config import Config
    from nist_mcp.index import IndexManager

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Detail-level formatters
# ---------------------------------------------------------------------------

def _format_publication(pub: dict, detail_level: str) -> str:
    """Format a single publication dict as Markdown."""
    lines: list[str] = []

    lines.append(f"### {pub.get('id', '?')}")
    lines.append(f"**{pub.get('title', 'Untitled')}**\n")

    if detail_level == "summary":
        if pub.get("series"):
            lines.append(f"- Series: {pub['series']}")
        if pub.get("pub_date"):
            lines.append(f"- Date: {pub['pub_date']}")
        return "\n".join(lines)

    # standard or full
    for key in ("series", "pub_date", "status", "pub_type"):
        val = pub.get(key)
        if val:
            label = key.replace("_", " ").title()
            lines.append(f"- {label}: {val}")

    abstract = pub.get("abstract")
    if abstract and detail_level in ("standard", "full"):
        lines.append(f"\n{abstract}\n")

    if detail_level == "full":
        for key in ("authors", "topics", "doi", "detail_url", "supersedes",
                     "superseded_by", "related_pubs"):
            val = pub.get(key)
            if val:
                label = key.replace("_", " ").title()
                lines.append(f"- {label}: {val}")

    return "\n".join(lines)


def _format_publication_full(pub: dict) -> str:
    """Format a publication with all available metadata."""
    lines: list[str] = []
    lines.append(f"# {pub.get('id', '?')}")
    lines.append(f"**{pub.get('title', 'Untitled')}**\n")

    for key, label in [
        ("series", "Series"),
        ("number", "Number"),
        ("revision", "Revision"),
        ("status", "Status"),
        ("pub_type", "Type"),
        ("pub_date", "Published"),
        ("doi", "DOI"),
        ("detail_url", "Detail URL"),
    ]:
        val = pub.get(key)
        if val:
            lines.append(f"- **{label}:** {val}")

    lines.append("")

    abstract = pub.get("abstract")
    if abstract:
        lines.append(f"## Abstract\n\n{abstract}\n")

    authors = pub.get("authors")
    if authors:
        lines.append(f"## Authors\n\n{authors}\n")

    topics = pub.get("topics")
    if topics:
        lines.append(f"## Topics\n\n{topics}\n")

    # Supersedes chain
    for key, label in [
        ("supersedes", "Supersedes"),
        ("superseded_by", "Superseded By"),
        ("related_pubs", "Related Publications"),
    ]:
        val = pub.get(key)
        if val:
            lines.append(f"- **{label}:** {val}")

    is_latest = pub.get("is_latest")
    if is_latest is not None:
        lines.append(f"- **Latest revision:** {'Yes' if is_latest else 'No'}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Supplemental materials helper
# ---------------------------------------------------------------------------

def _get_supplemental_materials(db_path: Path, pub_id: str) -> list[dict]:
    """Fetch supplemental materials for a publication."""
    conn = db.get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM supplemental_materials WHERE pub_id = ?",
            (pub_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []
    finally:
        conn.close()


def _format_supplemental_list(materials: list[dict]) -> str:
    """Format supplemental materials as a numbered Markdown list."""
    if not materials:
        return ""
    lines = ["\n## Supplemental Materials\n"]
    for i, mat in enumerate(materials):
        title = mat.get("title", "Untitled")
        fmt = mat.get("format", "")
        desc = mat.get("description", "")
        line = f"{i}. **{title}**"
        if fmt:
            line += f" ({fmt})"
        if desc:
            line += f" — {desc}"
        lines.append(line)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_publication_tools(
    mcp: FastMCP, index_mgr: IndexManager, config: Config
) -> None:
    """Register publication search and retrieval tools on *mcp*."""

    from fastmcp.server.context import Context
    from fastmcp.server.dependencies import CurrentContext

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def search_publications(
        query: Annotated[
            str, Field(description="Search keywords (title, abstract, topic)")
        ],
        series: Annotated[
            str | None,
            Field(description="Filter by series: SP, FIPS, IR, CSWP, AI"),
        ] = None,
        status: Annotated[
            str | None,
            Field(description="Filter by status: Final, Draft, Withdrawn"),
        ] = None,
        pub_type: Annotated[
            str | None,
            Field(
                description="Filter by type: Standard, Guideline, Framework, etc."
            ),
        ] = None,
        latest_only: Annotated[
            bool,
            Field(description="Only show newest revision of each document"),
        ] = True,
        detail_level: Annotated[
            str, Field(description="summary, standard, or full")
        ] = "summary",
        limit: Annotated[int, Field(description="Max results", ge=1, le=50)] = 20,
        offset: Annotated[int, Field(description="Pagination offset", ge=0)] = 0,
    ) -> str:
        """Search NIST publications by keyword across all series (SP 800, SP 1800, FIPS, IR, CSWP, AI).

        Returns matching publications with ID, title, date, and series. Use get_publication
        for full details on a specific publication. Default shows only the latest revision
        of each document. Do NOT use this for SP 800-53 security controls -- use search_controls instead."""
        db_path = await index_mgr.ensure_index()

        filters: dict = {}
        if series:
            filters["series"] = series.upper()
        if status:
            filters["status"] = status
        if pub_type:
            filters["pub_type"] = pub_type
        if latest_only:
            filters["is_latest"] = 1

        results, total = db.search_fts(
            db_path, "publications", query, filters=filters,
            limit=limit, offset=offset,
        )

        if not results:
            return "No publications found matching your query."

        # Pagination info.
        start = offset + 1
        end = offset + len(results)
        page = (offset // limit) + 1
        total_pages = (total + limit - 1) // limit

        lines = [f"**Showing {start}-{end} of {total} results (page {page}/{total_pages})**\n"]

        for pub in results:
            lines.append(_format_publication(pub, detail_level))
            lines.append("")

        if end < total:
            lines.append(
                f"_Use offset={end} to see the next page._"
            )

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_publication(
        publication_id: Annotated[
            str,
            Field(
                description="Publication ID, e.g. 'SP.800-53-Rev.-5' or 'FIPS.140-3'"
            ),
        ],
    ) -> str:
        """Get full metadata for a specific NIST publication including title, abstract,
        authors, date, supersedes chain, related publications, and list of supplemental materials."""
        db_path = await index_mgr.ensure_index()

        pub = db.get_by_id(db_path, "publications", publication_id)
        if pub is None:
            return f"Publication **{publication_id}** not found."

        md = _format_publication_full(pub)

        # Append supplemental materials.
        materials = _get_supplemental_materials(db_path, publication_id)
        if materials:
            md += _format_supplemental_list(materials)

        return md

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False))
    async def get_document_content(
        publication_id: Annotated[str, Field(description="Publication ID")],
        section: Annotated[
            str | None, Field(description="Section heading to extract")
        ] = None,
        pages: Annotated[
            str | None, Field(description="Page range, e.g. '1-50'")
        ] = None,
        ctx: Context = CurrentContext(),
    ) -> str:
        """Retrieve publication content as Markdown. Without section/pages, returns table
        of contents. With section, returns that section. With pages, returns those pages.
        Handles PDF, XLSX, CSV, JSON, and XML formats. Results are cached locally.

        Use this to read the actual content of NIST documents. For large documents like
        SP 800-53 (492 pages), use the pages parameter to request specific page ranges."""
        db_path = await index_mgr.ensure_index()

        pub = db.get_by_id(db_path, "publications", publication_id)
        if pub is None:
            return f"Publication **{publication_id}** not found."

        pdf_url = pub.get("pdf_url")
        if not pdf_url:
            detail = pub.get("detail_url", "")
            return (
                f"No downloadable document URL available for **{publication_id}**.\n\n"
                f"This publication's detail page is: {detail}\n\n"
                f"The document may need to be downloaded manually from the NIST website."
            )

        # Determine local file path.
        doc_dir = config.data_dir / "docs" / publication_id
        filename = pdf_url.rsplit("/", 1)[-1]
        local_path = doc_dir / filename

        # Download if needed.
        await ctx.report_progress(progress=0, total=3)
        await download_file(pdf_url, local_path)
        await ctx.report_progress(progress=1, total=3)

        suffix = local_path.suffix.lower()

        if suffix == ".pdf":
            if section:
                await ctx.report_progress(progress=2, total=3)
                md = get_pdf_section(local_path, section)
                await ctx.report_progress(progress=3, total=3)
                return md
            elif pages:
                await ctx.report_progress(progress=2, total=3)
                md = convert_to_markdown(local_path, pages=pages)
                await ctx.report_progress(progress=3, total=3)
                return md
            else:
                # No section/pages: return TOC.
                await ctx.report_progress(progress=2, total=3)
                toc = get_pdf_toc(local_path)
                await ctx.report_progress(progress=3, total=3)
                return (
                    f"# {pub.get('title', publication_id)}\n\n"
                    f"{toc}\n\n"
                    f"_Use `section` or `pages` parameter to read specific content._"
                )
        else:
            # Non-PDF: convert the whole thing.
            await ctx.report_progress(progress=2, total=3)
            md = convert_to_markdown(local_path)
            await ctx.report_progress(progress=3, total=3)
            return md

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False))
    async def download_document(
        publication_id: Annotated[str, Field(description="Publication ID")],
        material_index: Annotated[
            int | None,
            Field(
                description="Index of supplemental material (from get_publication output)"
            ),
        ] = None,
        ctx: Context = CurrentContext(),
    ) -> str:
        """Download a publication PDF or supplemental material to local cache.
        Returns the file path. Use material_index to download a specific supplemental
        file listed in the get_publication output."""
        db_path = await index_mgr.ensure_index()

        pub = db.get_by_id(db_path, "publications", publication_id)
        if pub is None:
            return f"Publication **{publication_id}** not found."

        if material_index is not None:
            # Download a supplemental material.
            materials = _get_supplemental_materials(db_path, publication_id)
            if not materials:
                return f"No supplemental materials found for **{publication_id}**."
            if material_index < 0 or material_index >= len(materials):
                return (
                    f"Invalid material_index {material_index}. "
                    f"Valid range: 0-{len(materials) - 1}."
                )
            mat = materials[material_index]
            url = mat.get("url")
            if not url:
                return f"Supplemental material {material_index} has no download URL."

            doc_dir = config.data_dir / "docs" / publication_id
            filename = url.rsplit("/", 1)[-1]
            local_path = doc_dir / filename

            await ctx.report_progress(progress=0, total=1)
            await download_file(url, local_path)
            await ctx.report_progress(progress=1, total=1)

            return (
                f"Downloaded supplemental material to:\n`{local_path}`\n\n"
                f"- **Title:** {mat.get('title', 'Untitled')}\n"
                f"- **Format:** {mat.get('format', 'unknown')}"
            )

        # Download the main document.
        pdf_url = pub.get("pdf_url")
        if not pdf_url:
            detail = pub.get("detail_url", "")
            return (
                f"No downloadable document URL available for **{publication_id}**.\n\n"
                f"Detail page: {detail}\n\n"
                f"The PDF URL is not in the database. Try visiting the detail page."
            )

        doc_dir = config.data_dir / "docs" / publication_id
        filename = pdf_url.rsplit("/", 1)[-1]
        local_path = doc_dir / filename

        await ctx.report_progress(progress=0, total=1)
        await download_file(pdf_url, local_path)
        await ctx.report_progress(progress=1, total=1)

        return f"Downloaded to:\n`{local_path}`"

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_latest_revision(
        publication_id: Annotated[
            str,
            Field(description="Any publication ID, e.g. 'SP.800-53-Rev.-5'"),
        ],
    ) -> str:
        """Resolve any publication to its newest available revision. Follows the
        supersedes chain. Use this when you need the most current version of a document."""
        db_path = await index_mgr.ensure_index()

        current_id = publication_id
        visited: set[str] = set()

        while True:
            if current_id in visited:
                # Cycle detected.
                break
            visited.add(current_id)

            pub = db.get_by_id(db_path, "publications", current_id)
            if pub is None:
                return f"Publication **{current_id}** not found."

            if pub.get("is_latest"):
                if current_id == publication_id:
                    return (
                        f"**{current_id}** is already the latest revision.\n\n"
                        f"- **Title:** {pub.get('title', 'Untitled')}\n"
                        f"- **Date:** {pub.get('pub_date', 'unknown')}"
                    )
                return (
                    f"Latest revision: **{current_id}**\n\n"
                    f"- **Title:** {pub.get('title', 'Untitled')}\n"
                    f"- **Date:** {pub.get('pub_date', 'unknown')}\n"
                    f"- **Resolved from:** {publication_id}"
                )

            superseded_by = pub.get("superseded_by")
            if not superseded_by:
                # No further chain; this is effectively the latest we know.
                return (
                    f"**{current_id}** has no newer revision linked.\n\n"
                    f"- **Title:** {pub.get('title', 'Untitled')}\n"
                    f"- **Date:** {pub.get('pub_date', 'unknown')}"
                )

            current_id = superseded_by

        return f"Could not resolve latest revision for **{publication_id}** (cycle detected)."
