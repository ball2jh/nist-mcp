"""Small MCP tool surface for NIST catalog access."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated, Literal

from fastmcp.exceptions import ToolError
from fastmcp.server.context import Context
from fastmcp.server.dependencies import CurrentContext
from mcp.types import ToolAnnotations
from pydantic import Field

from nist_mcp import db
from nist_mcp.convert import convert_to_markdown, download_file, get_pdf_section, get_pdf_toc
from nist_mcp.safety import safe_filename_from_url

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from nist_mcp.config import Config
    from nist_mcp.index import IndexManager
    from nist_mcp.kev import KEVClient
    from nist_mcp.nvd import NVDClient

log = logging.getLogger(__name__)

Source = Literal[
    "publications",
    "controls",
    "csf",
    "glossary",
    "cmvp",
    "checklists",
    "nice",
]

NvdKind = Literal["cve", "cpe"]
DetailLevel = Literal["summary", "standard", "full"]


_SOURCE_TABLES: dict[str, str] = {
    "publications": "publications",
    "controls": "controls",
    "csf": "csf",
    "glossary": "glossary",
    "cmvp": "cmvp",
    "checklists": "checklists",
    "nice": "nice_roles",
}

_SOURCE_LABELS: dict[str, str] = {
    "publications": "Publications",
    "controls": "SP 800-53 Controls",
    "csf": "CSF 2.0",
    "glossary": "Glossary",
    "cmvp": "CMVP Modules",
    "checklists": "NCP Checklists",
    "nice": "NICE Roles",
}


def _fmt_row(source: str, row: dict, detail: DetailLevel = "summary") -> str:
    """Format one local database row as compact Markdown."""
    if source == "publications":
        title = row.get("title") or "Untitled"
        line = f"**{row.get('id', '?')}** - {title}"
        if row.get("pub_date"):
            line += f" ({row['pub_date']})"
        if detail != "summary" and row.get("abstract"):
            line += f"\n  {row['abstract']}"
        return line

    if source == "controls":
        label = row.get("label") or row.get("id") or "?"
        withdrawn = " _(withdrawn)_" if row.get("is_withdrawn") else ""
        line = f"**{label}** - {row.get('title', 'Untitled')}{withdrawn}"
        if detail != "summary" and row.get("statement"):
            line += f"\n  {row['statement']}"
        return line

    if source == "csf":
        title = row.get("title") or row.get("category_name") or row.get("function_name") or ""
        return f"**{row.get('id', '?')}** [{row.get('level', '')}] - {title}"

    if source == "glossary":
        definition = row.get("definition") or ""
        if detail == "summary" and len(definition) > 160:
            definition = definition[:157] + "..."
        return f"**{row.get('term', '?')}** - {definition}"

    if source == "cmvp":
        cert = row.get("cert_number") or "?"
        vendor = row.get("vendor") or ""
        name = row.get("module_name") or ""
        level = row.get("fips_level") or "?"
        return f"**Cert #{cert}** - {vendor} {name} (Level {level})"

    if source == "checklists":
        name = row.get("name") or "Untitled"
        product = row.get("product") or ""
        return f"**{row.get('id', '?')}** - {name} ({product})"

    role_id = row.get("id") or "?"
    category = row.get("category") or ""
    return f"**{role_id}** - {row.get('name', 'Untitled')} [{category}]"


def _format_record(source: str, row: dict) -> str:
    """Format a full local database record without source-specific ceremony."""
    title = (
        row.get("title")
        or row.get("name")
        or row.get("term")
        or row.get("module_name")
        or row.get("id")
        or row.get("cert_number")
        or "NIST record"
    )
    lines = [f"# {title}", ""]

    for key, value in row.items():
        if value in (None, "", "[]"):
            continue
        label = key.replace("_", " ").title()
        if key in {"abstract", "description", "definition", "statement", "guidance"}:
            lines.append(f"## {label}\n\n{value}\n")
        else:
            lines.append(f"- **{label}:** {value}")

    return "\n".join(lines)


def _supplemental_materials(db_path, publication_id: str) -> list[dict]:
    conn = db.get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM supplemental_materials WHERE pub_id = ? ORDER BY rowid",
            (publication_id,),
        ).fetchall()
        return [dict(row) for row in rows]
    except Exception:
        return []
    finally:
        conn.close()


def _find_record(db_path, source: str, record_id: str) -> dict | None:
    table = _SOURCE_TABLES[source]
    lookup = record_id.strip()

    if source == "controls":
        lookup = db.normalize_control_id(lookup)
    elif source == "csf":
        lookup = lookup.upper()

    record = db.get_by_id(db_path, table, lookup)
    if record is not None:
        return record

    if source == "glossary":
        conn = db.get_connection(db_path)
        try:
            row = conn.execute(
                "SELECT * FROM glossary WHERE lower(term) = lower(?)",
                (record_id,),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    return None


def _format_cve(item: dict, kev_entry: dict | None = None) -> str:
    cve_id = item.get("id", "?")
    lines = [f"# {cve_id}"]

    meta = []
    for key, label in [
        ("published", "Published"),
        ("lastModified", "Modified"),
        ("vulnStatus", "Status"),
    ]:
        if item.get(key):
            meta.append(f"{label}: {str(item[key])[:10]}")
    if meta:
        lines.append(" | ".join(meta))
    lines.append("")

    if kev_entry:
        lines.append("## CISA KEV")
        vendor_product = (
            f"{kev_entry.get('vendorProject', '')} - {kev_entry.get('product', '')}"
        )
        lines.append(f"- **Vendor/Product:** {vendor_product}")
        lines.append(f"- **Due Date:** {kev_entry.get('dueDate', 'N/A')}")
        lines.append(f"- **Required Action:** {kev_entry.get('requiredAction', 'N/A')}")
        lines.append("")

    for desc in item.get("descriptions", []):
        if desc.get("lang") == "en":
            lines.append("## Description")
            lines.append(desc.get("value", ""))
            lines.append("")
            break

    metrics = item.get("metrics", {})
    for bucket in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(bucket):
            metric = metrics[bucket][0]
            cvss = metric.get("cvssData", {})
            score = cvss.get("baseScore", "?")
            severity = cvss.get("baseSeverity") or metric.get("baseSeverity", "")
            vector = cvss.get("vectorString", "")
            lines.append(f"**CVSS:** {score} {severity} ({vector})")
            break

    weaknesses = []
    for weakness in item.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en" and desc.get("value"):
                weaknesses.append(desc["value"])
    if weaknesses:
        lines.append(f"**Weaknesses:** {', '.join(sorted(set(weaknesses)))}")

    refs = [ref.get("url") for ref in item.get("references", []) if ref.get("url")]
    if refs:
        lines.append("\n## References")
        lines.extend(f"- {url}" for url in refs[:20])
        if len(refs) > 20:
            lines.append(f"- ...and {len(refs) - 20} more")

    return "\n".join(lines)


def register_tools(
    mcp: "FastMCP",
    index_mgr: "IndexManager",
    config: "Config",
    nvd_client: "NVDClient",
    kev_client: "KEVClient",
) -> None:
    """Register the intentionally small NIST MCP tool set."""

    @mcp.tool(
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            openWorldHint=True,
        )
    )
    async def update_database() -> str:
        """Rebuild the local NIST catalog from NIST source data."""
        built_at = await index_mgr.force_update()
        return f"Database rebuilt at: {built_at}"

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def database_status() -> str:
        """Show local database availability, freshness, size, and path."""
        info = index_mgr.status()
        return "\n".join(
            [
                "## NIST Database Status",
                f"- **Available:** {'Yes' if info['exists'] else 'No'}",
                f"- **Built:** {info.get('built_at', 'never')}",
                f"- **Last check:** {info.get('last_check', 'never')}",
                f"- **Size bytes:** {info.get('db_size_bytes') or 0}",
                f"- **Path:** `{info['path']}`",
            ]
        )

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def search_nist(
        query: Annotated[str, Field(description="Search keywords", max_length=500)],
        source: Annotated[
            Source | None,
            Field(
                description=(
                    "Optional source: publications, controls, csf, glossary, "
                    "cmvp, checklists, nice"
                )
            ),
        ] = None,
        detail: Annotated[DetailLevel, Field(description="summary, standard, or full")] = "summary",
        limit: Annotated[int, Field(ge=1, le=50)] = 10,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> str:
        """Search local NIST data. Omit source to search all local sources."""
        db_path = await index_mgr.ensure_index()
        sources = [source] if source else list(_SOURCE_TABLES)
        per_source = limit if source else max(2, limit // len(sources))

        sections: list[str] = []
        shown = 0
        for src in sources:
            table = _SOURCE_TABLES[src]
            try:
                rows, total = db.search_fts(
                    db_path,
                    table,
                    query,
                    limit=per_source,
                    offset=offset if source else 0,
                )
            except Exception as exc:
                log.debug("Search failed for %s: %s", src, exc)
                continue

            if not rows:
                continue

            shown += len(rows)
            lines = [f"### {_SOURCE_LABELS[src]} ({total} total)"]
            lines.extend(f"- {_fmt_row(src, row, detail)}" for row in rows)
            if total > per_source:
                next_offset = offset + len(rows) if source else per_source
                lines.append(f"\n_Use source='{src}' offset={next_offset} for more._")
            sections.append("\n".join(lines))

        if not sections:
            return f"No local NIST results found for '{query}'."

        return f"## NIST Search: {query}\n\n_Showing {shown} results_\n\n" + "\n\n".join(sections)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
    async def get_nist_record(
        source: Annotated[Source, Field(description="Source containing the record")],
        record_id: Annotated[str, Field(description="Record identifier", max_length=200)],
    ) -> str:
        """Fetch one local NIST record by source and identifier."""
        db_path = await index_mgr.ensure_index()
        record = _find_record(db_path, source, record_id)
        if record is None:
            return f"No {source} record found for '{record_id}'."

        md = _format_record(source, record)
        if source == "publications":
            materials = _supplemental_materials(db_path, record["id"])
            if materials:
                md += "\n\n## Supplemental Materials\n"
                for idx, material in enumerate(materials):
                    title = material.get("title") or "Untitled"
                    fmt = material.get("format") or "unknown"
                    md += f"\n- **{idx}:** {title} ({fmt})"
        return md

    @mcp.tool(
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def read_publication(
        publication_id: Annotated[str, Field(description="Publication ID", max_length=200)],
        section: Annotated[str | None, Field(description="Section heading", max_length=200)] = None,
        pages: Annotated[
            str | None,
            Field(description="Page range, e.g. 1-10", max_length=64),
        ] = None,
        material_index: Annotated[
            int | None,
            Field(description="Supplemental material index from get_nist_record", ge=0),
        ] = None,
        ctx: Context = CurrentContext(),
    ) -> str:
        """Download/cache and read a NIST publication document or supplemental file."""
        db_path = await index_mgr.ensure_index()
        pub = db.get_by_id(db_path, "publications", publication_id)
        if pub is None:
            return f"Publication '{publication_id}' not found."

        url = pub.get("pdf_url")
        if material_index is not None:
            materials = _supplemental_materials(db_path, publication_id)
            if material_index >= len(materials):
                return f"Invalid material_index {material_index}; found {len(materials)} materials."
            url = materials[material_index].get("url")

        if not url:
            return f"No downloadable URL is available for '{publication_id}'."

        doc_dir = config.data_dir / "docs" / publication_id
        path = doc_dir / safe_filename_from_url(url)

        await ctx.report_progress(progress=0, total=3)
        try:
            await download_file(url, path)
        except Exception as exc:
            raise ToolError(f"Document download failed: {exc}") from exc
        await ctx.report_progress(progress=1, total=3)

        suffix = path.suffix.lower()
        try:
            if suffix == ".pdf" and section:
                await ctx.report_progress(progress=2, total=3)
                md = get_pdf_section(path, section)
            elif suffix == ".pdf" and pages:
                await ctx.report_progress(progress=2, total=3)
                md = convert_to_markdown(path, pages=pages)
            elif suffix == ".pdf":
                await ctx.report_progress(progress=2, total=3)
                md = get_pdf_toc(path)
                md += "\n\n_Use `section` or `pages` to read specific content._"
            else:
                await ctx.report_progress(progress=2, total=3)
                md = convert_to_markdown(path)
        except ValueError as exc:
            raise ToolError(str(exc)) from exc
        finally:
            await ctx.report_progress(progress=3, total=3)

        return f"# {pub.get('title', publication_id)}\n\n{md}"

    @mcp.tool(
        annotations=ToolAnnotations(
            readOnlyHint=True,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def search_nvd(
        kind: Annotated[NvdKind, Field(description="Search CVEs or CPEs")] = "cve",
        keyword: Annotated[str | None, Field(description="Keyword search", max_length=500)] = None,
        severity: Annotated[
            Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] | None,
            Field(description="CVSS v3 severity for CVE searches"),
        ] = None,
        cpe_name: Annotated[
            str | None,
            Field(description="CPE name or match prefix", max_length=500),
        ] = None,
        cwe_id: Annotated[
            str | None,
            Field(description="CWE ID, e.g. CWE-79", pattern=r"^[Cc][Ww][Ee]-\d+$"),
        ] = None,
        has_kev: Annotated[bool, Field(description="Only CVEs in the CISA KEV catalog")] = False,
        limit: Annotated[int, Field(ge=1, le=100)] = 20,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> str:
        """Search live NVD CVE or CPE data."""
        if kind == "cpe":
            if not keyword and not cpe_name:
                raise ToolError("Provide keyword or cpe_name for CPE searches.")
            try:
                data = await nvd_client.search_cpes(
                    keyword=keyword,
                    match_string=cpe_name,
                    results_per_page=limit,
                    start_index=offset,
                )
            except Exception as exc:
                raise ToolError(f"NVD API error: {exc}") from exc
            products = [item.get("cpe", item) for item in data.get("products", [])]
            if not products:
                return "No CPE entries found."
            lines = [f"## CPE Results ({data.get('totalResults', len(products))} total)\n"]
            for item in products:
                title = next(
                    (t.get("title") for t in item.get("titles", []) if t.get("lang") == "en"),
                    item.get("cpeName", "?"),
                )
                lines.append(f"- **{title}**\n  `{item.get('cpeName', '')}`")
            return "\n".join(lines)

        if not any([keyword, severity, cpe_name, cwe_id, has_kev]):
            raise ToolError("Provide at least one CVE filter.")

        try:
            data = await nvd_client.search_cves(
                keyword=keyword,
                severity=severity,
                cpe_name=cpe_name,
                cwe_id=cwe_id,
                results_per_page=limit,
                start_index=offset,
            )
        except Exception as exc:
            raise ToolError(f"NVD API error: {exc}") from exc

        items = [item.get("cve", item) for item in data.get("vulnerabilities", [])]
        kev_ids: set[str] = set()
        if has_kev or items:
            catalog = await kev_client._ensure_catalog()
            kev_ids = {
                vuln["cveID"]
                for vuln in catalog.get("vulnerabilities", [])
                if vuln.get("cveID")
            }
        if has_kev:
            items = [item for item in items if item.get("id") in kev_ids]

        if not items:
            return "No CVEs found."

        lines = [f"## CVE Results ({data.get('totalResults', len(items))} total)\n"]
        for item in items:
            cve_id = item.get("id", "?")
            desc = next(
                (d.get("value", "") for d in item.get("descriptions", []) if d.get("lang") == "en"),
                "",
            )
            if len(desc) > 220:
                desc = desc[:217] + "..."
            kev = " **[KEV]**" if cve_id in kev_ids else ""
            lines.append(f"- **{cve_id}**{kev} - {desc}")
        return "\n".join(lines)

    @mcp.tool(
        annotations=ToolAnnotations(
            readOnlyHint=True,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def get_cve(
        cve_id: Annotated[
            str,
            Field(description="CVE identifier", pattern=r"^[Cc][Vv][Ee]-\d{4}-\d{4,}$"),
        ],
        include_history: Annotated[
            bool,
            Field(description="Include recent NVD change history"),
        ] = False,
    ) -> str:
        """Fetch one CVE with CVSS, weaknesses, references, KEV, and optional history."""
        cve_id = cve_id.strip().upper()
        try:
            data = await nvd_client.get_cve(cve_id)
        except Exception as exc:
            raise ToolError(f"NVD API error: {exc}") from exc

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return f"CVE '{cve_id}' not found."

        item = vulnerabilities[0].get("cve", vulnerabilities[0])
        try:
            kev_entry = await kev_client.get_kev_entry(cve_id)
        except Exception:
            log.warning("KEV lookup failed for %s", cve_id, exc_info=True)
            kev_entry = None

        md = _format_cve(item, kev_entry)
        if include_history:
            try:
                history = await nvd_client.get_cve_history(cve_id)
            except Exception as exc:
                raise ToolError(f"NVD history API error: {exc}") from exc
            changes = history.get("cveChanges", [])[:10]
            if changes:
                md += "\n\n## Recent Change History\n"
                for wrapper in changes:
                    change = wrapper.get("change", wrapper)
                    created = str(change.get("created", ""))[:10]
                    md += f"\n- **{created}:** {change.get('eventName', '')}"
        return md
