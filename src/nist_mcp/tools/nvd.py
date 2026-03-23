"""MCP tools for NVD CVE lookups and vulnerability search."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated

from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from nist_mcp.kev import KEVClient
    from nist_mcp.nvd import NVDClient

log = logging.getLogger(__name__)

_RATE_LIMIT_NOTE = (
    "\n\nNote: NVD API rate limit is 5 requests per 30 seconds without an API key "
    "(~6s between calls). Set NIST_MCP_NVD_API_KEY for 50 req/30s."
)


# ---------------------------------------------------------------------------
# NVD response helpers
# ---------------------------------------------------------------------------


def _get_description(cve_item: dict) -> str:
    """Extract the English description from a CVE item."""
    descriptions = cve_item.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _get_cvss_v3(cve_item: dict) -> dict | None:
    """Return the primary CVSS v3.x metric block (prefers v3.1, falls back to v3.0)."""
    metrics = cve_item.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30"):
        bucket = metrics.get(key, [])
        if bucket:
            # Prefer PRIMARY source; fall back to first entry
            primary = next((m for m in bucket if m.get("type") == "Primary"), bucket[0])
            return primary

    return None


def _get_cvss_v2(cve_item: dict) -> dict | None:
    """Return the primary CVSS v2 metric block if no v3 is available."""
    metrics = cve_item.get("metrics", {})
    bucket = metrics.get("cvssMetricV2", [])
    if bucket:
        primary = next((m for m in bucket if m.get("type") == "Primary"), bucket[0])
        return primary
    return None


def _format_cvss_v3(metric: dict) -> str:
    """Format CVSS v3 as: 'CVSS v3.1: 9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)'."""
    cvss_data = metric.get("cvssData", {})
    version = cvss_data.get("version", "3.x")
    score = cvss_data.get("baseScore", "?")
    severity = cvss_data.get("baseSeverity", "")
    vector = cvss_data.get("vectorString", "")
    return f"CVSS v{version}: {score} {severity} ({vector})"


def _format_cvss_v2(metric: dict) -> str:
    """Format CVSS v2 as: 'CVSS v2.0: 7.5 HIGH (AV:N/AC:L/Au:N/C:P/I:P/A:P)'."""
    cvss_data = metric.get("cvssData", {})
    score = cvss_data.get("baseScore", "?")
    severity = metric.get("baseSeverity", cvss_data.get("baseSeverity", ""))
    vector = cvss_data.get("vectorString", "")
    return f"CVSS v2.0: {score} {severity} ({vector})"


def _get_severity_and_score(cve_item: dict) -> tuple[str, str]:
    """Return (severity_label, score_string) for list view."""
    v3 = _get_cvss_v3(cve_item)
    if v3:
        cvss = v3.get("cvssData", {})
        return cvss.get("baseSeverity", "N/A"), str(cvss.get("baseScore", "N/A"))
    v2 = _get_cvss_v2(cve_item)
    if v2:
        cvss = v2.get("cvssData", {})
        severity = v2.get("baseSeverity", cvss.get("baseSeverity", "N/A"))
        return severity, str(cvss.get("baseScore", "N/A"))
    return "N/A", "N/A"


def _parse_cpe_name(cpe: str) -> str:
    """Convert a CPE 2.3 URI into a human-readable product string.

    cpe:2.3:a:vendor:product:version:... -> 'vendor product version'
    """
    if not cpe.startswith("cpe:2.3:"):
        return cpe
    parts = cpe.split(":")
    # Format: cpe:2.3:<part>:<vendor>:<product>:<version>:...
    # indices:   0    1    2      3       4        5
    if len(parts) < 6:
        return cpe
    part_type = {"a": "Application", "o": "OS", "h": "Hardware"}.get(parts[2], parts[2])
    vendor = parts[3].replace("_", " ").replace("\\", "")
    product = parts[4].replace("_", " ").replace("\\", "")
    version = parts[5] if parts[5] not in ("*", "-", "") else ""
    label = f"{vendor} {product}".strip()
    if version:
        label += f" {version}"
    return f"{label} [{part_type}]"


def _format_cve_summary(cve_item: dict, kev_ids: set[str] | None = None) -> str:
    """Format a CVE for list view: ID, severity, score, KEV flag, short description."""
    cve_id = cve_item.get("id", "?")
    severity, score = _get_severity_and_score(cve_item)
    desc = _get_description(cve_item)
    # Truncate long descriptions for list view
    if len(desc) > 200:
        desc = desc[:197] + "..."

    kev_flag = " **[KEV]**" if (kev_ids and cve_id in kev_ids) else ""
    return f"- **{cve_id}**{kev_flag} [{severity} {score}] {desc}"


def _format_cve_full(cve_item: dict, kev_entry: dict | None) -> str:
    """Format a single CVE with complete detail for get_cve output."""
    lines: list[str] = []
    cve_id = cve_item.get("id", "?")
    published = cve_item.get("published", "")[:10]
    modified = cve_item.get("lastModified", "")[:10]
    status = cve_item.get("vulnStatus", "")

    lines.append(f"# {cve_id}")
    meta_parts = []
    if published:
        meta_parts.append(f"Published: {published}")
    if modified:
        meta_parts.append(f"Modified: {modified}")
    if status:
        meta_parts.append(f"Status: {status}")
    if meta_parts:
        lines.append(" | ".join(meta_parts))
    lines.append("")

    # KEV block (show prominently at the top if in the catalog)
    if kev_entry:
        lines.append("## CISA Known Exploited Vulnerability")
        lines.append(f"- **Vendor/Product:** {kev_entry.get('vendorProject', '')} — {kev_entry.get('product', '')}")
        lines.append(f"- **Date Added:** {kev_entry.get('dateAdded', 'N/A')}")
        lines.append(f"- **Due Date:** {kev_entry.get('dueDate', 'N/A')}")
        lines.append(f"- **Required Action:** {kev_entry.get('requiredAction', 'N/A')}")
        ransomware = kev_entry.get("knownRansomwareCampaignUse", "Unknown")
        lines.append(f"- **Known Ransomware Use:** {ransomware}")
        short_desc = kev_entry.get("shortDescription", "")
        if short_desc:
            lines.append(f"- **CISA Description:** {short_desc}")
        lines.append("")

    # Description
    desc = _get_description(cve_item)
    if desc:
        lines.append("## Description")
        lines.append(desc)
        lines.append("")

    # CVSS scores
    v3 = _get_cvss_v3(cve_item)
    v2 = _get_cvss_v2(cve_item)
    if v3 or v2:
        lines.append("## CVSS Scores")
        if v3:
            lines.append(_format_cvss_v3(v3))
        if v2:
            lines.append(_format_cvss_v2(v2))
        lines.append("")

    # CWE weaknesses
    weaknesses = cve_item.get("weaknesses", [])
    if weaknesses:
        lines.append("## Weaknesses (CWE)")
        for w in weaknesses:
            for desc_item in w.get("description", []):
                if desc_item.get("lang") == "en":
                    lines.append(f"- {desc_item.get('value', '')}")
        lines.append("")

    # Affected products (CPE configurations)
    configs = cve_item.get("configurations", [])
    if configs:
        lines.append("## Affected Products (CPE)")
        seen: set[str] = set()
        for config in configs:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", True):
                        continue
                    cpe_name = match.get("criteria", "")
                    if cpe_name and cpe_name not in seen:
                        seen.add(cpe_name)
                        readable = _parse_cpe_name(cpe_name)
                        version_start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                        version_end = match.get("versionEndIncluding") or match.get("versionEndExcluding")
                        version_range = ""
                        if version_start:
                            prefix = ">=" if "Including" in (match.get("versionStartIncluding") or "") else ">"
                            version_range += f" {prefix}{version_start}"
                        if version_end:
                            suffix = "<=" if match.get("versionEndIncluding") else "<"
                            version_range += f" {suffix}{version_end}"
                        lines.append(f"- {readable}{version_range}")
        if seen:
            lines.append("")

    # References
    references = cve_item.get("references", [])
    if references:
        lines.append("## References")
        for ref in references:
            url = ref.get("url", "")
            source = ref.get("source", "")
            tags = ref.get("tags", [])
            tag_str = f" ({', '.join(tags)})" if tags else ""
            source_str = f" — {source}" if source else ""
            lines.append(f"- {url}{source_str}{tag_str}")

    return "\n".join(lines)


def _format_cpe_entry(cpe_item: dict) -> str:
    """Format a CPE dictionary entry for list view."""
    cpe_name = cpe_item.get("cpeName", "")
    readable = _parse_cpe_name(cpe_name)
    titles = cpe_item.get("titles", [])
    official_title = ""
    for t in titles:
        if t.get("lang") == "en":
            official_title = t.get("title", "")
            break
    deprecated = " _(deprecated)_" if cpe_item.get("deprecated") else ""
    last_mod = cpe_item.get("lastModified", "")[:10]
    line = f"- **{official_title or readable}**{deprecated}"
    if last_mod:
        line += f" (modified {last_mod})"
    line += f"\n  `{cpe_name}`"
    return line


def _format_history_event(change: dict) -> str:
    """Format a single CVE history change event."""
    cve_id = change.get("cveId", "?")
    event_name = change.get("eventName", "")
    created = change.get("created", "")[:10]
    source = change.get("sourceIdentifier", "")

    lines = [f"**{created}** — {event_name}"]
    if source:
        lines.append(f"  Source: {source}")

    details = change.get("details", [])
    for detail in details:
        action = detail.get("action", "")
        dtype = detail.get("type", "")
        old_val = detail.get("oldValue", "")
        new_val = detail.get("newValue", "")
        parts = [f"  - [{dtype}] {action}"]
        if old_val:
            parts.append(f": `{old_val}` → `{new_val}`")
        elif new_val:
            parts.append(f": added `{new_val}`")
        lines.append("".join(parts))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_nvd_tools(
    mcp: "FastMCP",
    nvd_client: "NVDClient",
    kev_client: "KEVClient",
) -> None:
    """Register NVD and KEV tools on *mcp*."""

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
    async def search_cves(
        keyword: Annotated[
            str | None,
            Field(description="Keyword search across CVE descriptions, e.g. 'Apache Log4j'"),
        ] = None,
        severity: Annotated[
            str | None,
            Field(description="CVSS v3 severity: CRITICAL, HIGH, MEDIUM, or LOW"),
        ] = None,
        cpe_name: Annotated[
            str | None,
            Field(description="CPE 2.3 product name, e.g. 'cpe:2.3:a:apache:log4j:*'"),
        ] = None,
        cwe_id: Annotated[
            str | None,
            Field(description="CWE weakness ID, e.g. 'CWE-79'"),
        ] = None,
        pub_start: Annotated[
            str | None,
            Field(description="Publication start date in ISO 8601, e.g. '2024-01-01T00:00:00.000'"),
        ] = None,
        pub_end: Annotated[
            str | None,
            Field(description="Publication end date in ISO 8601, e.g. '2024-12-31T23:59:59.999'"),
        ] = None,
        has_kev: Annotated[
            bool | None,
            Field(description="If True, only return CVEs that are in the CISA KEV catalog"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=2000)] = 20,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> str:
        """Search the NVD CVE database. Supports keyword, CVSS severity, CPE product,
        CWE weakness type, and date range filters. Set has_kev=True for only CISA
        Known Exploited Vulnerabilities. Results include CVE ID, description, severity,
        and score. May take 6+ seconds without an NVD API key due to rate limiting."""
        if not any([keyword, severity, cpe_name, cwe_id, pub_start, pub_end, has_kev]):
            raise ToolError(
                "Please provide at least one search parameter: keyword, severity, "
                "cpe_name, cwe_id, pub_start/pub_end, or has_kev=True."
            )

        try:
            data = await nvd_client.search_cves(
                keyword=keyword,
                severity=severity,
                cpe_name=cpe_name,
                cwe_id=cwe_id,
                pub_start=pub_start,
                pub_end=pub_end,
                results_per_page=limit,
                start_index=offset,
            )
        except Exception as e:
            raise ToolError(f"NVD API error: {e}") from e

        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)

        if not vulnerabilities:
            return f"No CVEs found matching your criteria. (NVD returned 0 results)"

        # Extract CVE items
        cve_items = [v.get("cve", v) for v in vulnerabilities]

        # Build KEV lookup set for this page if filtering or annotating
        kev_ids: set[str] | None = None
        if has_kev is not None or True:
            # Always fetch KEV IDs for annotation (catalog is cached, cheap)
            catalog = await kev_client._ensure_catalog()
            kev_ids = {v.get("cveID") for v in catalog.get("vulnerabilities", [])}

        if has_kev is True and kev_ids is not None:
            cve_items = [item for item in cve_items if item.get("id") in kev_ids]
            if not cve_items:
                return "No CVEs matching your criteria are in the CISA KEV catalog."

        start = offset + 1
        end = offset + len(cve_items)
        page = (offset // limit) + 1
        total_pages = max(1, (total_results + limit - 1) // limit)

        kev_count = sum(1 for item in cve_items if kev_ids and item.get("id") in kev_ids)
        kev_note = f" ({kev_count} in CISA KEV)" if kev_count else ""

        lines = [
            f"**Showing {start}–{end} of {total_results} CVEs (page {page}/{total_pages}){kev_note}**\n"
        ]

        for item in cve_items:
            lines.append(_format_cve_summary(item, kev_ids))

        if end < total_results:
            lines.append(f"\n_Use offset={end} to see the next page._")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
    async def get_cve(
        cve_id: Annotated[
            str,
            Field(description="CVE identifier, e.g. 'CVE-2021-44228'"),
        ],
    ) -> str:
        """Get full details for a CVE: description, CVSS scores, affected products (CPE),
        CWE classification, references, and CISA KEV status (if exploited: date added,
        due date, required action). Use this after search_cves to get complete vulnerability
        details. May take 6+ seconds without an NVD API key due to rate limiting."""
        cve_id = cve_id.strip().upper()
        if not cve_id.startswith("CVE-"):
            raise ToolError(f"Invalid CVE ID format: '{cve_id}'. Expected format: CVE-YYYY-NNNNN")

        try:
            data = await nvd_client.get_cve(cve_id)
        except Exception as e:
            raise ToolError(f"NVD API error: {e}") from e

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return f"CVE **{cve_id}** not found in NVD."

        cve_item = vulnerabilities[0].get("cve", vulnerabilities[0])

        # Check KEV
        try:
            kev_entry = await kev_client.get_kev_entry(cve_id)
        except Exception:
            log.warning("KEV lookup failed for %s", cve_id, exc_info=True)
            kev_entry = None

        return _format_cve_full(cve_item, kev_entry)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
    async def search_cpes(
        keyword: Annotated[
            str | None,
            Field(description="Keyword search, e.g. 'Apache Tomcat', 'Windows Server 2022'"),
        ] = None,
        match_string: Annotated[
            str | None,
            Field(description="CPE match string prefix, e.g. 'cpe:2.3:a:apache:tomcat'"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=2000)] = 20,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> str:
        """Search the NVD CPE (Common Platform Enumeration) database for products
        and platforms. May take 6+ seconds without an NVD API key due to rate limiting."""
        if not keyword and not match_string:
            raise ToolError("Please provide either 'keyword' or 'match_string' to search CPEs.")

        try:
            data = await nvd_client.search_cpes(
                keyword=keyword,
                match_string=match_string,
                results_per_page=limit,
                start_index=offset,
            )
        except Exception as e:
            raise ToolError(f"NVD API error: {e}") from e

        products = data.get("products", [])
        total_results = data.get("totalResults", 0)

        if not products:
            return f"No CPE entries found matching your criteria. (NVD total: {total_results})"

        cpe_items = [p.get("cpe", p) for p in products]

        start = offset + 1
        end = offset + len(cpe_items)
        page = (offset // limit) + 1
        total_pages = max(1, (total_results + limit - 1) // limit)

        lines = [
            f"**Showing {start}–{end} of {total_results} CPE entries (page {page}/{total_pages})**\n"
        ]

        for item in cpe_items:
            lines.append(_format_cpe_entry(item))

        if end < total_results:
            lines.append(f"\n_Use offset={end} to see the next page._")

        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
    async def get_cve_history(
        cve_id: Annotated[
            str,
            Field(description="CVE identifier, e.g. 'CVE-2021-44228'"),
        ],
    ) -> str:
        """Get the change history for a CVE — when it was modified, what changed
        (score updates, CPE additions, CWE remaps). May take 6+ seconds without
        an NVD API key due to rate limiting."""
        cve_id = cve_id.strip().upper()
        if not cve_id.startswith("CVE-"):
            raise ToolError(f"Invalid CVE ID format: '{cve_id}'. Expected format: CVE-YYYY-NNNNN")

        try:
            data = await nvd_client.get_cve_history(cve_id)
        except Exception as e:
            raise ToolError(f"NVD API error: {e}") from e

        changes = data.get("cveChanges", [])
        total_results = data.get("totalResults", 0)

        if not changes:
            return f"No change history found for **{cve_id}**."

        # Limit to most recent 20 events to avoid massive output
        max_events = 20
        shown = changes[:max_events]

        lines = [f"# Change History for {cve_id} ({total_results} events)\n"]

        if total_results > max_events:
            lines.append(
                f"_Showing most recent {max_events} of {total_results} events._\n"
            )

        for change_wrapper in shown:
            change = change_wrapper.get("change", change_wrapper)
            lines.append(_format_history_event(change))
            lines.append("")

        return "\n".join(lines)
