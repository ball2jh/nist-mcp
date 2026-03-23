# nist-mcp

A Model Context Protocol (MCP) server that gives AI assistants structured access to the full NIST cybersecurity catalog: SP 800 and SP 1800 publications, SP 800-53 Rev 5 security controls, NIST CSF 2.0, the NVD vulnerability database (CVEs and CPEs), FIPS 140-2/3 validated cryptographic modules (CMVP), NCP security checklists, the NIST glossary, and NICE Framework work roles — all served from a local SQLite index that auto-updates from pre-built GitHub Releases.

## Installation

```bash
pipx install nist-mcp
# or
pip install nist-mcp
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NIST_MCP_DATA_DIR` | `~/.nist-mcp` | Directory for the local database and cached documents |
| `NIST_MCP_NVD_API_KEY` | _(none)_ | Optional NVD API key for higher rate limits (recommended) |
| `NIST_MCP_UPDATE_INTERVAL` | `86400` | Seconds between background database update checks (default: 24 h) |
| `NIST_MCP_GITHUB_REPO` | `jacka/nist-mcp` | GitHub repo to pull pre-built database releases from |

### config.toml

Create `~/.nist-mcp/config.toml` (or `$NIST_MCP_DATA_DIR/config.toml`) for persistent settings:

```toml
nvd_api_key = "your-api-key-here"
update_interval = 43200   # 12 hours
```

Environment variables take precedence over the config file.

### MCP Client Config

Add to your MCP client's server list (e.g. Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "nist": {
      "command": "nist-mcp",
      "env": {
        "NIST_MCP_NVD_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

The first run downloads the pre-built database (~50 MB) from GitHub Releases automatically.

## Available Tools

| Tool | Description |
|---|---|
| `search_nist` | Meta-search across all 7 NIST data sources at once — use as starting point |
| `update_database` | Force-refresh the local NIST index from the latest GitHub Release |
| `database_status` | Show database version, size, last update check, and file path |
| `search_publications` | Full-text search across all NIST publication series (SP 800, SP 1800, FIPS, IR, CSWP, AI) |
| `get_publication` | Full metadata for a specific publication: abstract, authors, supplemental materials |
| `get_document_content` | Read publication content as Markdown (PDF, XLSX, CSV, JSON, XML); returns TOC by default |
| `download_document` | Download a publication PDF or supplemental file to local cache |
| `get_latest_revision` | Resolve any publication ID to its newest available revision |
| `search_controls` | Search SP 800-53 Rev 5 controls by keyword, control family, or baseline level |
| `get_control` | Full detail for a specific control: statement, guidance, parameters, baselines, CSF mappings |
| `get_csf_data` | Browse/search the NIST CSF 2.0 hierarchy (functions, categories, subcategories) |
| `get_framework_mappings` | Cross-reference between SP 800-53 controls and CSF subcategories, bidirectionally |
| `lookup_glossary` | Look up NIST cybersecurity/privacy term definitions with authoritative source |
| `search_cmvp` | Search FIPS 140-2/3 validated cryptographic modules by vendor, algorithm, or validation level |
| `search_checklists` | Search NCP security configuration checklists by product, format, or authority |
| `search_nice_roles` | Search NICE Framework work roles by keyword or category |
| `search_cves` | Search the NVD CVE database by keyword, severity, CPE product, CWE, date range, or KEV status |
| `get_cve` | Full CVE details: CVSS scores, affected products, CWE, references, and CISA KEV status |
| `search_cpes` | Search the NVD CPE product dictionary by keyword or CPE name prefix |
| `get_cve_history` | Audit trail of changes to a CVE (score updates, CPE additions, CWE remaps) |

## Available Resources

| URI | Description |
|---|---|
| `nist://about` | Server version, database freshness, and quick-start tool guide |
| `nist://controls/families` | All 20 SP 800-53 Rev 5 control families with one-line descriptions |
| `nist://controls/baselines` | LOW, MODERATE, HIGH, and PRIVACY baselines with control counts and descriptions |
| `nist://csf/overview` | CSF 2.0 structure: the 6 core Functions with descriptions |
| `nist://glossary/common` | ~30 most commonly referenced NIST cybersecurity terms and definitions |

## Available Prompts

| Prompt | Parameters | Description |
|---|---|---|
| `compliance_assessment` | `system_description`, `baseline` (default: MODERATE) | Step-by-step workflow to assess a system against an SP 800-53 baseline |
| `vulnerability_analysis` | `cve_id`, `system_description` (optional) | Analyze a CVE's impact, affected components, and applicable NIST controls |
| `policy_draft` | `control_family` | Draft a security policy document grounded in SP 800-53 Rev 5 |
| `incident_response_guide` | `incident_type` | NIST-based guidance for detecting, containing, and recovering from a security incident |

## Quick Examples

### Find NIST guidance on zero trust

```
search_nist("zero trust architecture")
```

### Look up the SP 800-207 publication

```
search_publications("zero trust")
get_publication("SP.800-207")
```

### Review access control requirements for a MODERATE system

```
search_controls(family="ac", baseline="MODERATE", detail_level="standard")
get_control("AC-2", include_enhancements=True)
```

### Analyze Log4Shell

```
get_cve("CVE-2021-44228")
```

### Check if your cryptographic library is FIPS validated

```
search_cmvp(vendor="OpenSSL", fips_level=1)
```

### Find CSF guidance on incident response

```
get_csf_data(function="RS")
get_csf_data(function="RC")
```

### Use a workflow prompt

```
compliance_assessment(
    system_description="Web application processing PII, hosted on AWS, with MFA for admin access",
    baseline="MODERATE"
)
```

## License

MIT license. Note that the optional `pymupdf4llm` dependency (used for PDF-to-Markdown conversion) is licensed under AGPL-3.0. If AGPL is not acceptable for your use case, the server functions fully without it for all non-document-content tools; remove `pymupdf4llm` from your installation and `get_document_content` will fall back to pdfplumber for PDF parsing.
