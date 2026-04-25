# nist-mcp

A small Model Context Protocol (MCP) server that gives AI assistants structured access to the NIST cybersecurity catalog: publications, SP 800-53 Rev 5 controls, CSF 2.0, CMVP modules, NCP checklists, glossary terms, NICE work roles, and live NVD CVE/CPE data. Local NIST data is served from a SQLite index that builds automatically on first use by downloading structured data directly from NIST.

## Installation

Install directly from GitHub:

```bash
pipx install git+https://github.com/ball2jh/nist-mcp.git
# or
pip install git+https://github.com/ball2jh/nist-mcp.git
```

For local development:

```bash
git clone https://github.com/ball2jh/nist-mcp.git
cd nist-mcp
pip install -e ".[dev,scraper]"
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NIST_MCP_DATA_DIR` | `~/.nist-mcp` | Directory for the local database and cached documents |
| `NIST_MCP_NVD_API_KEY` | _(none)_ | Optional NVD API key for higher rate limits (recommended) |
| `NIST_MCP_UPDATE_INTERVAL` | `604800` | Seconds between background database rebuilds (default: 7 days) |

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

On first run, the server builds a local database by downloading structured data from NIST (~2 seconds). The database is cached and rebuilt automatically when stale (default: every 7 days).

## MCP Safety Notes

This server is intended to run as a local stdio MCP server. It does not expose an HTTP listener, so access is limited to the MCP client process that launches it. Logs are written through Python logging, which writes to stderr by default and does not corrupt stdio JSON-RPC traffic.

Tool schemas constrain common option sets and result sizes. Document downloads are limited to HTTPS URLs from known NIST publication hosts, redirects are revalidated, filenames are sanitized before writing to the local cache, and page extraction is capped at 50 pages per request. Tools that download, cache, or rebuild local data are annotated as non-destructive but not purely read-only so clients can present appropriate confirmation UI.

## Available Tools

| Tool | Description |
|---|---|
| `search_nist` | Search local NIST catalog data across publications, controls, CSF, glossary, CMVP, checklists, and NICE |
| `get_nist_record` | Fetch a single local NIST record by source and ID |
| `read_publication` | Download/cache and read publication content as Markdown; returns a PDF TOC by default |
| `search_nvd` | Search live NVD CVE or CPE data |
| `get_cve` | Fetch one CVE with CVSS, weaknesses, references, KEV status, and optional change history |
| `database_status` | Show database build date, size, freshness, and file path |
| `update_database` | Rebuild the local NIST index by downloading fresh data from NIST sources |

## Available Resources

| URI | Description |
|---|---|
| `nist://about` | Server version, database freshness, and quick-start tool guide |

## Quick Examples

### Find NIST guidance on zero trust

```
search_nist("zero trust architecture")
```

### Look up the SP 800-207 publication

```
search_nist("zero trust", source="publications")
get_nist_record(source="publications", record_id="SP.800-207")
```

### Review access control requirements for a MODERATE system

```
search_nist("account management", source="controls", detail="standard")
get_nist_record(source="controls", record_id="AC-2")
```

### Analyze Log4Shell

```
get_cve("CVE-2021-44228")
```

### Check if your cryptographic library is FIPS validated

```
search_nist("OpenSSL", source="cmvp")
```

### Find CSF guidance on incident response

```
search_nist("incident response", source="csf")
```

## License

MIT license. Note that `pymupdf4llm`, used for PDF-to-Markdown conversion, is licensed under AGPL-3.0.
