"""Scraper for NIST National Checklist Program (NCP) data.

The NCP repository at ncp.nist.gov is JS-rendered and not directly scrapeable
with simple HTTP requests.  This module provides a curated dataset of popular
security checklists/benchmarks from the NCP repository as a starting point.

TODO: Replace with live scraping or NCP API integration when a machine-readable
endpoint becomes available.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS checklists (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    product         TEXT,
    version         TEXT,
    authority       TEXT,
    target_audience TEXT,
    format          TEXT,
    download_url    TEXT,
    description     TEXT
);
CREATE INDEX IF NOT EXISTS idx_chklist_product ON checklists(product);
CREATE INDEX IF NOT EXISTS idx_chklist_authority ON checklists(authority);
"""

# ---------------------------------------------------------------------------
# Curated NCP checklists
#
# This dataset covers the most commonly referenced security checklists from
# the NIST National Checklist Program.  IDs use a "NCP-" prefix followed by
# the NCP checklist number where known, or a descriptive slug otherwise.
#
# TODO: Replace with live scraping when the NCP site exposes a stable
# machine-readable download or API.
# ---------------------------------------------------------------------------

_CURATED_CHECKLISTS: list[dict[str, Any]] = [
    {
        "id": "NCP-RHEL9-STIG",
        "name": "Red Hat Enterprise Linux 9 STIG",
        "product": "Red Hat Enterprise Linux 9",
        "version": "V1R1",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for RHEL 9 systems in DoD environments.",
    },
    {
        "id": "NCP-RHEL8-STIG",
        "name": "Red Hat Enterprise Linux 8 STIG",
        "product": "Red Hat Enterprise Linux 8",
        "version": "V1R13",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for RHEL 8 systems in DoD environments.",
    },
    {
        "id": "NCP-UBUNTU2204-STIG",
        "name": "Canonical Ubuntu 22.04 LTS STIG",
        "product": "Ubuntu 22.04 LTS",
        "version": "V1R1",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Ubuntu 22.04 LTS.",
    },
    {
        "id": "NCP-UBUNTU2004-STIG",
        "name": "Canonical Ubuntu 20.04 LTS STIG",
        "product": "Ubuntu 20.04 LTS",
        "version": "V1R12",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Ubuntu 20.04 LTS.",
    },
    {
        "id": "NCP-WIN2022-STIG",
        "name": "Windows Server 2022 STIG",
        "product": "Microsoft Windows Server 2022",
        "version": "V1R4",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Windows Server 2022.",
    },
    {
        "id": "NCP-WIN2019-STIG",
        "name": "Windows Server 2019 STIG",
        "product": "Microsoft Windows Server 2019",
        "version": "V2R8",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Windows Server 2019.",
    },
    {
        "id": "NCP-WIN11-STIG",
        "name": "Windows 11 STIG",
        "product": "Microsoft Windows 11",
        "version": "V1R5",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Windows 11.",
    },
    {
        "id": "NCP-WIN10-STIG",
        "name": "Windows 10 STIG",
        "product": "Microsoft Windows 10",
        "version": "V2R8",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Windows 10.",
    },
    {
        "id": "NCP-SLES15-STIG",
        "name": "SUSE Linux Enterprise Server 15 STIG",
        "product": "SUSE Linux Enterprise Server 15",
        "version": "V1R12",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for SLES 15.",
    },
    {
        "id": "NCP-OEL8-STIG",
        "name": "Oracle Linux 8 STIG",
        "product": "Oracle Linux 8",
        "version": "V1R8",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Oracle Linux 8.",
    },
    {
        "id": "NCP-VMWARE-VSPHERE8-STIG",
        "name": "VMware vSphere 8.0 STIG",
        "product": "VMware vSphere 8.0",
        "version": "V1R1",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for VMware vSphere 8.0 ESXi hosts.",
    },
    {
        "id": "NCP-DOCKER-STIG",
        "name": "Docker Enterprise STIG",
        "product": "Docker Enterprise",
        "version": "V2R2",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Docker Enterprise.",
    },
    {
        "id": "NCP-K8S-STIG",
        "name": "Kubernetes STIG",
        "product": "Kubernetes",
        "version": "V1R9",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Kubernetes container orchestration.",
    },
    {
        "id": "NCP-APACHE-STIG",
        "name": "Apache HTTP Server 2.4 STIG",
        "product": "Apache HTTP Server 2.4",
        "version": "V2R6",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Apache HTTP Server 2.4.",
    },
    {
        "id": "NCP-NGINX-STIG",
        "name": "NGINX Web Server STIG",
        "product": "NGINX",
        "version": "V2R2",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for NGINX web server.",
    },
    {
        "id": "NCP-IIS10-STIG",
        "name": "Microsoft IIS 10.0 STIG",
        "product": "Microsoft IIS 10.0",
        "version": "V2R10",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Internet Information Services 10.0.",
    },
    {
        "id": "NCP-MSSQL2019-STIG",
        "name": "Microsoft SQL Server 2019 STIG",
        "product": "Microsoft SQL Server 2019",
        "version": "V1R4",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for SQL Server 2019.",
    },
    {
        "id": "NCP-POSTGRES14-STIG",
        "name": "PostgreSQL 14 STIG",
        "product": "PostgreSQL 14",
        "version": "V1R1",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for PostgreSQL 14.",
    },
    {
        "id": "NCP-ORACLE19-STIG",
        "name": "Oracle Database 19c STIG",
        "product": "Oracle Database 19c",
        "version": "V2R4",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Oracle Database 19c.",
    },
    {
        "id": "NCP-CISCO-IOS-STIG",
        "name": "Cisco IOS XE Router STIG",
        "product": "Cisco IOS XE",
        "version": "V3R2",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Cisco IOS XE routers.",
    },
    {
        "id": "NCP-PANOS-STIG",
        "name": "Palo Alto Networks PAN-OS STIG",
        "product": "Palo Alto PAN-OS",
        "version": "V3R1",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Palo Alto PAN-OS firewalls.",
    },
    {
        "id": "NCP-JUNOS-STIG",
        "name": "Juniper JunOS Router STIG",
        "product": "Juniper JunOS",
        "version": "V2R4",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Juniper JunOS routers.",
    },
    {
        "id": "NCP-M365-STIG",
        "name": "Microsoft 365 STIG",
        "product": "Microsoft 365",
        "version": "V2R10",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Microsoft 365 (Office) applications.",
    },
    {
        "id": "NCP-CHROME-STIG",
        "name": "Google Chrome STIG",
        "product": "Google Chrome",
        "version": "V2R9",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Google Chrome browser.",
    },
    {
        "id": "NCP-EDGE-STIG",
        "name": "Microsoft Edge STIG",
        "product": "Microsoft Edge",
        "version": "V1R5",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Microsoft Edge (Chromium-based) browser.",
    },
    {
        "id": "NCP-FIREFOX-STIG",
        "name": "Mozilla Firefox STIG",
        "product": "Mozilla Firefox",
        "version": "V6R5",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Mozilla Firefox browser.",
    },
    {
        "id": "NCP-MACOS14-STIG",
        "name": "Apple macOS 14 (Sonoma) STIG",
        "product": "Apple macOS 14 Sonoma",
        "version": "V1R2",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for macOS 14 Sonoma.",
    },
    {
        "id": "NCP-ANDROID14-STIG",
        "name": "Google Android 14 STIG",
        "product": "Android 14",
        "version": "V1R1",
        "authority": "DISA",
        "target_audience": "Federal / DoD",
        "format": "XCCDF",
        "download_url": "https://ncp.nist.gov/repository",
        "description": "Security Technical Implementation Guide for Android 14 devices.",
    },
    {
        "id": "NCP-AWS-CIS",
        "name": "CIS Amazon Web Services Foundations Benchmark",
        "product": "Amazon Web Services",
        "version": "v3.0.0",
        "authority": "CIS",
        "target_audience": "Cloud / Enterprise",
        "format": "PDF/XCCDF",
        "download_url": "https://www.cisecurity.org/benchmark/amazon_web_services",
        "description": "CIS Benchmark for securing AWS accounts following security best practices.",
    },
    {
        "id": "NCP-AZURE-CIS",
        "name": "CIS Microsoft Azure Foundations Benchmark",
        "product": "Microsoft Azure",
        "version": "v3.0.0",
        "authority": "CIS",
        "target_audience": "Cloud / Enterprise",
        "format": "PDF/XCCDF",
        "download_url": "https://www.cisecurity.org/benchmark/azure",
        "description": "CIS Benchmark for securing Azure subscriptions and resources.",
    },
    {
        "id": "NCP-GCP-CIS",
        "name": "CIS Google Cloud Platform Benchmark",
        "product": "Google Cloud Platform",
        "version": "v3.0.0",
        "authority": "CIS",
        "target_audience": "Cloud / Enterprise",
        "format": "PDF/XCCDF",
        "download_url": "https://www.cisecurity.org/benchmark/google_cloud_computing_platform",
        "description": "CIS Benchmark for securing Google Cloud Platform projects and resources.",
    },
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scrape_checklists(db: sqlite3.Connection) -> int:
    """Populate the ``checklists`` table with NCP checklist data.

    Uses curated reference data since the NCP site is JS-rendered.
    Returns the number of rows inserted.
    """
    rows = _CURATED_CHECKLISTS

    db.execute("DELETE FROM checklists")
    db.executemany(
        """
        INSERT INTO checklists (
            id, name, product, version, authority,
            target_audience, format, download_url, description
        ) VALUES (
            :id, :name, :product, :version, :authority,
            :target_audience, :format, :download_url, :description
        )
        """,
        rows,
    )
    db.commit()
    log.info("Inserted %d NCP checklists", len(rows))
    return len(rows)


# ---------------------------------------------------------------------------
# Standalone test harness
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    conn = sqlite3.connect(":memory:")
    conn.executescript(CREATE_TABLE_SQL)
    n = scrape_checklists(conn)
    print(f"Inserted {n} checklists")

    cur = conn.execute(
        "SELECT authority, COUNT(*) FROM checklists GROUP BY authority"
    )
    for row in cur:
        print(f"  {row[0]}: {row[1]}")

    cur = conn.execute("SELECT id, name FROM checklists LIMIT 10")
    for row in cur:
        print(f"  {row[0]}: {row[1]}")
    conn.close()
