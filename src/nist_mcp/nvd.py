"""NVD API client for CVE and CPE lookups."""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

log = logging.getLogger(__name__)


class NVDClient:
    BASE = "https://services.nvd.nist.gov/rest/json"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key
        self._last_request = 0.0
        # Rate limit: 5 req/30s without key (~6s between), 50 req/30s with key (~0.6s between)
        self._min_interval = 0.6 if api_key else 6.0

    async def _get(self, endpoint: str, params: dict) -> dict:
        """Rate-limited GET to NVD API."""
        # Enforce rate limit
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self._min_interval:
            await asyncio.sleep(self._min_interval - elapsed)

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get(
                f"{self.BASE}/{endpoint}",
                params=params,
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
            self._last_request = time.monotonic()
            return resp.json()

    async def search_cves(
        self,
        *,
        keyword: str | None = None,
        severity: str | None = None,
        cpe_name: str | None = None,
        cwe_id: str | None = None,
        pub_start: str | None = None,
        pub_end: str | None = None,
        results_per_page: int = 20,
        start_index: int = 0,
    ) -> dict:
        """Search CVEs with optional filters."""
        params: dict = {"resultsPerPage": results_per_page, "startIndex": start_index}
        if keyword:
            params["keywordSearch"] = keyword
        if severity:
            params["cvssV3Severity"] = severity.upper()
        if cpe_name:
            params["cpeName"] = cpe_name
        if cwe_id:
            params["cweId"] = cwe_id
        if pub_start:
            params["pubStartDate"] = pub_start
        if pub_end:
            params["pubEndDate"] = pub_end
        return await self._get("cves/2.0", params)

    async def get_cve(self, cve_id: str) -> dict:
        """Fetch a single CVE by ID."""
        return await self._get("cves/2.0", {"cveId": cve_id})

    async def search_cpes(
        self,
        *,
        keyword: str | None = None,
        match_string: str | None = None,
        results_per_page: int = 20,
        start_index: int = 0,
    ) -> dict:
        """Search CPE dictionary."""
        params: dict = {"resultsPerPage": results_per_page, "startIndex": start_index}
        if keyword:
            params["keywordSearch"] = keyword
        if match_string:
            params["cpeMatchString"] = match_string
        return await self._get("cpes/2.0", params)

    async def get_cve_history(self, cve_id: str) -> dict:
        """Fetch change history for a CVE."""
        return await self._get("cvehistory/2.0", {"cveId": cve_id})
