"""CISA Known Exploited Vulnerabilities (KEV) catalog client."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import httpx

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_TTL = 86400  # 24 hours


class KEVClient:
    def __init__(self, cache_dir: Path):
        self._cache_path = cache_dir / "kev_catalog.json"
        self._catalog: dict | None = None
        self._last_load = 0.0

    async def get_kev_entry(self, cve_id: str) -> dict | None:
        """Look up a CVE in the KEV catalog. Returns the entry dict or None."""
        catalog = await self._ensure_catalog()
        for vuln in catalog.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id:
                return vuln
        return None

    async def _ensure_catalog(self) -> dict:
        """Return a cached or freshly downloaded KEV catalog."""
        # In-memory cache still valid
        if self._catalog and (time.monotonic() - self._last_load) < KEV_CACHE_TTL:
            return self._catalog

        # Try the on-disk cache
        if self._cache_path.exists():
            age = time.time() - self._cache_path.stat().st_mtime
            if age < KEV_CACHE_TTL:
                self._catalog = json.loads(self._cache_path.read_text())
                self._last_load = time.monotonic()
                return self._catalog

        # Download a fresh copy
        try:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                resp = await client.get(KEV_URL, timeout=30)
                resp.raise_for_status()
                self._catalog = resp.json()
                self._cache_path.parent.mkdir(parents=True, exist_ok=True)
                self._cache_path.write_text(resp.text)
                self._last_load = time.monotonic()
                return self._catalog
        except Exception:
            log.warning("Failed to download KEV catalog", exc_info=True)
            # Fall back to stale on-disk cache if available
            if self._cache_path.exists():
                self._catalog = json.loads(self._cache_path.read_text())
                self._last_load = time.monotonic()
                return self._catalog
            return {"vulnerabilities": []}
