"""Full-text search index management using SQLite FTS5.

Manages the lifecycle of the pre-built SQLite database: downloading from
GitHub Releases, checking for staleness, and atomic replacement.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path

import httpx

from nist_mcp.config import Config

log = logging.getLogger(__name__)

_DB_FILENAME = "nist_mcp.db"
_META_FILENAME = "index_meta.json"


class IndexManager:
    """Manages the local SQLite index downloaded from GitHub Releases."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._db_path = config.data_dir / _DB_FILENAME
        self._meta_path = config.data_dir / _META_FILENAME
        self._update_task: asyncio.Task | None = None

    # -- Public API ------------------------------------------------------------

    @property
    def db_path(self) -> Path:
        return self._db_path

    async def ensure_index(self) -> Path:
        """Ensure a usable database exists, downloading if needed.

        * First run (no local DB): performs a **blocking** download.
        * Subsequent runs: if stale, kicks off a background update and
          returns the existing (slightly outdated) database immediately.
        """
        if not self._db_path.exists():
            log.info("No local database found — downloading from GitHub Releases.")
            await self._download_latest()
            return self._db_path

        if self._is_stale():
            log.info("Database index is stale — scheduling background update.")
            self._schedule_background_update()

        return self._db_path

    async def force_update(self) -> str:
        """Download the latest release and return the version tag."""
        await self._download_latest()
        meta = self._read_meta()
        return meta.get("current_tag", "unknown")

    def status(self) -> dict:
        """Return a status dict for the ``database_status`` tool."""
        exists = self._db_path.exists()
        meta = self._read_meta()

        last_check_ts = meta.get("last_check")
        if last_check_ts is not None:
            last_check_human = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC", time.gmtime(last_check_ts)
            )
        else:
            last_check_human = None

        return {
            "exists": exists,
            "current_tag": meta.get("current_tag"),
            "last_check": last_check_human,
            "db_size_bytes": self._db_path.stat().st_size if exists else None,
            "path": str(self._db_path),
        }

    # -- Internal --------------------------------------------------------------

    def _is_stale(self) -> bool:
        meta = self._read_meta()
        last_check = meta.get("last_check")
        if last_check is None:
            return True
        return (time.time() - last_check) > self._config.update_interval

    def _schedule_background_update(self) -> None:
        """Launch a background task if one is not already running."""
        if self._update_task is not None and not self._update_task.done():
            return
        self._update_task = asyncio.create_task(self._check_and_update())

    async def _check_and_update(self) -> None:
        """Check the latest release tag; download only if it differs."""
        try:
            tag = await self._fetch_latest_tag()
            meta = self._read_meta()
            if tag and tag != meta.get("current_tag"):
                log.info("New release %s available — downloading.", tag)
                await self._download_release(tag)
            else:
                # Update last_check even when tag hasn't changed.
                self._write_meta(meta.get("current_tag", ""), time.time())
        except Exception:
            log.warning("Background index update failed.", exc_info=True)

    async def _download_latest(self) -> None:
        """Download the latest release (blocking the caller)."""
        try:
            tag = await self._fetch_latest_tag()
            if tag is None:
                raise RuntimeError("Could not determine latest release tag.")
            await self._download_release(tag)
        except Exception:
            if self._db_path.exists():
                log.warning(
                    "Download failed but a local database exists — using it.",
                    exc_info=True,
                )
            else:
                raise

    async def _fetch_latest_tag(self) -> str | None:
        """Query GitHub Releases API for the latest tag name."""
        url = (
            f"https://api.github.com/repos/"
            f"{self._config.github_repo}/releases/latest"
        )
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get(url, timeout=30)
            resp.raise_for_status()
            return resp.json().get("tag_name")

    async def _download_release(self, tag: str) -> None:
        """Download the ``nist_mcp.db`` asset from a given release tag."""
        url = (
            f"https://api.github.com/repos/"
            f"{self._config.github_repo}/releases/tags/{tag}"
        )
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get(url, timeout=30)
            resp.raise_for_status()
            release = resp.json()

            asset_url: str | None = None
            for asset in release.get("assets", []):
                if asset["name"] == _DB_FILENAME:
                    asset_url = asset["browser_download_url"]
                    break

            if asset_url is None:
                raise RuntimeError(
                    f"Release {tag} has no '{_DB_FILENAME}' asset."
                )

            log.info("Downloading %s from release %s …", _DB_FILENAME, tag)
            asset_resp = await client.get(asset_url, timeout=300)
            asset_resp.raise_for_status()

        # Atomic replacement: write to tmp, then rename.
        tmp_path = self._db_path.with_suffix(".tmp")
        tmp_path.write_bytes(asset_resp.content)
        tmp_path.rename(self._db_path)

        self._write_meta(tag, time.time())
        log.info("Index updated to %s.", tag)

    # -- Meta file helpers -----------------------------------------------------

    def _read_meta(self) -> dict:
        if not self._meta_path.exists():
            return {}
        try:
            return json.loads(self._meta_path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def _write_meta(self, tag: str, timestamp: float) -> None:
        payload = {"current_tag": tag, "last_check": timestamp}
        self._meta_path.write_text(json.dumps(payload))
