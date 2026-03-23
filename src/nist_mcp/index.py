"""NIST metadata index lifecycle management.

Builds the SQLite database locally by downloading structured data from
NIST (XLSX, JSON, ZIP) and assembling it into a searchable index.  The
database is cached on disk and rebuilt when stale.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from nist_mcp.config import Config

log = logging.getLogger(__name__)

_DB_FILENAME = "nist_mcp.db"
_META_FILENAME = "index_meta.json"
_SCHEMA_VERSION = "1"

# Default staleness: 7 days
_DEFAULT_STALENESS = 7 * 86400


class IndexManager:
    """Manages the local SQLite index — builds it from NIST sources."""

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
        """Ensure a usable database exists, building if needed.

        * First run (no local DB): performs a **blocking** build (~5-10s).
        * Subsequent runs: if stale, kicks off a background rebuild and
          returns the existing database immediately.
        """
        if not self._db_path.exists():
            log.info("No local database found — building from NIST sources.")
            await self._build()
            return self._db_path

        if self._is_stale():
            log.info("Database index is stale — scheduling background rebuild.")
            self._schedule_background_rebuild()

        return self._db_path

    async def force_update(self) -> str:
        """Rebuild the database from scratch. Returns a status message."""
        await self._build()
        meta = self._read_meta()
        return meta.get("built_at", "unknown")

    def status(self) -> dict:
        """Return a status dict for the ``database_status`` tool."""
        exists = self._db_path.exists()
        meta = self._read_meta()

        built_at = meta.get("built_at")
        last_check_ts = meta.get("last_check")
        if last_check_ts is not None:
            last_check_human = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC", time.gmtime(last_check_ts)
            )
        else:
            last_check_human = None

        return {
            "exists": exists,
            "built_at": built_at,
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

    def _schedule_background_rebuild(self) -> None:
        """Launch a background rebuild if one is not already running."""
        if self._update_task is not None and not self._update_task.done():
            return
        self._update_task = asyncio.create_task(self._background_rebuild())

    async def _background_rebuild(self) -> None:
        """Rebuild in the background, swallowing errors."""
        try:
            await self._build()
        except Exception:
            log.warning("Background index rebuild failed.", exc_info=True)

    async def _build(self) -> None:
        """Build the SQLite database from NIST sources.

        Downloads structured data (XLSX, JSON, ZIP) and assembles the
        index.  Runs synchronous scraper code in a thread pool to avoid
        blocking the event loop.
        """
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._build_sync)

    def _build_sync(self) -> None:
        """Synchronous database build — called from a thread."""
        from scraper.controls import CREATE_TABLE_SQL as CONTROLS_SQL, scrape_controls
        from scraper.csf import CREATE_TABLE_SQL as CSF_SQL, scrape_csf
        from scraper.glossary import CREATE_TABLE_SQL as GLOSSARY_SQL, scrape_glossary
        from scraper.nice import CREATE_TABLE_SQL as NICE_SQL, scrape_nice
        from scraper.synonyms import CREATE_TABLE_SQL as SYNONYMS_SQL, build_synonyms
        from scraper.mappings import CREATE_TABLE_SQL as MAPPINGS_SQL, scrape_mappings
        from scraper.publications import CREATE_TABLE_SQL as PUBS_SQL, scrape_publications
        from scraper.cmvp import CREATE_TABLE_SQL as CMVP_SQL, scrape_cmvp
        from scraper.checklists import CREATE_TABLE_SQL as CHECKLISTS_SQL, scrape_checklists

        output_dir = str(self._config.data_dir)
        os.makedirs(output_dir, exist_ok=True)

        fd, tmp_path = tempfile.mkstemp(
            suffix=".db", prefix=".nist_mcp_build_", dir=output_dir
        )
        os.close(fd)

        _FTS_SQL = """
        CREATE VIRTUAL TABLE IF NOT EXISTS controls_fts USING fts5(
            id, title, statement, guidance, content='controls', content_rowid='rowid');
        CREATE VIRTUAL TABLE IF NOT EXISTS publications_fts USING fts5(
            id, title, abstract, authors, topics, content='publications', content_rowid='rowid');
        CREATE VIRTUAL TABLE IF NOT EXISTS glossary_fts USING fts5(
            term, definition, content='glossary', content_rowid='rowid');
        CREATE VIRTUAL TABLE IF NOT EXISTS csf_fts USING fts5(
            id, title, content='csf', content_rowid='rowid');
        CREATE VIRTUAL TABLE IF NOT EXISTS cmvp_fts USING fts5(
            cert_number, vendor, module_name, description, algorithms,
            content='cmvp', content_rowid='rowid');
        CREATE VIRTUAL TABLE IF NOT EXISTS checklists_fts USING fts5(
            id, name, product, description, content='checklists', content_rowid='rowid');
        CREATE VIRTUAL TABLE IF NOT EXISTS nice_roles_fts USING fts5(
            id, name, category, description, content='nice_roles', content_rowid='rowid');
        """

        _META_SQL = "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"

        log.info("Building NIST database from sources ...")

        try:
            conn = sqlite3.connect(tmp_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")

            # Create tables
            for name, sql in [
                ("controls", CONTROLS_SQL), ("csf", CSF_SQL),
                ("glossary", GLOSSARY_SQL), ("nice_roles", NICE_SQL),
                ("synonyms", SYNONYMS_SQL), ("mappings", MAPPINGS_SQL),
                ("publications", PUBS_SQL), ("cmvp", CMVP_SQL),
                ("checklists", CHECKLISTS_SQL), ("meta", _META_SQL),
            ]:
                conn.executescript(sql)

            conn.executescript(_FTS_SQL)

            # Run scrapers
            results: dict[str, int] = {}
            scrapers = [
                ("controls", lambda: scrape_controls(conn)),
                ("csf", lambda: scrape_csf(conn)),
                ("glossary", lambda: scrape_glossary(conn)),
                ("nice_roles", lambda: scrape_nice(conn)),
                ("synonyms", lambda: build_synonyms(conn)),
                ("mappings", lambda: scrape_mappings(conn)),
                ("publications", lambda: scrape_publications(conn, quick=True)),
                ("cmvp", lambda: scrape_cmvp(conn)),
                ("checklists", lambda: scrape_checklists(conn)),
            ]

            for name, scraper_fn in scrapers:
                log.info("  Building: %s ...", name)
                try:
                    results[name] = scraper_fn()
                except Exception:
                    log.exception("  FAILED: %s", name)
                    results[name] = 0

            # Rebuild FTS
            for fts in ["controls_fts", "publications_fts", "glossary_fts",
                        "csf_fts", "cmvp_fts", "checklists_fts", "nice_roles_fts"]:
                try:
                    conn.execute(f"INSERT INTO {fts}({fts}) VALUES('rebuild')")
                except Exception:
                    log.exception("  FTS rebuild failed: %s", fts)

            # Meta
            now = datetime.now(timezone.utc).isoformat()
            conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                         ("schema_version", _SCHEMA_VERSION))
            conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                         ("built_at", now))
            conn.commit()

            conn.execute("VACUUM")
            conn.execute("ANALYZE")
            conn.close()

            # Atomic rename
            os.replace(tmp_path, str(self._db_path))

            # Update meta file
            self._write_meta(now, time.time())

            total = sum(results.values())
            log.info("Database built: %d total rows in %s", total, self._db_path)

        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    # -- Meta file helpers -----------------------------------------------------

    def _read_meta(self) -> dict:
        if not self._meta_path.exists():
            return {}
        try:
            return json.loads(self._meta_path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def _write_meta(self, built_at: str, timestamp: float) -> None:
        payload = {"built_at": built_at, "last_check": timestamp}
        self._meta_path.write_text(json.dumps(payload))
