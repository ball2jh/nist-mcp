"""Orchestrator that runs all scrapers and builds the SQLite database.

Usage::

    python -m scraper -o nist_mcp.db --quick

The ``--quick`` flag skips slow operations like individual detail page
scraping for the 2000+ publications, which is useful during development.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import tempfile
from datetime import datetime, timezone

from scraper.controls import CREATE_TABLE_SQL as CONTROLS_SQL, scrape_controls
from scraper.csf import CREATE_TABLE_SQL as CSF_SQL, scrape_csf
from scraper.glossary import CREATE_TABLE_SQL as GLOSSARY_SQL, scrape_glossary
from scraper.nice import CREATE_TABLE_SQL as NICE_SQL, scrape_nice
from scraper.synonyms import CREATE_TABLE_SQL as SYNONYMS_SQL, build_synonyms
from scraper.mappings import CREATE_TABLE_SQL as MAPPINGS_SQL, scrape_mappings
from scraper.publications import CREATE_TABLE_SQL as PUBLICATIONS_SQL, scrape_publications
from scraper.cmvp import CREATE_TABLE_SQL as CMVP_SQL, scrape_cmvp
from scraper.checklists import CREATE_TABLE_SQL as CHECKLISTS_SQL, scrape_checklists

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Meta table and FTS virtual tables
# ---------------------------------------------------------------------------

_META_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_FTS_SQL = """
-- Full-text search indexes for key tables
CREATE VIRTUAL TABLE IF NOT EXISTS controls_fts USING fts5(
    id, title, statement, guidance,
    content='controls',
    content_rowid='rowid'
);

CREATE VIRTUAL TABLE IF NOT EXISTS publications_fts USING fts5(
    id, title, abstract, authors, topics,
    content='publications',
    content_rowid='rowid'
);

CREATE VIRTUAL TABLE IF NOT EXISTS glossary_fts USING fts5(
    term, definition,
    content='glossary',
    content_rowid='rowid'
);

CREATE VIRTUAL TABLE IF NOT EXISTS csf_fts USING fts5(
    id, title,
    content='csf',
    content_rowid='rowid'
);

CREATE VIRTUAL TABLE IF NOT EXISTS cmvp_fts USING fts5(
    cert_number, vendor, module_name, description, algorithms,
    content='cmvp',
    content_rowid='rowid'
);

CREATE VIRTUAL TABLE IF NOT EXISTS checklists_fts USING fts5(
    id, name, product, description,
    content='checklists',
    content_rowid='rowid'
);
"""

_SCHEMA_VERSION = "1"


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def build_database(output_path: str = "nist_mcp.db", quick: bool = False) -> None:
    """Build the complete NIST metadata index.

    Args:
        output_path: Where to write the SQLite file.
        quick: If True, skip slow operations (detail page scraping).
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    output_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(output_dir, exist_ok=True)

    # Build into a temp file in the same directory (for atomic rename)
    fd, tmp_path = tempfile.mkstemp(
        suffix=".db", prefix=".nist_mcp_build_", dir=output_dir
    )
    os.close(fd)

    log.info("Building NIST MCP database ...")
    log.info("  Output: %s", output_path)
    log.info("  Quick mode: %s", quick)
    log.info("  Temp file: %s", tmp_path)

    try:
        conn = sqlite3.connect(tmp_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")

        # Step 1: Create all tables
        log.info("Creating tables ...")
        for name, sql in [
            ("controls", CONTROLS_SQL),
            ("csf", CSF_SQL),
            ("glossary", GLOSSARY_SQL),
            ("nice_roles", NICE_SQL),
            ("synonyms", SYNONYMS_SQL),
            ("mappings", MAPPINGS_SQL),
            ("publications", PUBLICATIONS_SQL),
            ("cmvp", CMVP_SQL),
            ("checklists", CHECKLISTS_SQL),
            ("meta", _META_SQL),
        ]:
            log.info("  Creating table: %s", name)
            conn.executescript(sql)

        # Create FTS virtual tables
        log.info("Creating FTS virtual tables ...")
        conn.executescript(_FTS_SQL)

        # Step 2: Run each scraper in sequence
        results: dict[str, int] = {}

        scrapers: list[tuple[str, object]] = [
            ("controls", lambda: scrape_controls(conn)),
            ("csf", lambda: scrape_csf(conn)),
            ("glossary", lambda: scrape_glossary(conn)),
            ("nice_roles", lambda: scrape_nice(conn)),
            ("synonyms", lambda: build_synonyms(conn)),
            ("mappings", lambda: scrape_mappings(conn)),
            ("publications", lambda: scrape_publications(conn, quick=quick)),
            ("cmvp", lambda: scrape_cmvp(conn)),
            ("checklists", lambda: scrape_checklists(conn)),
        ]

        for name, scraper_fn in scrapers:
            log.info("Running scraper: %s ...", name)
            try:
                count = scraper_fn()
                results[name] = count
                log.info("  %s: %d rows", name, count)
            except Exception:
                log.exception("  FAILED: %s", name)
                results[name] = 0

        # Step 3: Rebuild FTS indexes
        log.info("Rebuilding FTS indexes ...")
        fts_tables = [
            "controls_fts",
            "publications_fts",
            "glossary_fts",
            "csf_fts",
            "cmvp_fts",
            "checklists_fts",
            "nice_roles_fts",
        ]
        for fts_table in fts_tables:
            try:
                conn.execute(
                    f"INSERT INTO {fts_table}({fts_table}) VALUES('rebuild')"
                )
                log.info("  Rebuilt: %s", fts_table)
            except Exception:
                log.exception("  Failed to rebuild: %s", fts_table)

        conn.commit()

        # Step 4: Write meta table
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            ("schema_version", _SCHEMA_VERSION),
        )
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            ("built_at", now),
        )
        conn.commit()

        # Step 5: VACUUM and ANALYZE
        log.info("Running VACUUM and ANALYZE ...")
        conn.execute("VACUUM")
        conn.execute("ANALYZE")
        conn.close()

        # Step 6: Atomic rename
        os.replace(tmp_path, output_path)
        log.info("Database written to: %s", output_path)

        # Summary
        log.info("Build complete. Summary:")
        total = 0
        for name, count in results.items():
            log.info("  %-20s %6d rows", name, count)
            total += count
        log.info("  %-20s %6d rows", "TOTAL", total)

    except Exception:
        log.exception("Build failed!")
        # Clean up temp file on failure
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise
