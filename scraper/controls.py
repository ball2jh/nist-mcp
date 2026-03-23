"""Scraper for SP 800-53 security and privacy controls.

Parses the OSCAL JSON catalog published by NIST on GitHub.  Extracts every
control and control-enhancement, assembles statement prose, resolves baseline
membership (LOW / MODERATE / HIGH), and writes everything to the ``controls``
table.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any

import httpx

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS controls (
    id            TEXT PRIMARY KEY,
    family_id     TEXT NOT NULL,
    family_name   TEXT NOT NULL,
    label         TEXT,
    title         TEXT NOT NULL,
    is_enhancement INTEGER NOT NULL DEFAULT 0,
    parent_id     TEXT,
    statement     TEXT,
    guidance      TEXT,
    parameters    TEXT,          -- JSON array
    related_controls TEXT,       -- comma-separated IDs
    is_withdrawn  INTEGER NOT NULL DEFAULT 0,
    withdrawn_to  TEXT,
    baselines     TEXT           -- comma-separated: LOW,MODERATE,HIGH
);
CREATE INDEX IF NOT EXISTS idx_ctrl_family ON controls(family_id);
CREATE INDEX IF NOT EXISTS idx_ctrl_parent ON controls(parent_id);
CREATE INDEX IF NOT EXISTS idx_ctrl_baseline ON controls(baselines);
"""

# ---------------------------------------------------------------------------
# OSCAL data URLs
# ---------------------------------------------------------------------------

_CATALOG_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/"
    "main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)

_BASELINE_URLS: dict[str, str] = {
    "LOW": (
        "https://raw.githubusercontent.com/usnistgov/oscal-content/"
        "main/nist.gov/SP800-53/rev5/json/"
        "NIST_SP-800-53_rev5_LOW-baseline-resolved-profile_catalog.json"
    ),
    "MODERATE": (
        "https://raw.githubusercontent.com/usnistgov/oscal-content/"
        "main/nist.gov/SP800-53/rev5/json/"
        "NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json"
    ),
    "HIGH": (
        "https://raw.githubusercontent.com/usnistgov/oscal-content/"
        "main/nist.gov/SP800-53/rev5/json/"
        "NIST_SP-800-53_rev5_HIGH-baseline-resolved-profile_catalog.json"
    ),
}

_TIMEOUT = 60  # seconds per request


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_prop(props: list[dict[str, Any]] | None, name: str) -> str | None:
    """Return the ``value`` of the first prop matching *name*."""
    if not props:
        return None
    for p in props:
        if p.get("name") == name:
            return p.get("value")
    return None


def _assemble_statement(parts: list[dict[str, Any]] | None) -> str:
    """Recursively walk OSCAL ``parts`` to build human-readable prose."""
    if not parts:
        return ""
    chunks: list[str] = []
    for part in parts:
        if part.get("name") not in ("statement", "item"):
            continue
        label = _get_prop(part.get("props"), "label") or ""
        prose = part.get("prose", "")
        if label and prose:
            chunks.append(f"{label} {prose}")
        elif prose:
            chunks.append(prose)
        # recurse into nested items
        sub = part.get("parts")
        if sub:
            chunks.append(_assemble_statement(sub))
    return "\n".join(chunks)


def _extract_guidance(parts: list[dict[str, Any]] | None) -> str:
    """Return guidance prose from a control's parts list."""
    if not parts:
        return ""
    for part in parts:
        if part.get("name") == "guidance":
            return part.get("prose", "")
    return ""


def _extract_related(links: list[dict[str, Any]] | None) -> str:
    """Return comma-separated control IDs from ``related`` links."""
    if not links:
        return ""
    ids: list[str] = []
    for link in links:
        if link.get("rel") == "related":
            href = link.get("href", "")
            ids.append(href.lstrip("#"))
    return ",".join(ids)


def _extract_withdrawn_to(links: list[dict[str, Any]] | None) -> str:
    """Return comma-separated control IDs from ``moved-to`` links."""
    if not links:
        return ""
    ids: list[str] = []
    for link in links:
        if link.get("rel") == "moved-to":
            href = link.get("href", "")
            ids.append(href.lstrip("#"))
    return ",".join(ids)


def _extract_parameters(params: list[dict[str, Any]] | None) -> str:
    """Return a JSON array of parameter dicts (id + label)."""
    if not params:
        return "[]"
    out: list[dict[str, str]] = []
    for p in params:
        entry: dict[str, str] = {"id": p.get("id", "")}
        if "label" in p:
            entry["label"] = p["label"]
        elif "select" in p:
            # Some params use select/choice instead of label
            choices = p["select"].get("choice", [])
            entry["label"] = " | ".join(choices) if choices else ""
        out.append(entry)
    return json.dumps(out, separators=(",", ":"))


def _collect_baseline_ids(catalog_json: dict[str, Any]) -> set[str]:
    """Return a set of control IDs present in a resolved baseline catalog."""
    ids: set[str] = set()
    catalog = catalog_json.get("catalog", {})
    for group in catalog.get("groups", []):
        for ctrl in group.get("controls", []):
            ids.add(ctrl["id"])
            for enh in ctrl.get("controls", []):
                ids.add(enh["id"])
    return ids


def _parse_control(
    ctrl: dict[str, Any],
    family_id: str,
    family_name: str,
    *,
    parent_id: str | None = None,
) -> dict[str, Any]:
    """Extract a flat dict of columns from an OSCAL control node."""
    props = ctrl.get("props", [])
    is_withdrawn = 1 if _get_prop(props, "status") == "withdrawn" else 0

    return {
        "id": ctrl["id"],
        "family_id": family_id,
        "family_name": family_name,
        "label": _get_prop(props, "label") or ctrl["id"].upper(),
        "title": ctrl.get("title", ""),
        "is_enhancement": 1 if parent_id is not None else 0,
        "parent_id": parent_id,
        "statement": _assemble_statement(ctrl.get("parts")),
        "guidance": _extract_guidance(ctrl.get("parts")),
        "parameters": _extract_parameters(ctrl.get("params")),
        "related_controls": _extract_related(ctrl.get("links")),
        "is_withdrawn": is_withdrawn,
        "withdrawn_to": _extract_withdrawn_to(ctrl.get("links")) if is_withdrawn else "",
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scrape_controls(db: sqlite3.Connection) -> int:
    """Download OSCAL data and populate the ``controls`` table.

    Returns the number of rows inserted.
    """
    client = httpx.Client(timeout=_TIMEOUT, follow_redirects=True)

    # -- Fetch main catalog ------------------------------------------------
    log.info("Downloading SP 800-53 rev5 OSCAL catalog ...")
    resp = client.get(_CATALOG_URL)
    resp.raise_for_status()
    catalog_json = resp.json()

    # -- Fetch baselines ---------------------------------------------------
    baseline_ids: dict[str, set[str]] = {}
    for level, url in _BASELINE_URLS.items():
        log.info("Downloading %s baseline ...", level)
        try:
            r = client.get(url)
            r.raise_for_status()
            baseline_ids[level] = _collect_baseline_ids(r.json())
            log.info("  %s baseline: %d controls", level, len(baseline_ids[level]))
        except httpx.HTTPError:
            log.warning("Failed to download %s baseline; skipping", level)

    client.close()

    # -- Parse controls ----------------------------------------------------
    rows: list[dict[str, Any]] = []
    catalog = catalog_json.get("catalog", {})
    for group in catalog.get("groups", []):
        fam_id = group["id"]
        fam_name = group.get("title", "")
        for ctrl in group.get("controls", []):
            rows.append(_parse_control(ctrl, fam_id, fam_name))
            # Enhancements are nested controls
            for enh in ctrl.get("controls", []):
                rows.append(
                    _parse_control(enh, fam_id, fam_name, parent_id=ctrl["id"])
                )

    # -- Resolve baselines -------------------------------------------------
    for row in rows:
        levels = [lv for lv, ids in sorted(baseline_ids.items()) if row["id"] in ids]
        row["baselines"] = ",".join(levels)

    # -- Insert into DB ----------------------------------------------------
    db.execute("DELETE FROM controls")  # idempotent rebuild
    db.executemany(
        """
        INSERT INTO controls (
            id, family_id, family_name, label, title,
            is_enhancement, parent_id, statement, guidance,
            parameters, related_controls, is_withdrawn,
            withdrawn_to, baselines
        ) VALUES (
            :id, :family_id, :family_name, :label, :title,
            :is_enhancement, :parent_id, :statement, :guidance,
            :parameters, :related_controls, :is_withdrawn,
            :withdrawn_to, :baselines
        )
        """,
        rows,
    )
    db.commit()
    log.info("Inserted %d controls", len(rows))
    return len(rows)


# ---------------------------------------------------------------------------
# Standalone test harness
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    conn = sqlite3.connect(":memory:")
    conn.executescript(CREATE_TABLE_SQL)
    n = scrape_controls(conn)
    print(f"Inserted {n} controls")

    # Quick spot-check
    cur = conn.execute("SELECT id, label, title, baselines FROM controls LIMIT 10")
    for row in cur:
        print(row)

    cur = conn.execute(
        "SELECT COUNT(*) FROM controls WHERE is_enhancement = 1"
    )
    print(f"Enhancements: {cur.fetchone()[0]}")

    cur = conn.execute("SELECT COUNT(*) FROM controls WHERE is_withdrawn = 1")
    print(f"Withdrawn: {cur.fetchone()[0]}")

    cur = conn.execute(
        "SELECT COUNT(*) FROM controls WHERE baselines LIKE '%HIGH%'"
    )
    print(f"HIGH baseline: {cur.fetchone()[0]}")
    conn.close()
