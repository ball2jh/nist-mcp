"""SQLite database connection and query helpers.

All access is **read-only**.  FTS5 queries go through synonym expansion so
that users can search for e.g. ``MFA`` and also match ``multi-factor
authentication``.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path


# -- Connection ----------------------------------------------------------------


def get_connection(db_path: Path) -> sqlite3.Connection:
    """Open a **read-only** SQLite connection with ``Row`` factory."""
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


# -- Synonym expansion ---------------------------------------------------------


def expand_query_with_synonyms(db_path: Path, query: str) -> str:
    """Expand terms in *query* using the ``synonyms`` table.

    For each token that appears as a ``term`` in the synonyms table, the
    synonyms are OR-ed in:

        ``MFA requirements`` -> ``MFA OR "multi-factor authentication" requirements``

    If the synonyms table does not exist (e.g. before the DB is downloaded),
    returns *query* unchanged.
    """
    try:
        conn = get_connection(db_path)
    except sqlite3.OperationalError:
        return query

    try:
        # Check if synonyms table exists.
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='synonyms'"
        )
        if cur.fetchone() is None:
            return query

        # Build a lookup dict: lowered term -> list of synonym strings.
        rows = conn.execute("SELECT term, synonyms FROM synonyms").fetchall()
        lookup: dict[str, list[str]] = {}
        for row in rows:
            term = row["term"].strip().lower()
            # synonyms column is comma-separated
            syns = [s.strip() for s in row["synonyms"].split(",") if s.strip()]
            if syns:
                lookup[term] = syns
    finally:
        conn.close()

    if not lookup:
        return query

    # Tokenise preserving quoted phrases as-is.
    tokens = _tokenize_query(query)
    expanded: list[str] = []
    for token in tokens:
        # Skip FTS operators and already-quoted phrases.
        if token.upper() in ("AND", "OR", "NOT", "NEAR") or token.startswith('"'):
            expanded.append(token)
            continue

        lower = token.lower()
        if lower in lookup:
            synonyms = lookup[lower]
            # Build: term OR "synonym1" OR "synonym2"
            parts = [token] + [f'"{s}"' for s in synonyms]
            expanded.append(" OR ".join(parts))
        else:
            expanded.append(token)

    return " ".join(expanded)


def _tokenize_query(query: str) -> list[str]:
    """Split a query into tokens, keeping quoted phrases intact."""
    tokens: list[str] = []
    i = 0
    while i < len(query):
        if query[i] == '"':
            # Find closing quote.
            end = query.find('"', i + 1)
            if end == -1:
                end = len(query)
            else:
                end += 1  # include closing quote
            tokens.append(query[i:end])
            i = end
        elif query[i].isspace():
            i += 1
        else:
            end = i
            while end < len(query) and not query[end].isspace() and query[end] != '"':
                end += 1
            tokens.append(query[i:end])
            i = end
    return tokens


# -- FTS search ----------------------------------------------------------------


def search_fts(
    db_path: Path,
    table: str,
    query: str,
    filters: dict | None = None,
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """Execute an FTS5 search with optional column filters.

    Parameters
    ----------
    db_path:
        Path to the SQLite database.
    table:
        Base table name.  The FTS table is assumed to be ``{table}_fts``.
    query:
        Raw user query (will be synonym-expanded).
    filters:
        Optional ``{column: value}`` pairs appended as ``WHERE`` conditions
        using parameterized queries.
    limit, offset:
        Pagination.

    Returns
    -------
    tuple of (results list[dict], total_count int)
    """
    _validate_identifier(table)
    expanded = expand_query_with_synonyms(db_path, query)
    conn = get_connection(db_path)

    fts_table = f"{table}_fts"

    try:
        # Validate that the FTS table exists.
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (fts_table,),
        )
        if cur.fetchone() is None:
            raise ValueError(f"FTS table '{fts_table}' does not exist.")

        # Build the query.  We join FTS results back to the base table.
        where_clauses = [f"{fts_table} MATCH ?"]
        params: list = [expanded]

        if filters:
            for col, val in filters.items():
                _validate_identifier(col)
                where_clauses.append(f"{table}.{col} = ?")
                params.append(val)

        where_sql = " AND ".join(where_clauses)

        # Count query.
        count_sql = (
            f"SELECT count(*) FROM {fts_table} "
            f"JOIN {table} ON {table}.rowid = {fts_table}.rowid "
            f"WHERE {where_sql}"
        )
        total = conn.execute(count_sql, params).fetchone()[0]

        # Result query — order by FTS rank.
        result_sql = (
            f"SELECT {table}.* FROM {fts_table} "
            f"JOIN {table} ON {table}.rowid = {fts_table}.rowid "
            f"WHERE {where_sql} "
            f"ORDER BY {fts_table}.rank "
            f"LIMIT ? OFFSET ?"
        )
        rows = conn.execute(result_sql, [*params, limit, offset]).fetchall()

        results = [dict(row) for row in rows]
    finally:
        conn.close()

    return results, total


# -- Single-row lookup ---------------------------------------------------------


def get_by_id(db_path: Path, table: str, id_value: str) -> dict | None:
    """Return a single row by primary key, or ``None``."""
    _validate_identifier(table)
    conn = get_connection(db_path)
    try:
        # Determine the primary key column.
        pk_col = _primary_key_column(conn, table)
        row = conn.execute(
            f"SELECT * FROM {table} WHERE {pk_col} = ?", (id_value,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# -- Utility -------------------------------------------------------------------


def get_table_count(db_path: Path, table: str) -> int:
    """Return the row count of *table*."""
    _validate_identifier(table)
    conn = get_connection(db_path)
    try:
        return conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def normalize_control_id(control_id: str) -> str:
    """Normalize an SP 800-53 control identifier.

    Strips whitespace, lowercases, inserts hyphens between letter and digit
    groups when missing, and converts parenthesised enhancement notation to
    dot notation::

        "AC2"     -> "ac-2"
        "ac-2"    -> "ac-2"
        "AC-2(1)" -> "ac-2(1)"
        " AC 2 "  -> "ac-2"
    """
    s = control_id.strip().lower()
    # Remove interior spaces (e.g. "AC 2" -> "AC2").
    s = s.replace(" ", "")
    # Insert hyphen between trailing letters and leading digits: ac2 -> ac-2.
    s = re.sub(r"([a-z])(\d)", r"\1-\2", s)
    return s


# -- Internal helpers ----------------------------------------------------------

_IDENT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def _validate_identifier(name: str) -> None:
    """Guard against SQL injection in dynamic identifiers."""
    if not _IDENT_RE.match(name):
        raise ValueError(f"Invalid SQL identifier: {name!r}")


def _primary_key_column(conn: sqlite3.Connection, table: str) -> str:
    """Return the primary-key column name for *table*."""
    _validate_identifier(table)
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    for row in rows:
        if row["pk"] == 1:
            return row["name"]
    # Fallback: use ``id`` if no explicit PK.
    return "id"
