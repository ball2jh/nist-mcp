"""Tests for the SQLite database connection and query helpers."""

import sqlite3
from pathlib import Path

import pytest

from nist_mcp.db import (
    expand_query_with_synonyms,
    get_by_id,
    get_connection,
    get_table_count,
    normalize_control_id,
    search_fts,
    _validate_identifier,
)


# -- Fixtures ------------------------------------------------------------------


@pytest.fixture()
def sample_db(tmp_path: Path) -> Path:
    """Create a minimal SQLite database with FTS5 for testing."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        CREATE TABLE controls (
            id TEXT PRIMARY KEY,
            family TEXT,
            title TEXT,
            description TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE VIRTUAL TABLE controls_fts USING fts5(
            id, family, title, description,
            content=controls, content_rowid=rowid
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE synonyms (
            alias TEXT NOT NULL,
            canonical TEXT NOT NULL,
            PRIMARY KEY (alias, canonical)
        )
        """
    )
    # Seed data.
    controls = [
        ("ac-1", "AC", "Policy and Procedures", "Access control policy and procedures"),
        ("ac-2", "AC", "Account Management", "Manage system accounts"),
        ("ac-2(1)", "AC", "Account Management | Automated Management", "Automated account management"),
        ("ia-1", "IA", "Policy and Procedures", "Identification and authentication policy"),
        ("ia-2", "IA", "Identification and Authentication", "Multi-factor authentication for users"),
    ]
    conn.executemany(
        "INSERT INTO controls VALUES (?, ?, ?, ?)", controls
    )
    # Rebuild FTS index.
    conn.execute("INSERT INTO controls_fts(controls_fts) VALUES('rebuild')")

    # Synonyms (alias -> canonical).
    conn.executemany(
        "INSERT INTO synonyms (alias, canonical) VALUES (?, ?)",
        [
            ("mfa", "multi-factor authentication"),
            ("mfa", "two-factor authentication"),
            ("2fa", "two-factor authentication"),
        ],
    )
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture()
def db_no_synonyms(tmp_path: Path) -> Path:
    """Database without a synonyms table."""
    db_path = tmp_path / "no_syn.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE controls (id TEXT PRIMARY KEY, title TEXT)")
    conn.commit()
    conn.close()
    return db_path


# -- Connection ----------------------------------------------------------------


class TestGetConnection:
    def test_read_only(self, sample_db: Path):
        conn = get_connection(sample_db)
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("INSERT INTO controls VALUES ('zz-1', 'ZZ', 'Nope', 'nope')")
        conn.close()

    def test_row_factory(self, sample_db: Path):
        conn = get_connection(sample_db)
        row = conn.execute("SELECT * FROM controls WHERE id = 'ac-1'").fetchone()
        assert row["id"] == "ac-1"
        assert row["family"] == "AC"
        conn.close()


# -- Synonym expansion ---------------------------------------------------------


class TestSynonymExpansion:
    def test_basic_expansion(self, sample_db: Path):
        result = expand_query_with_synonyms(sample_db, "MFA requirements")
        assert "MFA" in result
        assert '"multi-factor authentication"' in result
        assert '"two-factor authentication"' in result
        assert "requirements" in result

    def test_no_synonyms_table(self, db_no_synonyms: Path):
        result = expand_query_with_synonyms(db_no_synonyms, "MFA test")
        assert result == "MFA test"

    def test_nonexistent_db(self, tmp_path: Path):
        result = expand_query_with_synonyms(tmp_path / "nope.db", "some query")
        assert result == "some query"

    def test_no_match(self, sample_db: Path):
        result = expand_query_with_synonyms(sample_db, "firewall rules")
        assert result == "firewall rules"

    def test_quoted_phrases_preserved(self, sample_db: Path):
        result = expand_query_with_synonyms(sample_db, '"exact phrase" MFA')
        assert result.startswith('"exact phrase"')
        assert '"multi-factor authentication"' in result

    def test_fts_operators_preserved(self, sample_db: Path):
        result = expand_query_with_synonyms(sample_db, "MFA AND policy")
        # AND should remain as-is, not be expanded.
        assert " AND " in result


# -- FTS search ----------------------------------------------------------------


class TestSearchFts:
    def test_basic_search(self, sample_db: Path):
        results, total = search_fts(sample_db, "controls", "account")
        assert total >= 2
        assert len(results) >= 2
        ids = {r["id"] for r in results}
        assert "ac-2" in ids

    def test_with_filter(self, sample_db: Path):
        results, total = search_fts(
            sample_db, "controls", "policy", filters={"family": "IA"}
        )
        assert total >= 1
        for r in results:
            assert r["family"] == "IA"

    def test_pagination(self, sample_db: Path):
        results_all, total = search_fts(sample_db, "controls", "policy")
        assert total >= 2

        results_p1, _ = search_fts(
            sample_db, "controls", "policy", limit=1, offset=0
        )
        results_p2, _ = search_fts(
            sample_db, "controls", "policy", limit=1, offset=1
        )
        assert len(results_p1) == 1
        assert len(results_p2) == 1
        assert results_p1[0]["id"] != results_p2[0]["id"]

    def test_missing_fts_table(self, db_no_synonyms: Path):
        with pytest.raises(ValueError, match="does not exist"):
            search_fts(db_no_synonyms, "controls", "hello")

    def test_results_are_dicts(self, sample_db: Path):
        results, _ = search_fts(sample_db, "controls", "account")
        assert isinstance(results[0], dict)


# -- get_by_id -----------------------------------------------------------------


class TestGetById:
    def test_existing_row(self, sample_db: Path):
        row = get_by_id(sample_db, "controls", "ac-2")
        assert row is not None
        assert row["title"] == "Account Management"

    def test_missing_row(self, sample_db: Path):
        row = get_by_id(sample_db, "controls", "zz-99")
        assert row is None


# -- get_table_count -----------------------------------------------------------


class TestGetTableCount:
    def test_count(self, sample_db: Path):
        assert get_table_count(sample_db, "controls") == 5

    def test_count_synonyms(self, sample_db: Path):
        assert get_table_count(sample_db, "synonyms") == 3


# -- Control ID normalization --------------------------------------------------


class TestNormalizeControlId:
    @pytest.mark.parametrize(
        "input_id, expected",
        [
            ("AC-2", "ac-2"),
            ("ac-2", "ac-2"),
            ("AC2", "ac-2"),
            ("ac2", "ac-2"),
            (" AC 2 ", "ac-2"),
            ("AC-2(1)", "ac-2(1)"),
            ("ac2(1)", "ac-2(1)"),
            ("IA-5", "ia-5"),
            ("ia5", "ia-5"),
            ("SI-12", "si-12"),
            ("si12", "si-12"),
        ],
    )
    def test_normalization(self, input_id: str, expected: str):
        assert normalize_control_id(input_id) == expected


# -- SQL identifier validation -------------------------------------------------


class TestValidateIdentifier:
    def test_valid(self):
        _validate_identifier("controls")
        _validate_identifier("controls_fts")
        _validate_identifier("_private")

    def test_invalid(self):
        with pytest.raises(ValueError):
            _validate_identifier("Robert'; DROP TABLE--")
        with pytest.raises(ValueError):
            _validate_identifier("123starts_with_digit")
        with pytest.raises(ValueError):
            _validate_identifier("")
