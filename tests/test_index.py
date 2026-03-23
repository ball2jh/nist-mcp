"""Tests for the IndexManager (local build model)."""

import json
import time
from pathlib import Path

import pytest

from nist_mcp.config import Config
from nist_mcp.index import IndexManager


@pytest.fixture()
def config(tmp_path: Path) -> Config:
    """A Config pointing at a temporary data directory."""
    return Config(
        data_dir=tmp_path,
        nvd_api_key=None,
        update_interval=86400,
    )


@pytest.fixture()
def mgr(config: Config) -> IndexManager:
    return IndexManager(config)


# -- Staleness ----------------------------------------------------------------


class TestStaleness:
    def test_no_meta_is_stale(self, mgr: IndexManager):
        assert mgr._is_stale() is True

    def test_fresh_meta_not_stale(self, mgr: IndexManager):
        mgr._write_meta("2026-01-01T00:00:00+00:00", time.time())
        assert mgr._is_stale() is False

    def test_old_meta_is_stale(self, mgr: IndexManager):
        mgr._write_meta("2026-01-01T00:00:00+00:00", time.time() - 200_000)
        assert mgr._is_stale() is True


# -- Status -------------------------------------------------------------------


class TestStatus:
    def test_status_no_db(self, mgr: IndexManager):
        status = mgr.status()
        assert status["exists"] is False
        assert status["db_size_bytes"] is None

    def test_status_with_db(self, mgr: IndexManager):
        mgr.db_path.write_bytes(b"x" * 1024)
        mgr._write_meta("2026-03-01T12:00:00+00:00", time.time())

        status = mgr.status()
        assert status["exists"] is True
        assert status["db_size_bytes"] == 1024
        assert status["built_at"] == "2026-03-01T12:00:00+00:00"
        assert status["last_check"] is not None


# -- Meta helpers -------------------------------------------------------------


class TestMeta:
    def test_read_empty(self, mgr: IndexManager):
        assert mgr._read_meta() == {}

    def test_write_and_read(self, mgr: IndexManager):
        mgr._write_meta("2026-01-01T00:00:00+00:00", 1700000000.0)
        meta = mgr._read_meta()
        assert meta["built_at"] == "2026-01-01T00:00:00+00:00"
        assert meta["last_check"] == 1700000000.0

    def test_corrupt_meta(self, mgr: IndexManager):
        mgr._meta_path.write_text("NOT JSON!!!")
        assert mgr._read_meta() == {}
