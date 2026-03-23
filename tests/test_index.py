"""Tests for the index manager."""

import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
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
        github_repo="test-org/test-repo",
    )


@pytest.fixture()
def manager(config: Config) -> IndexManager:
    return IndexManager(config)


@pytest.fixture()
def fake_db(config: Config) -> Path:
    """Create a fake database file so the manager thinks it's already downloaded."""
    db = config.data_dir / "nist_mcp.db"
    db.write_bytes(b"SQLite fake data for testing")
    return db


@pytest.fixture()
def fresh_meta(config: Config):
    """Write meta indicating a recent check."""
    meta_path = config.data_dir / "index_meta.json"
    meta_path.write_text(json.dumps({
        "current_tag": "v0.1.0",
        "last_check": time.time(),
    }))


@pytest.fixture()
def stale_meta(config: Config):
    """Write meta indicating a stale check (2 days ago)."""
    meta_path = config.data_dir / "index_meta.json"
    meta_path.write_text(json.dumps({
        "current_tag": "v0.1.0",
        "last_check": time.time() - 172800,
    }))


# -- Staleness -----------------------------------------------------------------


class TestStaleness:
    def test_no_meta_is_stale(self, manager: IndexManager):
        assert manager._is_stale() is True

    def test_fresh_meta_not_stale(
        self, manager: IndexManager, fresh_meta, fake_db: Path
    ):
        assert manager._is_stale() is False

    def test_old_meta_is_stale(
        self, manager: IndexManager, stale_meta, fake_db: Path
    ):
        assert manager._is_stale() is True


# -- Status --------------------------------------------------------------------


class TestStatus:
    def test_status_no_db(self, manager: IndexManager):
        s = manager.status()
        assert s["exists"] is False
        assert s["current_tag"] is None
        assert s["db_size_bytes"] is None

    def test_status_with_db(
        self, manager: IndexManager, fake_db: Path, fresh_meta
    ):
        s = manager.status()
        assert s["exists"] is True
        assert s["current_tag"] == "v0.1.0"
        assert s["db_size_bytes"] > 0
        assert "UTC" in s["last_check"]
        assert s["path"] == str(fake_db)


# -- Meta file helpers ---------------------------------------------------------


class TestMeta:
    def test_read_empty(self, manager: IndexManager):
        assert manager._read_meta() == {}

    def test_write_and_read(self, manager: IndexManager):
        now = time.time()
        manager._write_meta("v1.2.3", now)
        meta = manager._read_meta()
        assert meta["current_tag"] == "v1.2.3"
        assert meta["last_check"] == now

    def test_corrupt_meta(self, manager: IndexManager, config: Config):
        (config.data_dir / "index_meta.json").write_text("not json{{{")
        assert manager._read_meta() == {}


# -- ensure_index --------------------------------------------------------------


class TestEnsureIndex:
    @pytest.mark.asyncio
    async def test_existing_fresh_db_returns_immediately(
        self, manager: IndexManager, fake_db: Path, fresh_meta
    ):
        """When DB exists and is fresh, no download should happen."""
        path = await manager.ensure_index()
        assert path == fake_db

    @pytest.mark.asyncio
    async def test_missing_db_triggers_download(
        self, manager: IndexManager, config: Config
    ):
        """When no local DB exists, ensure_index should attempt download."""
        with patch.object(
            manager, "_download_latest", new_callable=AsyncMock
        ) as mock_dl:
            # Make _download_latest create the fake file so ensure_index succeeds.
            async def _create_fake():
                (config.data_dir / "nist_mcp.db").write_bytes(b"fake")

            mock_dl.side_effect = _create_fake
            await manager.ensure_index()
            mock_dl.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_stale_db_schedules_background(
        self, manager: IndexManager, fake_db: Path, stale_meta
    ):
        """When DB is stale, ensure_index should schedule background, not block."""
        with patch.object(
            manager, "_schedule_background_update"
        ) as mock_bg:
            path = await manager.ensure_index()
            assert path == fake_db
            mock_bg.assert_called_once()


# -- force_update --------------------------------------------------------------


class TestForceUpdate:
    @pytest.mark.asyncio
    async def test_force_update_calls_download(
        self, manager: IndexManager, config: Config
    ):
        with patch.object(
            manager, "_download_latest", new_callable=AsyncMock
        ) as mock_dl:
            async def _fake_download():
                (config.data_dir / "nist_mcp.db").write_bytes(b"fake")
                manager._write_meta("v2.0.0", time.time())

            mock_dl.side_effect = _fake_download
            tag = await manager.force_update()
            assert tag == "v2.0.0"
            mock_dl.assert_awaited_once()


# -- download resilience -------------------------------------------------------


class TestDownloadResilience:
    @pytest.mark.asyncio
    async def test_download_fails_with_existing_db(
        self, manager: IndexManager, fake_db: Path
    ):
        """If download fails but a local DB exists, it should not raise."""
        with patch.object(
            manager, "_fetch_latest_tag", new_callable=AsyncMock
        ) as mock_tag:
            mock_tag.side_effect = httpx.ConnectError("no network")
            # Should not raise because fake_db exists.
            await manager._download_latest()

    @pytest.mark.asyncio
    async def test_download_fails_no_db_raises(self, manager: IndexManager):
        """If download fails with no local DB, it must raise."""
        with patch.object(
            manager, "_fetch_latest_tag", new_callable=AsyncMock
        ) as mock_tag:
            mock_tag.side_effect = httpx.ConnectError("no network")
            with pytest.raises(httpx.ConnectError):
                await manager._download_latest()
