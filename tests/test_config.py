"""Tests for configuration loading."""

from pathlib import Path

import pytest

from nist_mcp.config import Config, get_config, reset_config


@pytest.fixture(autouse=True)
def _clean_singleton():
    """Reset the module-level singleton between tests."""
    reset_config()
    yield
    reset_config()


@pytest.fixture()
def tmp_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point data_dir at a temp directory via env var."""
    data_dir = tmp_path / "nist-mcp-test"
    monkeypatch.setenv("NIST_MCP_DATA_DIR", str(data_dir))
    return data_dir


class TestConfigDefaults:
    def test_defaults(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        for key in (
            "NIST_MCP_DATA_DIR",
            "NIST_MCP_NVD_API_KEY",
            "NIST_MCP_UPDATE_INTERVAL",
        ):
            monkeypatch.delenv(key, raising=False)

        monkeypatch.setenv("NIST_MCP_DATA_DIR", str(tmp_path / "data"))

        cfg = Config.load()
        assert cfg.data_dir == tmp_path / "data"
        assert cfg.nvd_api_key is None
        assert cfg.update_interval == 7 * 86400  # 7 days

    def test_data_dir_created(self, tmp_data_dir: Path):
        cfg = Config.load()
        assert cfg.data_dir == tmp_data_dir
        assert tmp_data_dir.is_dir()


class TestEnvOverrides:
    def test_nvd_api_key(self, tmp_data_dir: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("NIST_MCP_NVD_API_KEY", "test-key-123")
        cfg = Config.load()
        assert cfg.nvd_api_key == "test-key-123"

    def test_update_interval(self, tmp_data_dir: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("NIST_MCP_UPDATE_INTERVAL", "3600")
        cfg = Config.load()
        assert cfg.update_interval == 3600


class TestConfigFile:
    def test_file_values_used(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        data_dir = tmp_path / "from-env"
        monkeypatch.setenv("NIST_MCP_DATA_DIR", str(data_dir))
        for key in ("NIST_MCP_NVD_API_KEY", "NIST_MCP_UPDATE_INTERVAL"):
            monkeypatch.delenv(key, raising=False)

        data_dir.mkdir(parents=True)
        (data_dir / "config.toml").write_text(
            'nvd_api_key = "from-file"\n'
            "update_interval = 7200\n"
        )

        cfg = Config.load()
        assert cfg.nvd_api_key == "from-file"
        assert cfg.update_interval == 7200

    def test_env_overrides_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        data_dir = tmp_path / "mixed"
        monkeypatch.setenv("NIST_MCP_DATA_DIR", str(data_dir))
        monkeypatch.setenv("NIST_MCP_NVD_API_KEY", "from-env")

        data_dir.mkdir(parents=True)
        (data_dir / "config.toml").write_text('nvd_api_key = "from-file"\n')

        cfg = Config.load()
        assert cfg.nvd_api_key == "from-env"


class TestSingleton:
    def test_get_config_returns_same_instance(
        self, tmp_data_dir: Path, monkeypatch: pytest.MonkeyPatch
    ):
        a = get_config()
        b = get_config()
        assert a is b

    def test_reset_config(
        self, tmp_data_dir: Path, monkeypatch: pytest.MonkeyPatch
    ):
        a = get_config()
        reset_config()
        b = get_config()
        assert a is not b
