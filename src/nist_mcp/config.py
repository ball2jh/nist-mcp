"""Configuration loading and defaults for nist-mcp."""

from dataclasses import dataclass, field
from pathlib import Path
import os
import tomllib


_DEFAULT_DATA_DIR = Path.home() / ".nist-mcp"
_DEFAULT_UPDATE_INTERVAL = 7 * 86400  # 7 days in seconds


@dataclass
class Config:
    """Server configuration loaded from env vars, config file, and defaults."""

    data_dir: Path = field(default_factory=lambda: _DEFAULT_DATA_DIR)
    nvd_api_key: str | None = None
    update_interval: int = _DEFAULT_UPDATE_INTERVAL

    @classmethod
    def load(cls) -> "Config":
        """Load config with priority: env vars > config file > defaults.

        The config file is at ``{data_dir}/config.toml``.  ``data_dir`` itself
        can be overridden by the ``NIST_MCP_DATA_DIR`` env var *or* the
        ``data_dir`` key in the config file (env var wins).
        """
        # Step 1: Determine data_dir early so we can find the config file.
        env_data_dir = os.environ.get("NIST_MCP_DATA_DIR")
        data_dir = Path(env_data_dir) if env_data_dir else _DEFAULT_DATA_DIR

        # Step 2: Read the config file (if it exists).
        file_values: dict = {}
        config_path = data_dir / "config.toml"
        if config_path.is_file():
            with open(config_path, "rb") as f:
                file_values = tomllib.load(f)

        # If the file specifies data_dir and no env var overrides it, use it.
        if not env_data_dir and "data_dir" in file_values:
            data_dir = Path(file_values["data_dir"])

        # Step 3: Build the final config — env vars override file values.
        nvd_api_key = (
            os.environ.get("NIST_MCP_NVD_API_KEY")
            or file_values.get("nvd_api_key")
            or None
        )

        raw_interval = os.environ.get("NIST_MCP_UPDATE_INTERVAL")
        if raw_interval is not None:
            update_interval = int(raw_interval)
        elif "update_interval" in file_values:
            update_interval = int(file_values["update_interval"])
        else:
            update_interval = _DEFAULT_UPDATE_INTERVAL

        config = cls(
            data_dir=data_dir,
            nvd_api_key=nvd_api_key,
            update_interval=update_interval,
        )

        # Ensure data_dir exists on disk.
        config.data_dir.mkdir(parents=True, exist_ok=True)

        return config


# Module-level singleton -------------------------------------------------------

_config: Config | None = None


def get_config() -> Config:
    """Return the singleton ``Config`` instance, loading it on first call."""
    global _config
    if _config is None:
        _config = Config.load()
    return _config


def reset_config() -> None:
    """Reset the singleton (useful for tests)."""
    global _config
    _config = None
