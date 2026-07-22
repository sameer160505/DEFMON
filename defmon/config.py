"""DefMon configuration loader — reads config.yaml and .env variables."""

import os
from functools import lru_cache
from pathlib import Path

import yaml
from dotenv import load_dotenv

load_dotenv()

CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"


class Settings:
    """Application settings loaded from config.yaml and environment variables."""

    def __init__(self, config_path: Path = CONFIG_PATH):
        with open(config_path, "r") as f:
            self._config = yaml.safe_load(f)

        self.database_url = "sqlite+aiosqlite:///data/defmon.db"

        # App settings
        app = self._config.get("app", {})
        self.app_name = app.get("name", "DefMon")
        self.version = app.get("version", "1.0.0")
        self.debug = os.getenv("DEBUG", str(app.get("debug", False))).lower() == "true"
        self.host = app.get("host", "0.0.0.0")
        self.port = app.get("port", 8000)
        self.enable_local_collector = (
            os.getenv(
                "ENABLE_LOCAL_COLLECTOR", str(app.get("enable_local_collector", False))
            ).lower()
            == "true"
        )

        # Log sources
        log_sources_env = os.getenv("LOG_PATHS", "").strip()
        if log_sources_env:
            self.log_sources = [p.strip() for p in log_sources_env.split(",") if p.strip()]
        else:
            self.log_sources = self._config.get("log_sources", [])

        # Auth
        self.jwt_secret = os.getenv("JWT_SECRET_KEY", "dev-secret-change-me")
        self.jwt_algorithm = os.getenv("JWT_ALGORITHM", "HS256")
        auth = self._config.get("auth", {})
        self.access_token_expire_minutes = auth.get("access_token_expire_minutes", 30)

        # Threat Intel
        self.abuseipdb_key = os.getenv("ABUSEIPDB_KEY", "")
        self.webhook_url = os.getenv("WEBHOOK_URL", "")

    @property
    def detection_rules(self) -> list:
        """Get detection rules from config."""
        return self._config.get("detection", {}).get("rules", [])

    @property
    def threshold_config(self) -> dict:
        """Get threshold detection settings."""
        return self._config.get("detection", {}).get("threshold", {})

    @property
    def behavioral_config(self) -> dict:
        """Get behavioral detection settings."""
        return self._config.get("detection", {}).get("behavioral", {})

    @property
    def dedup_window(self) -> int:
        """Get deduplication window in seconds."""
        return self._config.get("detection", {}).get("dedup_window_seconds", 600)

    @property
    def risk_scoring(self) -> dict:
        """Get risk scoring weights."""
        return self._config.get("detection", {}).get("risk_scoring", {})

    @property
    def log_parser_patterns(self) -> dict:
        """Get log parser regex patterns."""
        return self._config.get("log_parser", {}).get("patterns", {})

    @property
    def threat_intel_config(self) -> dict:
        """Get threat intelligence settings."""
        return self._config.get("threat_intel", {})

    @property
    def soar_config(self) -> dict:
        """Get SOAR playbook settings."""
        return self._config.get("soar", {})

    @property
    def raw_config(self) -> dict:
        """Get the full raw config dict."""
        return self._config


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
