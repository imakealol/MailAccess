from __future__ import annotations

import json

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    database_url: str = "sqlite+aiosqlite:///./data/mailaccess.db"

    # Application
    debug: bool = False
    log_level: str = "INFO"
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Worker
    max_concurrent_modules: int = 10
    module_timeout_seconds: int = 30

    # Webhooks
    slack_webhook_url: str | None = None
    discord_webhook_url: str | None = None
    integration_webhook_url: str | None = None
    integration_webhook_secret: str | None = None

    # API keys (all optional — modules skip themselves when their key is absent)
    mailaccess_api_key: str | None = None
    haveibeenpwned_api_key: str | None = None
    hibp_api_key: str | None = None
    hunter_io_api_key: str | None = None
    emailrep_api_key: str | None = None
    shodan_api_key: str | None = None
    serpapi_key: str | None = None

    # Proxy
    proxy_url: str | None = None
    proxy_enabled: bool = False

    # Rate limiting
    rate_limit_enabled: bool = True
    request_delay_ms: int = 1000
    # Per-domain overrides (ms): RATE_LIMIT_OVERRIDES={"api.github.com": 500}
    rate_limit_overrides: dict[str, int] = {}
    # Legacy per-domain delays (seconds): RATE_LIMIT_DELAYS={"haveibeenpwned.com": 1.5}
    rate_limit_delays: dict[str, float] = {}

    @field_validator("rate_limit_overrides", mode="before")
    @classmethod
    def _parse_overrides(cls, v: str | dict) -> dict[str, int]:
        if isinstance(v, str):
            return json.loads(v) if v else {}
        return v

    @field_validator("rate_limit_delays", mode="before")
    @classmethod
    def _parse_delays(cls, v: str | dict) -> dict[str, float]:
        if isinstance(v, str):
            return json.loads(v) if v else {}
        return v

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_cors(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v


settings = Settings()
