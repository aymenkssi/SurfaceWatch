from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "SurfaceWatch"
    secret_key: str = "change-me"
    database_url: str = "sqlite:///./surfacewatch.db"
    redis_url: str = "redis://localhost:6379/0"

    # Scan guardrails
    scan_timeout_seconds: int = 1800
    max_scans_per_day: int = 5
    retention_days: int = 30
    scans_dir: Path = Path("./data/scans")
    bbot_bin: str = "bbot"

    # Domain verification
    verify_record_prefix: str = "_surfacewatch-verify"
    verify_token_prefix: str = "sw-verify="
    verify_token_ttl_hours: int = 72


@lru_cache
def get_settings() -> Settings:
    return Settings()
