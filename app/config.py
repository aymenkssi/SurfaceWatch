from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "SurfaceWatch"
    secret_key: str = "change-me"
    database_url: str = "sqlite:///./surfacewatch.db"
    redis_url: str = "redis://localhost:6379/0"

    # Auth (JWT bearer, same scheme as Waselni)
    access_token_ttl_minutes: int = 720
    # Comma-separated origins allowed to call the API (React dev server)
    cors_origins: str = "http://localhost:5173"
    # Built React app served by FastAPI in production (Docker)
    frontend_dist: Path = Path("./frontend/dist")

    # Scan guardrails
    scan_timeout_seconds: int = 1800
    max_scans_per_day: int = 5
    max_concurrent_scans_per_user: int = 1
    # "deep" level (active port scan): stricter dedicated quota and timeout.
    deep_scan_timeout_seconds: int = 3600
    deep_max_scans_per_day: int = 1
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
