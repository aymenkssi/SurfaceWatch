from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "SurfaceAttackWatch"
    # Public base URL of the front end, used for links in e-mails (reset, scan done).
    public_url: str = "http://localhost:5173"
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
    # Advanced level (active + brute-force): stricter, dedicated limits.
    advanced_scan_timeout_seconds: int = 3600
    advanced_max_scans_per_day: int = 1
    retention_days: int = 30
    scans_dir: Path = Path("./data/scans")
    bbot_bin: str = "bbot"

    # E-mail (SMTP). No provider key is embedded: e-mail features are disabled until
    # SMTP_HOST and SMTP_FROM are set (password reset, notifications).
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_security: str = "starttls"  # starttls | ssl | none
    smtp_timeout_seconds: int = 15
    password_reset_ttl_minutes: int = 60
    password_reset_max_per_hour: int = 3

    # Domain verification
    verify_record_prefix: str = "_surfacewatch-verify"
    verify_token_prefix: str = "sw-verify="
    verify_token_ttl_hours: int = 72


@lru_cache
def get_settings() -> Settings:
    return Settings()
