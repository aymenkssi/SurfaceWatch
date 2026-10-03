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
    # Deep level (active port scan): its own stricter quota and timeout. The port scan
    # on many hosts can be slow, so the budget is larger than the other levels to let the
    # web-probe and service-fingerprint phases finish (otherwise URLs/versions are lost).
    deep_scan_timeout_seconds: int = 7200
    deep_max_scans_per_day: int = 1
    # Extra RQ budget beyond the scan subprocess: the worker still runs the mail checks,
    # the CISA KEV / NVD vulnerability lookups and the retention purge after BBOT returns.
    # The RQ job timeout must clear the longest per-level subprocess timeout plus this.
    scan_post_processing_seconds: int = 600
    retention_days: int = 30
    scans_dir: Path = Path("./data/scans")
    bbot_bin: str = "bbot"

    # Self-driven config audit: probe the web/TLS services the scan discovered, from our
    # own infrastructure, to re-derive HTTP headers, advertised versions and certificate
    # findings when BBOT's own web-probe phase yields nothing. This sends packets to the
    # target, so the worker runs it ONLY for active levels on a verified domain. No
    # third-party keys. Bounded by a per-connection timeout, a service cap and concurrency.
    self_audit_enabled: bool = True
    self_audit_max_services: int = 150
    self_audit_timeout_seconds: float = 6.0
    self_audit_concurrency: int = 16
    self_audit_cert_expiry_warning_days: int = 30
    # How much of each page body to read for technology fingerprinting (never stored).
    self_audit_max_body_bytes: int = 40000

    # Vulnerability inference (passive): map advertised versions to known CVEs via the
    # public CISA KEV feed and the keyless NVD API. All best-effort; disable to skip.
    vuln_lookup_enabled: bool = True
    kev_feed_url: str = ("https://www.cisa.gov/sites/default/files/feeds/"
                         "known_exploited_vulnerabilities.json")
    kev_cache_path: Path = Path("./data/cisa_kev.json")
    kev_cache_ttl_seconds: int = 86400  # refresh the KEV catalogue at most once a day
    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_results_per_cpe: int = 20
    vuln_cves_per_component: int = 5
    vuln_http_timeout_seconds: int = 20

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
