"""Run BBOT as a subprocess and collect its JSON events.

BBOT is deliberately invoked through its CLI (not imported) — see CLAUDE.md (licence).
Users never pass BBOT options: they pick a level, mapped here to a fixed argument list.

CLI flags and the output path were checked against the BBOT 3.0.2 source
(bbot/scanner/preset/args.py): JSON events land in <output_dir>/<scan name>/output.json.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from app.config import get_settings
from app.domains import normalize_domain


class ScanLevel(str, Enum):
    PASSIVE = "passive"
    STANDARD = "standard"  # active — requires a verified domain (v0.3)
    ADVANCED = "advanced"  # active + brute-force — verified domain AND explicit consent (v0.4)
    DEEP = "deep"          # active port scan + service fingerprinting — verified AND consent


# Server-side presets. NEVER build these from user input.
# The "web" preset includes "iis-shortnames" (detect_only: false), which pulls loud brute-force
# modules such as webbrute_shortnames: exclude those flags so "standard" stays light.
FORBIDDEN_FLAGS = ["loud", "invasive", "iis-shortnames", "web-heavy"]
# GDPR (no email-enum): drop the email-harvesting module that subdomain-enum pulls in. Other
# modules flagged email-enum (sslcert, dnscaa, dnstlsrpt) are kept for their DNS results; the
# e-mail addresses they emit are discarded in load_events().
EXCLUDED_MODULES = ["hunterio"]

# BBOT omits HTTP_RESPONSE from its output by default. We need it (headers only) to derive
# security-header and advertised-version findings, so every active level overrides
# omit_event_types to keep HTTP_RESPONSE while still dropping the other noisy types.
_OMIT_EVENT_TYPES = "omit_event_types=[RAW_TEXT,URL_UNVERIFIED,DNS_NAME_UNRESOLVED,FILESYSTEM,WEB_PARAMETER]"

# "advanced" adds surface-level brute-force on top of the standard web scan:
#   - dnsbrute: subdomain name brute-force (needs massdns in the worker image)
#   - webbrute: web directory brute-force (surface-level, 1000-word list)
# It deliberately still excludes, via flags:
#   - invasive: credential brute-force against live services (legba, medusa) — never run
#   - iis-shortnames / web-heavy: IIS shortname brute-force (webbrute_shortnames) and other
#     heavy web modules
#   - web-paramminer: parameter brute-force (slow, noisy, low signal)
# kitchen-sink / paramminer / raw modules stay impossible: users only pick a level.
ADVANCED_BRUTE_MODULES = ["dnsbrute", "webbrute"]
ADVANCED_FORBIDDEN_FLAGS = ["invasive", "iis-shortnames", "web-heavy", "web-paramminer"]

# "deep" adds a real port scan (masscan, via the portscan module) and service fingerprinting
# (fingerprintx) to find exposed services. masscan is "loud", so we cannot exclude the loud
# flag here; instead we forbid the same aggressive flags as advanced. nuclei (active vuln
# probing) stays excluded via the invasive flag. The preset stays server-side.
DEEP_MODULES = ["portscan", "fingerprintx"]
DEEP_FORBIDDEN_FLAGS = ["invasive", "iis-shortnames", "web-heavy", "web-paramminer"]

LEVEL_ARGS: dict[ScanLevel, list[str]] = {
    ScanLevel.PASSIVE: ["-p", "subdomain-enum", "-rf", "passive", "-em", *EXCLUDED_MODULES],
    ScanLevel.STANDARD: ["-p", "subdomain-enum", "web", "-ef", *FORBIDDEN_FLAGS,
                         "-em", *EXCLUDED_MODULES, "-c", _OMIT_EVENT_TYPES],
    ScanLevel.ADVANCED: ["-p", "subdomain-enum", "web", "-m", *ADVANCED_BRUTE_MODULES,
                         "-ef", *ADVANCED_FORBIDDEN_FLAGS, "-em", *EXCLUDED_MODULES,
                         "-c", _OMIT_EVENT_TYPES],
    ScanLevel.DEEP: ["-p", "subdomain-enum", "web", "-m", *DEEP_MODULES,
                     "-ef", *DEEP_FORBIDDEN_FLAGS, "-em", *EXCLUDED_MODULES,
                     "-c", _OMIT_EVENT_TYPES,
                     "-c", "modules.portscan.top_ports=100",
                     "-c", "modules.portscan.rate=300"],
}

# Levels that send active traffic to the target: a verified domain is mandatory.
ACTIVE_LEVELS = frozenset({ScanLevel.STANDARD, ScanLevel.ADVANCED, ScanLevel.DEEP})
# Levels aggressive enough to require explicit, logged user consent.
CONSENT_LEVELS = frozenset({ScanLevel.ADVANCED, ScanLevel.DEEP})


def timeout_for(level: ScanLevel) -> int:
    settings = get_settings()
    if level is ScanLevel.ADVANCED:
        return settings.advanced_scan_timeout_seconds
    if level is ScanLevel.DEEP:
        return settings.deep_scan_timeout_seconds
    return settings.scan_timeout_seconds

# Personal data BBOT may emit: never stored, never shown in reports.
PERSONAL_DATA_EVENTS = {"EMAIL_ADDRESS", "USERNAME", "PASSWORD", "HASHED_PASSWORD"}
# HTTP_RESPONSE carries the full page body; keep only the light metadata we analyse.
_HTTP_RESPONSE_KEEP = {"url", "input", "host", "status_code", "title", "header"}


class ScanNotAllowed(PermissionError):
    pass


@dataclass
class ScanResult:
    scan_id: str
    domain: str
    level: ScanLevel
    returncode: int
    events: list[dict] = field(default_factory=list)
    error: str | None = None


def build_command(domain: str, level: ScanLevel, scan_id: str, output_dir: Path) -> list[str]:
    settings = get_settings()
    return [
        settings.bbot_bin,
        "-t", domain,
        *LEVEL_ARGS[level],
        "-om", "json",
        "-eom", "csv", "txt",  # only the JSON output is used
        "-o", str(output_dir),
        "-n", scan_id,
        "-y",  # non-interactive
        # Never install dependencies at scan time: the worker runs unprivileged (no root, no
        # sudo) and BBOT's installer would abort the scan. They are installed at image build
        # time by install_deps() below.
        "--no-deps",
    ]


def install_deps_command(level: ScanLevel) -> list[str]:
    """Dry run with no target: BBOT installs the level's module dependencies, scans nothing."""
    return [get_settings().bbot_bin, *LEVEL_ARGS[level], "-y", "--dry-run"]


def install_deps() -> int:
    """Install BBOT dependencies for every level. Run at image build time, as the worker user."""
    for level in ScanLevel:
        rc = subprocess.run(install_deps_command(level), check=False).returncode
        if rc != 0:
            return rc
    return 0


def run_scan(raw_domain: str, level: str, domain_verified: bool) -> ScanResult:
    """Entry point executed by the RQ worker."""
    settings = get_settings()
    domain = normalize_domain(raw_domain)
    level = ScanLevel(level)

    if level in ACTIVE_LEVELS and not domain_verified:
        raise ScanNotAllowed("active scans require a verified domain")

    scan_id = f"sw_{uuid.uuid4().hex[:12]}"
    output_dir = settings.scans_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = build_command(domain, level, scan_id, output_dir)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_for(level), check=False
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(output_dir / scan_id, ignore_errors=True)
        return ScanResult(scan_id, domain, level, returncode=-1, error="timeout")
    except FileNotFoundError:
        return ScanResult(scan_id, domain, level, returncode=-1, error="bbot binary not found")

    scan_dir = output_dir / scan_id
    try:
        events = load_events(scan_dir / "output.json")
    finally:
        # Events are stored in the DB (and purged after RETENTION_DAYS); never keep a second copy.
        shutil.rmtree(scan_dir, ignore_errors=True)
    error = None if proc.returncode == 0 else proc.stderr[-2000:]
    return ScanResult(scan_id, domain, level, proc.returncode, events, error)


def load_events(path: Path) -> list[dict]:
    """BBOT JSON output is one JSON event per line (NDJSON). Personal data events are dropped."""
    if not path.exists():
        return []
    events = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict) or event.get("type") in PERSONAL_DATA_EVENTS:
                continue
            # Drop the heavy body/raw_header from HTTP responses: we only analyse headers.
            if event.get("type") == "HTTP_RESPONSE" and isinstance(event.get("data"), dict):
                event["data"] = {k: v for k, v in event["data"].items() if k in _HTTP_RESPONSE_KEEP}
            events.append(event)
    return events


if __name__ == "__main__":
    import sys

    if sys.argv[1:] != ["install-deps"]:
        sys.exit("usage: python -m app.scans install-deps")
    sys.exit(install_deps())
