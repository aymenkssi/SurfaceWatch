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


# Server-side presets. NEVER build these from user input.
# The "web" preset includes "iis-shortnames" (detect_only: false), which pulls loud brute-force
# modules such as webbrute_shortnames: exclude those flags so "standard" stays light.
FORBIDDEN_FLAGS = ["loud", "invasive", "iis-shortnames", "web-heavy"]
LEVEL_ARGS: dict[ScanLevel, list[str]] = {
    ScanLevel.PASSIVE: ["-p", "subdomain-enum", "-rf", "passive"],
    ScanLevel.STANDARD: ["-p", "subdomain-enum", "web", "-ef", *FORBIDDEN_FLAGS],
}


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
    ]


def run_scan(raw_domain: str, level: str, domain_verified: bool) -> ScanResult:
    """Entry point executed by the RQ worker."""
    settings = get_settings()
    domain = normalize_domain(raw_domain)
    level = ScanLevel(level)

    if level is not ScanLevel.PASSIVE and not domain_verified:
        raise ScanNotAllowed("active scans require a verified domain")

    scan_id = f"sw_{uuid.uuid4().hex[:12]}"
    output_dir = settings.scans_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = build_command(domain, level, scan_id, output_dir)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=settings.scan_timeout_seconds, check=False
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
    """BBOT JSON output is one JSON event per line (NDJSON)."""
    if not path.exists():
        return []
    events = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events
