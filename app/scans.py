"""Run BBOT as a subprocess and collect its JSON events.

BBOT is deliberately invoked through its CLI (not imported) — see CLAUDE.md (licence).
Users never pass BBOT options: they pick a level, mapped here to a fixed argument list.

TODO(bbot-3.x): verify flags (-rf, -om, -o, -n, -y) and the JSON output path against the
official BBOT 3.x docs before the first real run — the CLI changed between 2.x and 3.0.
"""

from __future__ import annotations

import json
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
LEVEL_ARGS: dict[ScanLevel, list[str]] = {
    ScanLevel.PASSIVE: ["-p", "subdomain-enum", "-rf", "passive"],
    ScanLevel.STANDARD: ["-p", "subdomain-enum", "web"],
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
        return ScanResult(scan_id, domain, level, returncode=-1, error="timeout")
    except FileNotFoundError:
        return ScanResult(scan_id, domain, level, returncode=-1, error="bbot binary not found")

    events = load_events(output_dir / scan_id / "output.json")
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
