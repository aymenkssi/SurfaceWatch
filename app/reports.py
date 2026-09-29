"""Turn BBOT events into a report model, then render HTML (and PDF if WeasyPrint is installed)."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=select_autoescape())

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Report:
    domain: str
    level: str
    generated_at: datetime
    subdomains: dict[str, set[str]] = field(default_factory=dict)  # host -> IPs
    urls: set[str] = field(default_factory=set)
    findings: list[dict] = field(default_factory=list)

    @property
    def ip_count(self) -> int:
        return len({ip for ips in self.subdomains.values() for ip in ips})


def build_report(domain: str, level: str, events: list[dict]) -> Report:
    hosts: dict[str, set[str]] = defaultdict(set)
    urls: set[str] = set()
    findings: list[dict] = []

    for ev in events:
        etype = ev.get("type")
        data = ev.get("data")
        if etype == "DNS_NAME" and isinstance(data, str):
            hosts[data]
            for ip in ev.get("resolved_hosts", []) or []:
                hosts[data].add(ip)
        elif etype == "URL" and isinstance(data, str):
            urls.add(data)
        elif etype in {"FINDING", "VULNERABILITY"} and isinstance(data, dict):
            findings.append({
                "type": etype,
                "severity": (data.get("severity") or "INFO").upper(),
                "host": data.get("host", ""),
                "description": data.get("description", ""),
            })

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return Report(
        domain=domain,
        level=level,
        generated_at=datetime.now(timezone.utc),
        subdomains=dict(sorted(hosts.items())),
        urls=urls,
        findings=findings,
    )


def render_html(report: Report) -> str:
    return _env.get_template("report.html").render(report=report)


def render_pdf(report: Report) -> bytes:
    try:
        from weasyprint import HTML  # optional dependency: pip install -e ".[pdf]"
    except ImportError as exc:
        raise RuntimeError("PDF export requires the 'pdf' extra (WeasyPrint)") from exc
    return HTML(string=render_html(report)).write_pdf()
