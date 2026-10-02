"""Turn BBOT events into a report model, then render HTML (and PDF if WeasyPrint is installed)."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app import checks

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
    technologies: list[dict] = field(default_factory=list)  # {host, technology}

    @property
    def ip_count(self) -> int:
        return len({ip for ips in self.subdomains.values() for ip in ips})


def build_report(domain: str, level: str, events: list[dict]) -> Report:
    hosts: dict[str, set[str]] = defaultdict(set)
    urls: set[str] = set()
    findings: list[dict] = []
    tech_seen: set[tuple[str, str]] = set()
    technologies: list[dict] = []

    def add_tech(host: str, name: str) -> None:
        key = (host, name)
        if name and key not in tech_seen:
            tech_seen.add(key)
            technologies.append({"host": host, "technology": name})

    for ev in events:
        etype = ev.get("type")
        data = ev.get("data")
        if etype == "DNS_NAME" and isinstance(data, str):
            hosts[data]
            for ip in ev.get("resolved_hosts", []) or []:
                hosts[data].add(ip)
        elif etype == "URL" and isinstance(data, str):
            urls.add(data)
        elif etype == "TECHNOLOGY" and isinstance(data, dict):
            add_tech(str(data.get("host", "")), str(data.get("technology", "")))
        elif etype in {"FINDING", "VULNERABILITY"} and isinstance(data, dict):
            findings.append({
                "type": etype,
                "severity": (data.get("severity") or "INFO").upper(),
                "host": data.get("host", ""),
                "description": data.get("description", ""),
            })

    # Passive checks derived from the HTTP responses BBOT already fetched.
    findings.extend(checks.http_response_findings(events))
    for tech in checks.advertised_technologies(events):
        add_tech(tech["host"], tech["technology"])

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return Report(
        domain=domain,
        level=level,
        generated_at=datetime.now(timezone.utc),
        subdomains=dict(sorted(hosts.items())),
        urls=urls,
        findings=findings,
        technologies=sorted(technologies, key=lambda t: (t["host"], t["technology"])),
    )


def report_to_dict(report: Report) -> dict:
    """JSON-friendly view of a report, consumed by the React front end."""
    return {
        "domain": report.domain,
        "level": report.level,
        "generated_at": report.generated_at.isoformat(),
        "summary": {
            "subdomains": len(report.subdomains),
            "ips": report.ip_count,
            "urls": len(report.urls),
            "findings": len(report.findings),
            "technologies": len(report.technologies),
        },
        "subdomains": [{"host": h, "ips": sorted(ips)} for h, ips in report.subdomains.items()],
        "urls": sorted(report.urls),
        "findings": report.findings,
        "technologies": report.technologies,
    }


def render_html(report: Report) -> str:
    return _env.get_template("report.html").render(report=report)


def render_pdf(report: Report) -> bytes:
    try:
        from weasyprint import HTML  # optional dependency: pip install -e ".[pdf]"
    except ImportError as exc:
        raise RuntimeError("PDF export requires the 'pdf' extra (WeasyPrint)") from exc
    return HTML(string=render_html(report)).write_pdf()
