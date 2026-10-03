"""Turn BBOT events into a report model, then render HTML (and PDF if WeasyPrint is installed)."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app import branding as branding_mod
from app import checks

TEMPLATES_DIR = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=select_autoescape())

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Category buckets for grouping the report, in display order. A finding is placed by its
# type and description (the checks emit French descriptions).
CATEGORIES = ["Vulnérabilités", "TLS / Certificats", "En-têtes & web", "Mail", "DNS", "Réseau"]
_TLS_RE = re.compile(r"\bTLS\b|certificat|chiffrement", re.I)
_MAIL_RE = re.compile(r"\bSPF\b|DMARC|DKIM|MTA-STS|e-mail|SMTP", re.I)
_DNS_RE = re.compile(r"DNSSEC|\bCAA\b", re.I)
_WEB_RE = re.compile(r"en-tête|HSTS|CSP|clair|clickjacking|Referrer|Permissions|"
                     r"X-Content|X-Frame|cookie|HTTP", re.I)


def categorize(finding: dict) -> str:
    """Bucket a finding into one of CATEGORIES for the grouped report view."""
    if finding.get("type") == "VULNERABILITY":
        return "Vulnérabilités"
    desc = finding.get("description", "") or ""
    if _TLS_RE.search(desc):
        return "TLS / Certificats"
    if _DNS_RE.search(desc):
        return "DNS"
    if _MAIL_RE.search(desc):
        return "Mail"
    if _WEB_RE.search(desc):
        return "En-têtes & web"
    return "Réseau"


@dataclass
class Report:
    domain: str
    level: str
    generated_at: datetime
    subdomains: dict[str, set[str]] = field(default_factory=dict)  # host -> IPs
    urls: set[str] = field(default_factory=set)
    findings: list[dict] = field(default_factory=list)
    technologies: list[dict] = field(default_factory=list)  # {host, technology}
    services: list[dict] = field(default_factory=list)  # {host, port, protocol}
    components: list[dict] = field(default_factory=list)  # {host, product, version, source, vuln?}

    @property
    def ip_count(self) -> int:
        return len({ip for ips in self.subdomains.values() for ip in ips})

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = Counter(f["severity"] for f in self.findings)
        return {sev: counts.get(sev, 0) for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}

    @property
    def vulnerable_components(self) -> list[dict]:
        """Components with known CVEs, most severe first — the report's headline list."""
        order = SEVERITY_ORDER
        vulns = [c for c in self.components if c.get("vuln")]
        return sorted(vulns, key=lambda c: order.get(c["vuln"]["severity"], 99))

    @property
    def category_counts(self) -> dict[str, int]:
        """Number of findings per category, only for categories that have any."""
        counts = Counter(f.get("category", "Réseau") for f in self.findings)
        return {cat: counts[cat] for cat in CATEGORIES if counts[cat]}

    @property
    def findings_by_category(self) -> list[tuple[str, list[dict]]]:
        """Findings grouped by category (display order), each group severity-sorted."""
        groups: list[tuple[str, list[dict]]] = []
        for cat in CATEGORIES:
            items = [f for f in self.findings if f.get("category") == cat]
            if items:
                items.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
                groups.append((cat, items))
        return groups


def build_report(domain: str, level: str, events: list[dict]) -> Report:
    hosts: dict[str, set[str]] = defaultdict(set)
    urls: set[str] = set()
    findings: list[dict] = []
    tech_seen: set[tuple[str, str]] = set()
    technologies: list[dict] = []
    services: dict[tuple[str, str], str] = {}  # (host, port) -> protocol
    # Structured vulnerability verdicts (from VULNERABILITY events the worker appends),
    # keyed so we can attach them back to the matching detected component.
    vuln_by_component: dict[tuple[str, str, str], dict] = {}

    def add_tech(host: str, name: str) -> None:
        key = (host, name)
        if name and key not in tech_seen:
            tech_seen.add(key)
            technologies.append({"host": host, "technology": name})

    def add_service(host: str, port: str, protocol: str = "") -> None:
        if not host or not port:
            return
        key = (host, str(port))
        # A PROTOCOL event names the service; keep it over a bare open port.
        if key not in services or (protocol and not services[key]):
            services[key] = protocol

    for ev in events:
        etype = ev.get("type")
        data = ev.get("data")
        if etype == "DNS_NAME" and isinstance(data, str):
            hosts[data]
            for ip in ev.get("resolved_hosts", []) or []:
                hosts[data].add(ip)
        elif etype == "URL" and isinstance(data, str):
            urls.add(data)
        elif etype == "OPEN_TCP_PORT" and isinstance(data, str):
            host, _, port = data.rpartition(":")
            add_service(host.strip("[]"), port)
        elif etype == "PROTOCOL" and isinstance(data, dict):
            add_service(str(data.get("host", "")), str(data.get("port", "")),
                        str(data.get("protocol", "")))
        elif etype == "TECHNOLOGY" and isinstance(data, dict):
            add_tech(str(data.get("host", "")), str(data.get("technology", "")))
        elif etype in {"FINDING", "VULNERABILITY"} and isinstance(data, dict):
            severity = (data.get("severity") or "INFO").upper()
            findings.append({
                "type": etype,
                "severity": severity,
                "host": data.get("host", ""),
                "description": data.get("description", ""),
            })
            if etype == "VULNERABILITY" and data.get("product") and data.get("version"):
                vuln_by_component[(str(data.get("host", "")),
                                   str(data["product"]).lower(), str(data["version"]))] = {
                    "severity": severity, "cves": data.get("cves", []),
                    "kev": bool(data.get("kev")),
                }

    # Passive checks derived from the HTTP responses BBOT already fetched.
    findings.extend(checks.http_response_findings(events))
    for tech in checks.advertised_technologies(events):
        add_tech(tech["host"], tech["technology"])

    # Detected software versions, each annotated with its vulnerability verdict (if any).
    # The verdicts themselves are computed by the worker and arrive as VULNERABILITY
    # events, already folded into `findings` above.
    components = checks.component_versions(events)
    for comp in components:
        vuln = vuln_by_component.get((comp["host"], comp["product"].lower(), comp["version"]))
        if vuln:
            comp["vuln"] = vuln

    for finding in findings:
        finding["category"] = categorize(finding)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return Report(
        domain=domain,
        level=level,
        generated_at=datetime.now(timezone.utc),
        subdomains=dict(sorted(hosts.items())),
        urls=urls,
        findings=findings,
        technologies=sorted(technologies, key=lambda t: (t["host"], t["technology"])),
        services=[{"host": h, "port": int(p) if p.isdigit() else p, "protocol": proto}
                  for (h, p), proto in sorted(services.items(),
                                              key=lambda kv: (kv[0][0], int(kv[0][1])
                                                              if kv[0][1].isdigit() else 0))],
        components=components,
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
            "services": len(report.services),
            "components": len(report.components),
            "vulnerabilities": sum(1 for f in report.findings if f["type"] == "VULNERABILITY"),
        },
        "severity_counts": report.severity_counts,
        "category_counts": report.category_counts,
        "subdomains": [{"host": h, "ips": sorted(ips)} for h, ips in report.subdomains.items()],
        "urls": sorted(report.urls),
        "findings": report.findings,
        "technologies": report.technologies,
        "services": report.services,
        "components": report.components,
    }


def _branding_context(branding: dict | None) -> dict:
    """Fill in defaults for any branding field the caller left out."""
    branding = branding or {}
    return {
        "site_name": branding.get("site_name") or branding_mod.DEFAULT_SITE_NAME,
        "site_logo": branding.get("site_logo"),
        "client_logo": branding.get("client_logo"),
        "accent": branding.get("accent") or branding_mod.DEFAULT_ACCENT,
    }


def render_html(report: Report, branding: dict | None = None) -> str:
    return _env.get_template("report.html").render(
        report=report, branding=_branding_context(branding))


def render_pdf(report: Report, branding: dict | None = None) -> bytes:
    try:
        from weasyprint import HTML  # optional dependency: pip install -e ".[pdf]"
    except ImportError as exc:
        raise RuntimeError("PDF export requires the 'pdf' extra (WeasyPrint)") from exc
    return HTML(string=render_html(report, branding)).write_pdf()
