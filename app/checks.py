"""Passive risk checks that turn raw scan data into report findings.

These complement BBOT: they do no active scanning of the target beyond what the
scan already collected (HTTP response headers) and public DNS lookups for the
mail configuration of the scanned domain. They mirror the bulk of what a managed
EASM report flags — HTTP security headers, cleartext HTTP, advertised software
versions and e-mail authentication records — without any louder BBOT module.

Everything here is passive and legal under the project's non-negotiable rules:
headers come from responses BBOT already fetched, and the mail checks are plain
TXT lookups on the domain the user owns.
"""

from __future__ import annotations

from urllib.parse import urlparse

import dns.exception
import dns.resolver

# BBOT lowercases header names and replaces "-" with "_" in HTTP_RESPONSE.header.
# header key -> (human label, severity) for headers whose ABSENCE is a risk.
SECURITY_HEADERS: list[tuple[str, str, str]] = [
    ("strict_transport_security", "En-tête HSTS absent (Strict-Transport-Security)", "MEDIUM"),
    ("content_security_policy", "En-tête CSP absent (Content-Security-Policy)", "MEDIUM"),
    ("x_content_type_options", "En-tête X-Content-Type-Options absent", "LOW"),
    ("x_frame_options", "En-tête X-Frame-Options absent (risque de clickjacking)", "LOW"),
    ("referrer_policy", "En-tête Referrer-Policy absent", "LOW"),
    ("permissions_policy", "En-tête Permissions-Policy absent", "LOW"),
]


def _http_responses(events: list[dict]) -> dict[str, dict]:
    """One representative HTTP_RESPONSE event per host (first reachable one)."""
    per_host: dict[str, dict] = {}
    for ev in events:
        if ev.get("type") != "HTTP_RESPONSE":
            continue
        data = ev.get("data")
        if not isinstance(data, dict):
            continue
        url = data.get("url", "")
        host = data.get("host") or urlparse(url).hostname or ""
        if host and host not in per_host:
            per_host[host] = data
    return per_host


def http_response_findings(events: list[dict]) -> list[dict]:
    """Security-header and cleartext-HTTP findings, one set per host."""
    findings: list[dict] = []
    for host, data in _http_responses(events).items():
        url = data.get("url", "")
        headers = data.get("header") or {}
        if not isinstance(headers, dict):
            headers = {}

        if url.startswith("http://"):
            findings.append({
                "type": "FINDING", "severity": "MEDIUM", "host": host,
                "description": "Service web accessible en clair (HTTP) sans redirection HTTPS.",
            })

        for key, label, severity in SECURITY_HEADERS:
            if key not in headers:
                findings.append({"type": "FINDING", "severity": severity, "host": host,
                                 "description": label})
    return findings


def advertised_technologies(events: list[dict]) -> list[dict]:
    """Software versions a host advertises in its Server / X-Powered-By headers."""
    techs: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for host, data in _http_responses(events).items():
        headers = data.get("header") or {}
        if not isinstance(headers, dict):
            continue
        for key in ("server", "x_powered_by"):
            value = headers.get(key)
            if not value:
                continue
            value = str(value).strip()
            if (host, value) not in seen:
                seen.add((host, value))
                techs.append({"host": host, "technology": value})
    return techs


def _txt_records(name: str, timeout: float = 5.0) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.exception.DNSException):
        return []
    records = []
    for rdata in answers:
        # A TXT record may be split into several quoted strings; join them.
        parts = [p.decode() if isinstance(p, bytes) else str(p) for p in rdata.strings]
        records.append("".join(parts))
    return records


def mail_config_findings(domain: str) -> list[dict]:
    """Passive e-mail authentication checks (SPF, DMARC, MTA-STS) on the domain."""
    findings: list[dict] = []

    spf = next((r for r in _txt_records(domain) if r.lower().startswith("v=spf1")), None)
    if spf is None:
        findings.append({"type": "FINDING", "severity": "MEDIUM", "host": domain,
                         "description": "Aucun enregistrement SPF : usurpation d'e-mail facilitée."})
    elif "+all" in spf.replace(" ", ""):
        findings.append({"type": "FINDING", "severity": "HIGH", "host": domain,
                         "description": "SPF en '+all' : n'importe quel serveur peut envoyer pour ce domaine."})
    elif not any(tok in spf for tok in ("-all", "~all")):
        findings.append({"type": "FINDING", "severity": "LOW", "host": domain,
                         "description": "SPF sans mécanisme de rejet (-all/~all)."})

    dmarc = next((r for r in _txt_records(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")), None)
    if dmarc is None:
        findings.append({"type": "FINDING", "severity": "MEDIUM", "host": domain,
                         "description": "Aucun enregistrement DMARC : pas de politique contre l'usurpation."})
    elif "p=none" in dmarc.replace(" ", "").lower():
        findings.append({"type": "FINDING", "severity": "LOW", "host": domain,
                         "description": "DMARC en 'p=none' : surveillance seule, aucun rejet appliqué."})

    mta_sts = any(r.lower().startswith("v=stsv1") for r in _txt_records(f"_mta-sts.{domain}"))
    if not mta_sts:
        findings.append({"type": "FINDING", "severity": "LOW", "host": domain,
                         "description": "Aucune politique MTA-STS : le chiffrement SMTP n'est pas imposé."})

    return findings
