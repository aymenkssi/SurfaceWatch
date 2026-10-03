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

import re
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


# A "Product/Version" token as advertised in a Server / X-Powered-By header, e.g.
# "Apache/2.4.52", "OpenSSL/1.1.1n", "PHP/7.4.3", "nginx/1.18.0". We require a slash
# and at least a dotted version so free text in parentheses ("(Debian)") is ignored.
_HEADER_VERSION = re.compile(r"([A-Za-z][\w.+\-]*?)/v?(\d+(?:\.\d+)+[\w.\-]*)")
# OpenSSH as advertised in an SSH banner, e.g. "SSH-2.0-OpenSSH_8.9p1 Debian-3".
_SSH_VERSION = re.compile(r"OpenSSH[_/](\d+(?:\.\d+)+[A-Za-z0-9]*)", re.IGNORECASE)


def _clean_version(version: str) -> str:
    return version.strip().rstrip(".,;:)")


def component_versions(events: list[dict]) -> list[dict]:
    """Software components and their versions, inferred passively from what the scan
    already collected: HTTP Server / X-Powered-By headers and service banners.

    Returns dicts {host, product, version, source}. This is advertised-version data:
    it never probes the target, and a backported security patch can make a version
    string look vulnerable when it is not — the vulnerability layer flags that caveat.
    """
    components: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    def add(host: str, product: str, version: str, source: str) -> None:
        product, version = product.strip(), _clean_version(version)
        key = (host, product.lower(), version)
        if host and product and version and key not in seen:
            seen.add(key)
            components.append({"host": host, "product": product,
                               "version": version, "source": source})

    # Web stack advertised in HTTP response headers (Apache, nginx, OpenSSL, PHP…).
    for host, data in _http_responses(events).items():
        headers = data.get("header") or {}
        if not isinstance(headers, dict):
            continue
        for key in ("server", "x_powered_by"):
            value = headers.get(key)
            if not value:
                continue
            for match in _HEADER_VERSION.finditer(str(value)):
                add(host, match.group(1), match.group(2), "http-header")

    # Service banners (e.g. OpenSSH on port 22), surfaced by the port-scan level.
    for ev in events:
        etype, data = ev.get("type"), ev.get("data")
        if etype == "PROTOCOL" and isinstance(data, dict):
            host = str(data.get("host", ""))
            blob = " ".join(str(data.get(k, "")) for k in ("banner", "version", "protocol"))
            for match in _SSH_VERSION.finditer(blob):
                add(host, "OpenSSH", match.group(1), "banner")
        elif etype == "TECHNOLOGY" and isinstance(data, dict):
            host = str(data.get("host", ""))
            version = str(data.get("version", "")).strip()
            name = str(data.get("technology", "")).strip()
            if version:
                add(host, name or "?", version, "technology")
            elif name:
                # Some BBOT TECHNOLOGY events fold the version into the name string.
                match = _HEADER_VERSION.search(name)
                if match:
                    add(host, match.group(1), match.group(2), "technology")

    components.sort(key=lambda c: (c["host"], c["product"].lower(), c["version"]))
    return components


def _resolve(name: str, rtype: str, timeout: float = 5.0) -> list:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        return list(resolver.resolve(name, rtype))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.exception.DNSException):
        return []


def _txt_records(name: str, timeout: float = 5.0) -> list[str]:
    records = []
    for rdata in _resolve(name, "TXT", timeout):
        # A TXT record may be split into several quoted strings; join them.
        parts = [p.decode() if isinstance(p, bytes) else str(p) for p in rdata.strings]
        records.append("".join(parts))
    return records


# Selectors to probe for a DKIM key; DKIM selectors are arbitrary, so a miss is only a
# soft signal (the domain may use a custom one) — reported at most as LOW.
_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1")


def dns_hygiene_findings(domain: str) -> list[dict]:
    """Passive DNS-configuration checks (DNSSEC, CAA, DKIM) via public lookups."""
    findings: list[dict] = []

    if not _resolve(domain, "DNSKEY"):
        findings.append({"type": "FINDING", "severity": "LOW", "host": domain,
                         "description": "DNSSEC non activé : les réponses DNS ne sont pas signées."})

    if not _resolve(domain, "CAA"):
        findings.append({"type": "FINDING", "severity": "LOW", "host": domain,
                         "description": "Aucun enregistrement CAA : aucune autorité de "
                                        "certification n'est restreinte pour ce domaine."})

    has_dkim = any(
        any(tok in r.lower() for tok in ("v=dkim1", "k=rsa", "p="))
        for selector in _DKIM_SELECTORS
        for r in _txt_records(f"{selector}._domainkey.{domain}")
    )
    if not has_dkim:
        findings.append({"type": "FINDING", "severity": "LOW", "host": domain,
                         "description": "Aucun sélecteur DKIM courant trouvé (un sélecteur "
                                        "personnalisé peut toutefois exister)."})

    return findings


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
