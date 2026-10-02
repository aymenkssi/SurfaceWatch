"""Conclude whether detected component versions are vulnerable.

This is a passive, inference-only layer: it takes the software versions a host
*advertises* (Server/X-Powered-By headers, service banners — see
``checks.component_versions``) and looks them up against two public,
key-free sources:

  * the CISA KEV catalogue (Known Exploited Vulnerabilities) — a public JSON feed,
  * the NVD CVE API (version 2.0, keyless, rate-limited).

No active vulnerability probing is performed (nuclei and the invasive BBOT modules
stay excluded at every scan level): we never send an exploit or a payload to the
target. We only map "this host says it runs X version Y" to "version Y has known
CVEs". That caveat matters — a distribution may have backported a fix without
changing the advertised version — so findings are labelled as inferred.

Network access is optional and best-effort: if the feeds are unreachable the scan
still succeeds with whatever could be resolved, and the KEV cache is reused.
All HTTP calls are injectable so the logic is unit-tested offline.
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from pathlib import Path

from app.config import get_settings

# Curated product -> (CPE vendor, CPE product) map for the components we can match
# reliably. We only assess a component when it maps here, to avoid guessing a wrong
# CPE (and raising false alarms) for software we do not recognise.
_CPE_MAP: list[tuple[re.Pattern[str], tuple[str, str]]] = [
    (re.compile(r"^openssh", re.I), ("openbsd", "openssh")),
    (re.compile(r"^apache(\s|/|-)?(http|2|$)", re.I), ("apache", "http_server")),
    (re.compile(r"^(apache\s+)?tomcat", re.I), ("apache", "tomcat")),
    (re.compile(r"^nginx", re.I), ("f5", "nginx")),
    (re.compile(r"^openssl", re.I), ("openssl", "openssl")),
    (re.compile(r"^php", re.I), ("php", "php")),
    (re.compile(r"^lighttpd", re.I), ("lighttpd", "lighttpd")),
    (re.compile(r"^(microsoft-?)?iis", re.I), ("microsoft", "internet_information_services")),
    (re.compile(r"^exim", re.I), ("exim", "exim")),
    (re.compile(r"^postfix", re.I), ("postfix", "postfix")),
    (re.compile(r"^(pure-?ftpd)", re.I), ("pureftpd", "pure-ftpd")),
    (re.compile(r"^proftpd", re.I), ("proftpd", "proftpd")),
    (re.compile(r"^vsftpd", re.I), ("vsftpd_project", "vsftpd")),
]

# NVD severity -> our report severity. NVD uses CVSS baseSeverity strings.
_SEVERITY_MAP = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
                 "LOW": "LOW", "NONE": "INFO"}


# OpenSSH-style "8.9p1" is, in CPE terms, version "8.9" with update "p1".
_PATCH_SUFFIX = re.compile(r"^(\d+(?:\.\d+)+)(p\d+)$")


def cpe_for(product: str, version: str) -> str | None:
    """A CPE 2.3 string for a recognised product+version, or None if unmapped."""
    product = product.strip()
    for pattern, (vendor, cpe_product) in _CPE_MAP:
        if pattern.match(product):
            update = "*"
            match = _PATCH_SUFFIX.match(version)
            if match:
                version, update = match.group(1), match.group(2)
            return f"cpe:2.3:a:{vendor}:{cpe_product}:{version}:{update}:*:*:*:*:*:*"
    return None


# --- CISA KEV --------------------------------------------------------------------

def _http_get_json(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "SurfaceAttackWatch"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https feeds
        return json.loads(resp.read().decode("utf-8"))


def refresh_kev(path: Path, *, url: str, timeout: float, http_get=_http_get_json) -> set[str]:
    """Fetch the CISA KEV catalogue and cache the set of exploited CVE ids to ``path``."""
    catalogue = http_get(url, timeout)
    cve_ids = sorted(
        str(v.get("cveID", "")).upper()
        for v in catalogue.get("vulnerabilities", []) if v.get("cveID")
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"cveIDs": cve_ids}), encoding="utf-8")
    return set(cve_ids)


def load_kev(*, http_get=_http_get_json) -> set[str]:
    """Known-exploited CVE ids. Refreshes the on-disk cache when stale; on any network
    failure, returns whatever is cached (possibly empty) instead of failing the scan."""
    settings = get_settings()
    path = Path(settings.kev_cache_path)
    fresh = path.exists() and (time.time() - path.stat().st_mtime) < settings.kev_cache_ttl_seconds
    if not fresh:
        try:
            return refresh_kev(path, url=settings.kev_feed_url,
                               timeout=settings.vuln_http_timeout_seconds, http_get=http_get)
        except Exception:  # noqa: BLE001 - KEV is best-effort; fall back to the cache
            pass
    try:
        return set(json.loads(path.read_text(encoding="utf-8")).get("cveIDs", []))
    except Exception:  # noqa: BLE001 - no usable cache yet
        return set()


# --- NVD -------------------------------------------------------------------------

def _parse_cvss(cve: dict) -> tuple[float, str]:
    """Best CVSS base score and severity across the metric versions NVD returns."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            cvss = entries[0].get("cvssData", {})
            score = float(cvss.get("baseScore", 0.0))
            severity = (entries[0].get("baseSeverity") or cvss.get("baseSeverity") or "").upper()
            if not severity:  # CVSS v2 carries severity outside cvssData
                severity = "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
            return score, severity
    return 0.0, "INFO"


def nvd_cves_for_cpe(cpe: str, *, http_get=_http_get_json) -> list[dict]:
    """CVEs NVD maps to an exact CPE (product+version). Best-effort: [] on failure."""
    settings = get_settings()
    url = f"{settings.nvd_api_base}?cpeName={cpe}&resultsPerPage={settings.nvd_results_per_cpe}"
    try:
        payload = http_get(url, settings.vuln_http_timeout_seconds)
    except Exception:  # noqa: BLE001 - NVD is best-effort
        return []
    cves: list[dict] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve") or {}
        cve_id = str(cve.get("id", "")).upper()
        if not cve_id:
            continue
        descriptions = cve.get("descriptions") or []
        summary = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
        score, severity = _parse_cvss(cve)
        cves.append({"id": cve_id, "cvss": score, "severity": severity, "summary": summary})
    cves.sort(key=lambda c: c["cvss"], reverse=True)
    return cves


# --- assessment ------------------------------------------------------------------

def assess_components(components: list[dict], *, kev_ids: set[str] | None = None,
                      nvd_lookup=nvd_cves_for_cpe) -> list[dict]:
    """Turn detected components into VULNERABILITY findings.

    One finding per (host, product, version) that maps to a CPE and has known CVEs.
    CVEs are looked up once per unique (product, version) and reused across hosts.
    """
    kev_ids = kev_ids or set()
    cache: dict[str, list[dict]] = {}
    findings: list[dict] = []

    for comp in components:
        product, version, host = comp["product"], comp["version"], comp["host"]
        cpe = cpe_for(product, version)
        if not cpe:
            continue
        if cpe not in cache:
            cache[cpe] = nvd_lookup(cpe)
        cves = cache[cpe]
        if not cves:
            continue

        top = cves[: get_settings().vuln_cves_per_component]
        kev_hits = [c["id"] for c in cves if c["id"] in kev_ids]
        severity = "CRITICAL" if kev_hits else _SEVERITY_MAP.get(top[0]["severity"], "MEDIUM")
        cve_list = ", ".join(f"{c['id']} (CVSS {c['cvss']:.1f})" for c in top)
        detail = (f"{product} {version} : {len(cves)} CVE(s) connue(s) pour cette version — "
                  f"{cve_list}")
        if kev_hits:
            detail += f". Activement exploitée (CISA KEV) : {', '.join(kev_hits)}"
        detail += ". Déduit de la version annoncée (un correctif rétroporté peut l'infirmer)."
        findings.append({
            "type": "VULNERABILITY", "severity": severity, "host": host,
            "description": detail,
            "product": product, "version": version,
            "cves": [c["id"] for c in top], "kev": bool(kev_hits),
        })
    return findings
