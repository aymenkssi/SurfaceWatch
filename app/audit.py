"""Self-driven config audit over the web/TLS services a scan discovered.

BBOT's own web-probe (``http``) and service-fingerprint (``fingerprintx``) phases
sometimes emit nothing on a large target (they get truncated by the scan timeout
after the port scan, or a binary is missing from the image). When that happens the
report has thousands of open ports but 0 URL, 0 component and no TLS/header findings,
because every downstream check is fed by ``HTTP_RESPONSE`` events that were never
produced.

This module re-derives that layer directly: for each discovered ``host:port`` on the
scanned domain it opens its own bounded HTTP/TLS connection and emits the very same
events the rest of the pipeline already consumes — ``URL``, ``HTTP_RESPONSE`` and
``PROTOCOL`` — plus ``FINDING`` events for certificate problems. Nothing downstream
changes: ``checks.http_response_findings`` / ``component_versions`` and the report
builder light up on the synthesized events exactly as they would on BBOT's own.

This sends packets to the target, so it is NOT passive in the rule-2 sense: the caller
(the worker) runs it only for active levels on a verified domain. It uses no
third-party API keys. It is best-effort: any failure is swallowed so a scan never
fails because of the audit.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

# Web service ports we probe. Everything else a port scan finds (SSH, SMTP, DNS, app
# ports) is left alone: this audit is about web and TLS configuration, like Hexiosec's.
HTTPS_PORTS = {443, 4443, 8443, 9443, 2053, 2083, 2087, 2096}
HTTP_PORTS = {80, 8080, 8880, 2052, 2082, 2086, 2095}
WEB_PORTS = HTTPS_PORTS | HTTP_PORTS

_USER_AGENT = "SurfaceAttackWatch/1.0 (+config-audit)"


def _norm_host(host: str) -> str:
    return host.strip().strip("[]").rstrip(".").lower()


def in_scope(host: str, domain: str) -> bool:
    """True only for the scanned domain itself or one of its sub-domains."""
    host, domain = _norm_host(host), _norm_host(domain)
    return bool(host) and (host == domain or host.endswith("." + domain))


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _norm_header(key: str) -> str:
    # Match BBOT: header names lowercased, "-" replaced with "_".
    return key.strip().lower().replace("-", "_")


def web_endpoints(events: list[dict], domain: str, max_services: int) -> list[tuple[str, str, int]]:
    """Discovered in-scope web endpoints as (host, scheme, port), deduplicated and capped.

    Reads OPEN_TCP_PORT ("host:port") and PROTOCOL ({host, port}) events — the output
    the port scan does produce even when the web phase is truncated.
    """
    seen: set[tuple[str, int]] = set()
    endpoints: list[tuple[str, str, int]] = []
    for ev in events:
        etype, data = ev.get("type"), ev.get("data")
        host = port = None
        if etype == "OPEN_TCP_PORT" and isinstance(data, str):
            raw_host, _, raw_port = data.rpartition(":")
            host, port = raw_host, raw_port
        elif etype == "PROTOCOL" and isinstance(data, dict):
            host, port = str(data.get("host", "")), str(data.get("port", ""))
        if not host or not port or not str(port).isdigit():
            continue
        host, port = _norm_host(host), int(port)
        if port not in WEB_PORTS or _is_ip(host) or not in_scope(host, domain):
            continue
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        scheme = "https" if port in HTTPS_PORTS else "http"
        endpoints.append((host, scheme, port))
    endpoints.sort()
    return endpoints[:max_services]


# --- Certificate evaluation (pure, unit-tested) --------------------------------------------

def classify_cert_error(reason: str) -> tuple[str, str] | None:
    """Map an SSL verification failure reason to a (severity, description) finding."""
    r = (reason or "").lower()
    if "expired" in r:
        return ("HIGH", "Certificat TLS expiré.")
    if "self signed" in r or "self-signed" in r:
        return ("MEDIUM", "Certificat TLS auto-signé (non reconnu par une autorité de confiance).")
    if "hostname mismatch" in r or "doesn't match" in r or "does not match" in r:
        return ("MEDIUM", "Le certificat TLS ne correspond pas au nom d'hôte.")
    if "unable to get local issuer" in r or "unable to verify" in r or "self signed certificate in certificate chain" in r:
        return ("MEDIUM", "Chaîne de certificats TLS incomplète ou non vérifiable.")
    return ("MEDIUM", "Certificat TLS non valide.")


def cert_expiry_finding(host: str, not_after: str, now: datetime, warning_days: int) -> dict | None:
    """A finding if a still-valid certificate expires within ``warning_days`` days."""
    try:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
    except (ValueError, OverflowError, TypeError):
        return None
    days_left = (expires - now).total_seconds() / 86400
    if days_left < 0:
        return {"type": "FINDING", "severity": "HIGH", "host": host,
                "description": "Certificat TLS expiré."}
    if days_left <= warning_days:
        return {"type": "FINDING", "severity": "MEDIUM", "host": host,
                "description": f"Certificat TLS expire bientôt ({int(days_left)} jour(s))."}
    return None


# --- Network probe -------------------------------------------------------------------------

def probe_endpoint(host: str, scheme: str, port: int, timeout: float,
                   warning_days: int) -> dict | None:
    """Open one bounded HTTP/HTTPS connection; return a result dict or None if unreachable.

    Result: {url, host, status_code, header, protocol, findings}. For HTTPS the TLS
    certificate is verified; a verification failure becomes a FINDING and headers are
    still fetched over a non-verifying connection so the header/version checks can run.
    """
    url = f"{scheme}://{host}" + ("" if port in (80, 443) else f":{port}")
    findings: list[dict] = []
    now = datetime.now(timezone.utc)

    def _fetch(context: ssl.SSLContext | None) -> tuple[int, dict, dict | None]:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("GET", "/", headers={"User-Agent": _USER_AGENT, "Accept": "*/*"})
            resp = conn.getresponse()
            headers = {_norm_header(k): v for k, v in resp.getheaders()}
            cert = None
            if scheme == "https" and conn.sock is not None:
                try:
                    cert = conn.sock.getpeercert()
                except (ValueError, OSError):
                    cert = None
            resp.read(2048)  # drain a little; body is never stored
            return resp.status, headers, cert
        finally:
            conn.close()

    try:
        if scheme == "https":
            try:
                status, headers, cert = _fetch(ssl.create_default_context())
                if isinstance(cert, dict) and cert.get("notAfter"):
                    f = cert_expiry_finding(host, cert["notAfter"], now, warning_days)
                    if f:
                        findings.append(f)
            except ssl.SSLCertVerificationError as exc:
                sev_desc = classify_cert_error(getattr(exc, "verify_message", "") or str(exc))
                if sev_desc:
                    findings.append({"type": "FINDING", "severity": sev_desc[0],
                                     "host": host, "description": sev_desc[1]})
                # Still collect headers so the header/version checks have input.
                unverified = ssl.create_default_context()
                unverified.check_hostname = False
                unverified.verify_mode = ssl.CERT_NONE
                status, headers, _ = _fetch(unverified)
        else:
            status, headers, _ = _fetch(None)
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None

    return {
        "url": url,
        "host": host,
        "status_code": status,
        "header": headers,
        "protocol": scheme.upper(),
        "findings": findings,
    }


# --- Orchestration -------------------------------------------------------------------------

def audit_endpoints(events: list[dict], domain: str, settings, *, probe=probe_endpoint) -> list[dict]:
    """Probe discovered web endpoints concurrently and return synthesized BBOT-shaped events.

    Emits URL + HTTP_RESPONSE + PROTOCOL per reachable endpoint (so the report's URL count,
    services, headers and component-version detection populate) and FINDING events for TLS
    certificate problems. ``probe`` is injectable for tests. Best-effort per endpoint.
    """
    endpoints = web_endpoints(events, domain, settings.self_audit_max_services)
    if not endpoints:
        return []

    timeout = settings.self_audit_timeout_seconds
    warning_days = settings.self_audit_cert_expiry_warning_days
    workers = max(1, min(settings.self_audit_concurrency, len(endpoints)))

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(probe, host, scheme, port, timeout, warning_days)
                   for host, scheme, port in endpoints]
        for fut in futures:
            try:
                res = fut.result()
            except Exception:  # noqa: BLE001 - a single bad endpoint must not sink the audit
                res = None
            if res:
                results.append(res)

    new_events: list[dict] = []
    for res in results:
        new_events.append({"type": "URL", "data": res["url"]})
        new_events.append({"type": "HTTP_RESPONSE", "data": {
            "url": res["url"], "host": res["host"],
            "status_code": res["status_code"], "header": res["header"],
        }})
        new_events.append({"type": "PROTOCOL", "data": {
            "host": res["host"], "port": _port_of(res["url"]), "protocol": res["protocol"],
        }})
        for finding in res.get("findings", []):
            new_events.append({"type": "FINDING", "data": finding})
    return new_events


def _port_of(url: str) -> str:
    tail = url.rsplit(":", 1)[-1]
    return tail if tail.isdigit() else ("443" if url.startswith("https") else "80")
