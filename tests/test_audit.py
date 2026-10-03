"""Audit logic tests. No sockets: probing is injected, cert evaluation is pure."""

import http.client
import ssl
from datetime import datetime, timedelta, timezone

from app import audit, reports
from app.config import get_settings


def test_in_scope_only_domain_and_subdomains():
    assert audit.in_scope("scc.com", "scc.com")
    assert audit.in_scope("www.fr.scc.com", "scc.com")
    assert audit.in_scope("SCC.COM.", "scc.com")  # normalised
    assert not audit.in_scope("scc-services.fr", "scc.com")  # different registrable domain
    assert not audit.in_scope("notscc.com", "scc.com")
    assert not audit.in_scope("", "scc.com")


def test_web_endpoints_filters_ports_scope_and_ips_and_caps():
    events = [
        {"type": "OPEN_TCP_PORT", "data": "www.scc.com:443"},
        {"type": "OPEN_TCP_PORT", "data": "www.scc.com:443"},   # dup
        {"type": "OPEN_TCP_PORT", "data": "mail.scc.com:25"},    # non-web port
        {"type": "OPEN_TCP_PORT", "data": "shop.scc.com:80"},
        {"type": "OPEN_TCP_PORT", "data": "evil.fr:443"},        # out of scope
        {"type": "OPEN_TCP_PORT", "data": "203.0.113.9:443"},    # bare IP
        {"type": "PROTOCOL", "data": {"host": "api.scc.com", "port": 8443}},
    ]
    eps = audit.web_endpoints(events, "scc.com", max_services=10)
    assert ("www.scc.com", "https", 443) in eps
    assert ("shop.scc.com", "http", 80) in eps
    assert ("api.scc.com", "https", 8443) in eps
    assert all(host.endswith("scc.com") for host, _, _ in eps)
    assert not any(port == 25 for _, _, port in eps)
    assert len(eps) == 3  # dup collapsed, IP + out-of-scope + port 25 dropped

    assert len(audit.web_endpoints(events, "scc.com", max_services=1)) == 1  # cap honoured


def test_classify_cert_error():
    assert audit.classify_cert_error("certificate has expired")[0] == "HIGH"
    assert audit.classify_cert_error("self-signed certificate")[0] == "MEDIUM"
    assert "hôte" in audit.classify_cert_error("hostname mismatch, doesn't match")[1]
    assert audit.classify_cert_error("some other reason")[0] == "MEDIUM"


def test_cert_expiry_finding():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    soon = (now + timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")
    far = (now + timedelta(days=200)).strftime("%b %d %H:%M:%S %Y GMT")
    gone = (now - timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")

    assert audit.cert_expiry_finding("h", soon, now, 30)["severity"] == "MEDIUM"
    assert audit.cert_expiry_finding("h", gone, now, 30)["severity"] == "HIGH"
    assert audit.cert_expiry_finding("h", far, now, 30) is None
    assert audit.cert_expiry_finding("h", "not-a-date", now, 30) is None


def test_audit_endpoints_synthesizes_events_with_injected_probe():
    events = [
        {"type": "OPEN_TCP_PORT", "data": "www.scc.com:443"},
        {"type": "OPEN_TCP_PORT", "data": "shop.scc.com:80"},
    ]

    def fake_probe(host, scheme, port, timeout, warning_days, max_body=40000):
        if host == "www.scc.com":
            return {
                "url": "https://www.scc.com", "host": host, "status_code": 200,
                "header": {"server": "Apache/2.4.52"},  # no HSTS/CSP -> header findings
                "protocol": "HTTPS", "body": "<html>/wp-content/ jquery-3.6.0.min.js</html>",
                "set_cookie": "PHPSESSID=abc; path=/",
                "findings": [{"type": "FINDING", "severity": "HIGH", "host": host,
                              "description": "Certificat TLS expiré."}],
            }
        return None  # unreachable endpoint is skipped

    new = audit.audit_endpoints(events, "scc.com", get_settings(), probe=fake_probe)
    kinds = [e["type"] for e in new]
    assert kinds.count("URL") == 1 and kinds.count("HTTP_RESPONSE") == 1
    assert kinds.count("PROTOCOL") == 1 and kinds.count("FINDING") == 1
    assert kinds.count("TECHNOLOGY") >= 2  # WordPress, jQuery, PHP fingerprinted

    # The synthesized events drive the existing downstream pipeline end to end.
    report = reports.build_report("scc.com", "deep", events + new)
    assert "https://www.scc.com" in report.urls
    descriptions = [f["description"] for f in report.findings]
    assert "Certificat TLS expiré." in descriptions
    assert any("HSTS" in d for d in descriptions)  # header check ran on our HTTP_RESPONSE
    assert any(c["product"] == "Apache" and c["version"] == "2.4.52"
               for c in report.components)  # version detection ran on our header
    assert any(s["protocol"] == "HTTPS" for s in report.services)  # service now named
    techs = {t["technology"] for t in report.technologies}
    assert any("WordPress" in t for t in techs) and any("jQuery" in t for t in techs)


def test_audit_endpoints_empty_when_no_web_services():
    events = [{"type": "OPEN_TCP_PORT", "data": "mail.scc.com:25"}]
    assert audit.audit_endpoints(events, "scc.com", get_settings(), probe=lambda *a: None) == []


class _FakeResponse:
    def __init__(self, status, headers):
        self.status = status
        self._headers = headers
    def getheaders(self):
        return list(self._headers.items())
    def read(self, n=-1):
        return b""


class _FakeHTTPS:
    """Stands in for http.client.HTTPSConnection; cert comes from the class attr."""
    peercert = {}
    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.context = host, context
        self.sock = type("S", (), {
            "getpeercert": lambda self_: _FakeHTTPS.peercert,
            "cipher": lambda self_: ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256),
        })()
    def request(self, *a, **k):
        # A strict (verifying) context fails when the fake cert is marked expired.
        if self.context and self.context.verify_mode != ssl.CERT_NONE \
                and _FakeHTTPS.peercert.get("_expired"):
            raise ssl.SSLCertVerificationError("certificate has expired")
    def getresponse(self):
        return _FakeResponse(200, {"Server": "nginx/1.18.0", "Strict-Transport-Security": "max-age=1"})
    def close(self):
        pass


def test_probe_endpoint_https_happy_path(monkeypatch):
    not_after = (datetime.now(timezone.utc) + timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
    _FakeHTTPS.peercert = {"notAfter": not_after}
    monkeypatch.setattr(http.client, "HTTPSConnection", _FakeHTTPS)
    monkeypatch.setattr(audit, "weak_tls_finding", lambda *a, **k: None)  # no real socket

    res = audit.probe_endpoint("www.scc.com", "https", 443, timeout=1, warning_days=30)
    assert res["url"] == "https://www.scc.com" and res["status_code"] == 200
    assert res["header"]["server"] == "nginx/1.18.0"
    assert res["header"]["strict_transport_security"] == "max-age=1"
    # Cert expires in 5 days -> a warning finding.
    assert any("expire" in f["description"].lower() for f in res["findings"])


def test_probe_endpoint_https_cert_error_still_gets_headers(monkeypatch):
    _FakeHTTPS.peercert = {"_expired": True}
    monkeypatch.setattr(http.client, "HTTPSConnection", _FakeHTTPS)
    monkeypatch.setattr(audit, "weak_tls_finding", lambda *a, **k: None)  # no real socket

    res = audit.probe_endpoint("bad.scc.com", "https", 443, timeout=1, warning_days=30)
    assert res is not None
    assert any(f["severity"] == "HIGH" and "expiré" in f["description"] for f in res["findings"])
    assert res["header"]["server"] == "nginx/1.18.0"  # fetched over the non-verifying retry


def test_tech_fingerprint_headers_cookies_body():
    from app import tech
    found = tech.fingerprint(
        {"x-powered-by": "Express", "server": "cloudflare"},
        "<html><script src='/wp-includes/js/jquery/jquery-3.6.0.min.js'></script>"
        "<meta name='generator' content='WordPress 6.4.2'></html>",
        "wordpress_logged_in=1; PHPSESSID=x",
    )
    names = {f["name"] for f in found}
    assert {"Express", "Cloudflare", "WordPress", "jQuery", "PHP"} <= names
    jq = next(f for f in found if f["name"] == "jQuery")
    assert jq["version"] == "3.6.0"
    wp = next(f for f in found if f["name"] == "WordPress")
    assert wp.get("version") == "6.4.2"


def test_cipher_finding_flags_weak_only():
    assert audit.cipher_finding("h", ("ECDHE-RSA-RC4-SHA", "TLSv1.2", 128))["severity"] == "MEDIUM"
    assert audit.cipher_finding("h", ("DES-CBC3-SHA", "TLSv1.0", 112))["severity"] == "MEDIUM"  # <128
    assert audit.cipher_finding("h", ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)) is None
    assert audit.cipher_finding("h", None) is None
