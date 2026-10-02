from app import checks
from app.reports import build_report


def _http_event(url, host, headers):
    return {"type": "HTTP_RESPONSE", "data": {"url": url, "host": host, "header": headers}}


def test_http_findings_flags_missing_headers_once_per_host():
    events = [_http_event("https://www.example.fr/", "www.example.fr", {})]
    findings = checks.http_response_findings(events)
    descriptions = " ".join(f["description"] for f in findings)
    assert "HSTS" in descriptions and "CSP" in descriptions
    # One representative response per host: six missing-header findings, no duplicates.
    assert len(findings) == len(checks.SECURITY_HEADERS)


def test_http_findings_no_noise_when_headers_present():
    headers = {k: "set" for k, _, _ in checks.SECURITY_HEADERS}
    events = [_http_event("https://www.example.fr/", "www.example.fr", headers)]
    assert checks.http_response_findings(events) == []


def test_http_findings_flags_cleartext_http():
    events = [_http_event("http://www.example.fr/", "www.example.fr",
                          {k: "set" for k, _, _ in checks.SECURITY_HEADERS})]
    findings = checks.http_response_findings(events)
    assert any("clair (HTTP)" in f["description"] and f["severity"] == "MEDIUM" for f in findings)


def test_advertised_technologies_from_headers():
    events = [_http_event("https://www.example.fr/", "www.example.fr",
                          {"server": "Apache/2.4.6", "x_powered_by": "PHP/7.4.30"})]
    techs = {t["technology"] for t in checks.advertised_technologies(events)}
    assert techs == {"Apache/2.4.6", "PHP/7.4.30"}


def test_mail_config_findings_when_all_missing(monkeypatch):
    monkeypatch.setattr(checks, "_txt_records", lambda name, timeout=5.0: [])
    findings = checks.mail_config_findings("example.fr")
    kinds = " ".join(f["description"] for f in findings)
    assert "SPF" in kinds and "DMARC" in kinds and "MTA-STS" in kinds


def test_mail_config_findings_clean_when_configured(monkeypatch):
    records = {
        "example.fr": ["v=spf1 include:_spf.example.fr -all"],
        "_dmarc.example.fr": ["v=DMARC1; p=reject"],
        "_mta-sts.example.fr": ["v=STSv1; id=1"],
    }
    monkeypatch.setattr(checks, "_txt_records", lambda name, timeout=5.0: records.get(name, []))
    assert checks.mail_config_findings("example.fr") == []


def test_build_report_surfaces_technologies_and_http_findings():
    events = [
        {"type": "DNS_NAME", "data": "www.example.fr", "resolved_hosts": ["203.0.113.1"]},
        {"type": "TECHNOLOGY", "data": {"host": "www.example.fr", "technology": "nginx"}},
        _http_event("https://www.example.fr/", "www.example.fr", {"server": "Apache/2.4.6"}),
    ]
    report = build_report("example.fr", "standard", events)
    names = {t["technology"] for t in report.technologies}
    assert {"nginx", "Apache/2.4.6"} <= names
    assert any("HSTS" in f["description"] for f in report.findings)
