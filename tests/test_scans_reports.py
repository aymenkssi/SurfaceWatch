from app import checks, scans, vulns
from app.reports import build_report, render_html, report_to_dict
from app.scans import LEVEL_ARGS, ScanLevel, ScanNotAllowed, build_command, run_scan

import pytest
from pathlib import Path

SAMPLE_EVENTS = [
    {"type": "DNS_NAME", "data": "www.example.fr", "resolved_hosts": ["203.0.113.10"]},
    {"type": "DNS_NAME", "data": "mail.example.fr", "resolved_hosts": ["203.0.113.20"]},
    {"type": "URL", "data": "https://www.example.fr/"},
    {"type": "FINDING", "data": {"host": "old.example.fr", "description": "Dangling CNAME", "severity": "high"}},
    {"type": "FINDING", "data": {"host": "www.example.fr", "description": "Info leak", "severity": "low"}},
]


def test_build_report_aggregates_and_sorts():
    report = build_report("example.fr", "passive", SAMPLE_EVENTS)
    assert list(report.subdomains) == ["mail.example.fr", "www.example.fr"]
    assert report.ip_count == 2
    assert [f["severity"] for f in report.findings] == ["HIGH", "LOW"]


def test_render_html_escapes_content():
    events = [{"type": "FINDING", "data": {"host": "x", "description": "<script>alert(1)</script>"}}]
    html = render_html(build_report("example.fr", "passive", events))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_passive_command_is_passive_only():
    cmd = build_command("example.fr", ScanLevel.PASSIVE, "sw_test", Path("/tmp"))
    assert cmd[cmd.index("-t") + 1] == "example.fr"
    assert "-rf" in cmd and cmd[cmd.index("-rf") + 1] == "passive"


@pytest.mark.parametrize("level", list(ScanLevel))
def test_scans_never_install_deps_at_runtime(level):
    # The worker has no root/sudo: BBOT's runtime installer would abort the scan.
    assert "--no-deps" in build_command("example.fr", level, "sw_test", Path("/tmp"))


def test_active_scan_requires_verification():
    with pytest.raises(ScanNotAllowed):
        run_scan("example.fr", "standard", domain_verified=False)


def test_levels_never_use_aggressive_presets():
    forbidden = {"kitchen-sink", "web-heavy", "webbrute", "paramminer"}
    for args in LEVEL_ARGS.values():
        start = args.index("-p") + 1
        end = next((i for i in range(start, len(args)) if args[i].startswith("-")), len(args))
        assert not forbidden & set(args[start:end])


def test_standard_level_excludes_loud_modules():
    args = LEVEL_ARGS[ScanLevel.STANDARD]
    excluded = set(args[args.index("-ef") + 1:])
    assert {"loud", "invasive", "iis-shortnames", "web-heavy"} <= excluded


def test_run_scan_reads_events_then_deletes_bbot_output(tmp_path, monkeypatch):
    """Fake BBOT binary: no network, just writes an NDJSON file where BBOT would."""
    from app import scans
    from app.config import get_settings

    fake = tmp_path / "fake-bbot"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys, pathlib\n"
        "a = sys.argv\n"
        "d = pathlib.Path(a[a.index('-o') + 1]) / a[a.index('-n') + 1]\n"
        "d.mkdir(parents=True)\n"
        "(d / 'output.json').write_text('\\n'.join(json.dumps(e) for e in [\n"
        "    {'type': 'DNS_NAME', 'data': 'www.example.fr'},\n"
        "    {'type': 'EMAIL_ADDRESS', 'data': 'jane@example.fr'},\n"
        "]) + '\\n')\n"
    )
    fake.chmod(0o755)
    settings = get_settings()
    monkeypatch.setattr(settings, "bbot_bin", str(fake))
    monkeypatch.setattr(settings, "scans_dir", tmp_path / "scans")

    result = scans.run_scan("example.fr", "passive", domain_verified=False)
    assert result.returncode == 0
    assert result.events == [{"type": "DNS_NAME", "data": "www.example.fr"}]
    assert list((tmp_path / "scans").iterdir()) == []


def test_standard_level_keeps_http_response_in_output():
    """HTTP_RESPONSE is omitted by BBOT by default; the active level must re-include it
    (we need the headers) while still dropping the other noisy types."""
    args = LEVEL_ARGS[ScanLevel.STANDARD]
    cfg = args[args.index("-c") + 1]
    assert cfg.startswith("omit_event_types=")
    assert "HTTP_RESPONSE" not in cfg
    assert "RAW_TEXT" in cfg


def test_load_events_strips_http_response_body(tmp_path):
    from app.scans import load_events
    import json

    path = tmp_path / "output.json"
    path.write_text(json.dumps({
        "type": "HTTP_RESPONSE",
        "data": {"url": "https://x/", "host": "x", "header": {"server": "nginx"},
                 "body": "secret page body", "raw_header": "HTTP/1.1 200"},
    }) + "\n")
    events = load_events(path)
    assert events[0]["data"].get("body") is None
    assert events[0]["data"]["header"] == {"server": "nginx"}


def test_email_harvesting_module_is_excluded_at_every_level():
    for args in LEVEL_ARGS.values():
        assert "hunterio" in args[args.index("-em") + 1:]


def test_advanced_level_enables_surface_bruteforce_only():
    args = LEVEL_ARGS[ScanLevel.ADVANCED]
    modules = args[args.index("-m") + 1:args.index("-ef")]
    assert set(modules) == {"dnsbrute", "webbrute"}  # subdomain + web-directory brute-force
    excluded = set(args[args.index("-ef") + 1:args.index("-em")])
    # No credential brute-force (invasive), no shortname/paramminer noise.
    assert {"invasive", "iis-shortnames", "web-heavy", "web-paramminer"} <= excluded


def test_advanced_scan_requires_verification():
    with pytest.raises(ScanNotAllowed):
        run_scan("example.fr", "advanced", domain_verified=False)


def test_advanced_level_uses_a_longer_timeout():
    from app.config import get_settings
    from app.scans import timeout_for

    s = get_settings()
    assert timeout_for(ScanLevel.ADVANCED) == s.advanced_scan_timeout_seconds
    assert timeout_for(ScanLevel.PASSIVE) == s.scan_timeout_seconds


def test_deep_level_enables_portscan_and_fingerprintx():
    args = LEVEL_ARGS[ScanLevel.DEEP]
    modules = set(args[args.index("-m") + 1:args.index("-ef")])
    assert {"portscan", "fingerprintx"} <= modules
    # Deep allows the loud flag (portscan is loud) but still forbids the aggressive ones.
    excluded = set(args[args.index("-ef") + 1:args.index("-em")])
    assert {"invasive", "iis-shortnames", "web-heavy", "web-paramminer"} <= excluded
    assert "loud" not in excluded


def test_deep_level_is_active_and_consent_gated():
    assert ScanLevel.DEEP in scans.ACTIVE_LEVELS
    assert ScanLevel.DEEP in scans.CONSENT_LEVELS


def test_deep_scan_requires_verification():
    with pytest.raises(ScanNotAllowed):
        run_scan("example.fr", "deep", domain_verified=False)


def test_component_versions_from_http_server_header():
    events = [{
        "type": "HTTP_RESPONSE",
        "data": {"url": "https://www.example.fr/", "host": "www.example.fr",
                 "header": {"server": "Apache/2.4.52 (Debian) OpenSSL/1.1.1n",
                            "x_powered_by": "PHP/7.4.3"}},
    }]
    comps = {(c["product"], c["version"]) for c in checks.component_versions(events)}
    assert ("Apache", "2.4.52") in comps
    assert ("OpenSSL", "1.1.1n") in comps
    assert ("PHP", "7.4.3") in comps


def test_component_versions_from_ssh_banner():
    events = [{"type": "PROTOCOL",
               "data": {"host": "ssh.example.fr", "port": 22, "protocol": "SSH",
                        "banner": "SSH-2.0-OpenSSH_8.9p1 Debian-3"}}]
    comps = checks.component_versions(events)
    assert {"host": "ssh.example.fr", "product": "OpenSSH",
            "version": "8.9p1", "source": "banner"} in comps


def test_cpe_for_maps_known_products_only():
    assert vulns.cpe_for("OpenSSH", "8.9p1") == "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*"
    assert vulns.cpe_for("Apache", "2.4.52") == "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"
    assert vulns.cpe_for("SomeUnknownThing", "1.0") is None


def test_assess_components_flags_cves_and_marks_kev():
    components = [{"host": "ssh.example.fr", "product": "OpenSSH", "version": "8.9p1",
                  "source": "banner"}]

    def fake_nvd(cpe):
        assert "openssh" in cpe
        return [{"id": "CVE-2024-6387", "cvss": 8.1, "severity": "HIGH", "summary": "regreSSHion"},
                {"id": "CVE-2023-0001", "cvss": 5.0, "severity": "MEDIUM", "summary": "x"}]

    findings = vulns.assess_components(components, kev_ids={"CVE-2024-6387"}, nvd_lookup=fake_nvd)
    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "VULNERABILITY" and f["host"] == "ssh.example.fr"
    assert f["severity"] == "CRITICAL"  # a KEV hit escalates
    assert f["kev"] is True
    assert "CVE-2024-6387" in f["description"] and "CISA KEV" in f["description"]


def test_assess_components_skips_unmapped_and_cve_free():
    comps = [
        {"host": "h", "product": "Mystery", "version": "1.0", "source": "http-header"},
        {"host": "h", "product": "Apache", "version": "2.4.99", "source": "http-header"},
    ]
    findings = vulns.assess_components(comps, kev_ids=set(), nvd_lookup=lambda cpe: [])
    assert findings == []


def test_vulnerability_events_fold_into_report_findings():
    events = [{"type": "VULNERABILITY",
               "data": {"severity": "critical", "host": "ssh.example.fr",
                        "description": "OpenSSH 8.9p1 : 1 CVE connue"}}]
    report = build_report("example.fr", "deep", events)
    assert any(f["type"] == "VULNERABILITY" and f["severity"] == "CRITICAL"
               for f in report.findings)
    assert report_to_dict(report)["summary"]["vulnerabilities"] == 1


def test_report_exposes_components():
    events = [{"type": "HTTP_RESPONSE",
               "data": {"url": "https://x/", "host": "x", "header": {"server": "nginx/1.18.0"}}}]
    report = build_report("example.fr", "standard", events)
    assert {"host": "x", "product": "nginx", "version": "1.18.0", "source": "http-header"} \
        in report.components
    assert report_to_dict(report)["summary"]["components"] == 1


def test_build_report_surfaces_services():
    events = [
        {"type": "OPEN_TCP_PORT", "data": "mail.example.fr:25"},
        {"type": "PROTOCOL", "data": {"host": "mail.example.fr", "port": 25, "protocol": "SMTP"}},
        {"type": "OPEN_TCP_PORT", "data": "www.example.fr:443"},
    ]
    report = build_report("example.fr", "deep", events)
    by_host = {(s["host"], s["port"]): s["protocol"] for s in report.services}
    assert by_host[("mail.example.fr", 25)] == "SMTP"
    assert ("www.example.fr", 443) in by_host
