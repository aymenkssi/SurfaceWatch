from app.reports import build_report, render_html
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
