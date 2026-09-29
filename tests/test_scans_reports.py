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
        assert not forbidden & set(args)
