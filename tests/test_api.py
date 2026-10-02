"""API tests. No network: DNS checks, the job queue and BBOT are all stubbed."""

import uuid

import pytest
from fastapi.testclient import TestClient

from app import api, domains, scans, worker
from app.db import SessionLocal
from app.main import app
from app.models import AuditLog

SAMPLE_EVENTS = [
    {"type": "DNS_NAME", "data": "www.example.fr", "resolved_hosts": ["203.0.113.10"]},
    {"type": "FINDING", "data": {"host": "old.example.fr", "description": "Dangling CNAME",
                                 "severity": "high"}},
]


@pytest.fixture
def queued():
    jobs = []
    app.dependency_overrides[api.get_enqueuer] = lambda: (lambda scan_id: jobs.append(scan_id) or "job-1")
    yield jobs
    app.dependency_overrides.clear()


@pytest.fixture
def client(queued):
    with TestClient(app) as c:
        yield c


def _auth(client) -> dict:
    email = f"{uuid.uuid4().hex[:8]}@example.fr"
    r = client.post("/api/auth/register", json={"email": email, "password": "correct horse battery"})
    assert r.status_code == 201
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _add_domain(client, headers, name="example.fr") -> dict:
    r = client.post("/api/domains", json={"domain": name}, headers=headers)
    assert r.status_code == 201
    return r.json()


def test_register_login_me(client):
    email = f"{uuid.uuid4().hex[:8]}@example.fr"
    client.post("/api/auth/register", json={"email": email, "password": "correct horse battery"})
    assert client.post("/api/auth/register",
                       json={"email": email, "password": "correct horse battery"}).status_code == 409
    assert client.post("/api/auth/login", json={"email": email, "password": "wrong password!"}).status_code == 401
    token = client.post("/api/auth/login",
                        json={"email": email, "password": "correct horse battery"}).json()["access_token"]
    me = client.get("/api/users/me", headers={"Authorization": f"Bearer {token}"})
    assert me.json()["email"] == email


def test_endpoints_require_auth(client):
    assert client.get("/api/domains").status_code == 401
    assert client.get("/api/scans", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_domain_is_normalized_and_rejects_garbage(client):
    h = _auth(client)
    d = _add_domain(client, h, "https://WWW.Example.fr/login")
    assert d["name"] == "example.fr"
    assert d["record_name"] == "_surfacewatch-verify.example.fr"
    assert client.post("/api/domains", json={"domain": "example.fr; rm -rf /"}, headers=h).status_code == 400


def test_domains_are_isolated_between_users(client):
    d = _add_domain(client, _auth(client))
    other = _auth(client)
    assert client.post(f"/api/domains/{d['id']}/verify", headers=other).status_code == 404
    assert client.post("/api/scans", json={"domain_id": d["id"]}, headers=other).status_code == 404


def test_active_scan_requires_verified_domain(client, queued, monkeypatch):
    h = _auth(client)
    d = _add_domain(client, h)
    r = client.post("/api/scans", json={"domain_id": d["id"], "level": "standard"}, headers=h)
    assert r.status_code == 403 and not queued

    monkeypatch.setattr(domains, "check_txt_record", lambda name, value: False)
    assert client.post(f"/api/domains/{d['id']}/verify", headers=h).json()["verified"] is False
    monkeypatch.setattr(domains, "check_txt_record", lambda name, value: value == d["record_value"])
    assert client.post(f"/api/domains/{d['id']}/verify", headers=h).json()["verified"] is True

    r = client.post("/api/scans", json={"domain_id": d["id"], "level": "standard"}, headers=h)
    assert r.status_code == 202 and queued == [r.json()["id"]]


def test_deep_scan_requires_consent(client, queued, monkeypatch):
    h = _auth(client)
    d = _add_domain(client, h)
    monkeypatch.setattr(domains, "check_txt_record", lambda name, value: value == d["record_value"])
    assert client.post(f"/api/domains/{d['id']}/verify", headers=h).json()["verified"] is True

    # Verified but no consent -> refused.
    r = client.post("/api/scans", json={"domain_id": d["id"], "level": "deep"}, headers=h)
    assert r.status_code == 403 and not queued

    # Verified + consent -> accepted, and the consent is written to the audit trail.
    r = client.post("/api/scans", json={"domain_id": d["id"], "level": "deep", "consent": True}, headers=h)
    assert r.status_code == 202
    with SessionLocal() as db:
        actions = {a.action for a in db.query(AuditLog).filter_by(scan_id=r.json()["id"])}
    assert "scan.active_consent" in actions


def test_deep_scan_has_its_own_daily_quota(client, queued, monkeypatch):
    h = _auth(client)
    d = _add_domain(client, h)
    monkeypatch.setattr(domains, "check_txt_record", lambda name, value: value == d["record_value"])
    client.post(f"/api/domains/{d['id']}/verify", headers=h)
    # Isolate the dedicated deep quota from the general concurrency/daily guards.
    monkeypatch.setattr(api.get_settings(), "deep_max_scans_per_day", 0)

    r = client.post("/api/scans", json={"domain_id": d["id"], "level": "deep", "consent": True}, headers=h)
    assert r.status_code == 429 and "deep" in r.json()["detail"] and not queued


def test_raw_bbot_options_are_rejected(client):
    h = _auth(client)
    d = _add_domain(client, h)
    r = client.post("/api/scans", json={"domain_id": d["id"], "level": "kitchen-sink"}, headers=h)
    assert r.status_code == 422


def test_scan_is_audited_and_rate_limited(client, queued):
    h = _auth(client)
    d = _add_domain(client, h)
    r = client.post("/api/scans", json={"domain_id": d["id"]}, headers=h)
    assert r.status_code == 202
    scan_id = r.json()["id"]
    # Only one scan at a time per user.
    assert client.post("/api/scans", json={"domain_id": d["id"]}, headers=h).status_code == 429

    with SessionLocal() as db:
        log = db.query(AuditLog).filter_by(scan_id=scan_id).one()
    assert (log.domain, log.level, log.action) == ("example.fr", "passive", "scan.requested")
    assert log.source_ip and log.user_email.endswith("@example.fr")


def test_worker_stores_events_and_report_is_served(client, queued, monkeypatch):
    h = _auth(client)
    d = _add_domain(client, h)
    scan_id = client.post("/api/scans", json={"domain_id": d["id"]}, headers=h).json()["id"]
    assert client.get(f"/api/scans/{scan_id}/report", headers=h).status_code == 409

    calls = []

    def fake_run_scan(domain, level, verified):
        calls.append((domain, level, verified))
        return scans.ScanResult("sw_x", domain, scans.ScanLevel(level), 0, SAMPLE_EVENTS)

    monkeypatch.setattr(scans, "run_scan", fake_run_scan)
    # Keep the suite hermetic: no live DNS for the passive mail checks.
    monkeypatch.setattr(worker.checks, "mail_config_findings", lambda domain: [])
    assert worker.execute_scan(scan_id) == "done"
    assert calls == [("example.fr", "passive", False)]

    report = client.get(f"/api/scans/{scan_id}/report", headers=h).json()
    assert report["summary"] == {"subdomains": 1, "ips": 1, "urls": 0, "findings": 1,
                                 "technologies": 0, "services": 0}
    assert report["findings"][0]["severity"] == "HIGH"
    html = client.get(f"/api/scans/{scan_id}/report.html", headers=h)
    assert "Dangling CNAME" in html.text


def test_delete_account_removes_data_but_keeps_audit(client, queued):
    h = _auth(client)
    d = _add_domain(client, h)
    scan_id = client.post("/api/scans", json={"domain_id": d["id"]}, headers=h).json()["id"]
    assert client.delete("/api/users/me", headers=h).status_code == 204
    assert client.get("/api/users/me", headers=h).status_code == 401
    with SessionLocal() as db:
        assert db.query(AuditLog).filter_by(scan_id=scan_id).count() == 1


def test_queue_failure_does_not_consume_quota(client):
    def broken(scan_id):
        raise ConnectionError("redis down")

    app.dependency_overrides[api.get_enqueuer] = lambda: broken
    h = _auth(client)
    d = _add_domain(client, h)
    assert client.post("/api/scans", json={"domain_id": d["id"]}, headers=h).status_code == 503
    assert client.get("/api/scans", headers=h).json() == []
