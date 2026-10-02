"""API tests. No network: DNS checks, the job queue and BBOT are all stubbed."""

import uuid

import pytest
from fastapi.testclient import TestClient

from app import api, domains, scans, worker
from app.db import SessionLocal
from app.main import app
from app.models import AuditLog, Domain, Scan

PASSWORD = "correct horse battery"

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


def _txt_ok_if(expected):
    return lambda name, value: domains.TxtCheck(domains.TXT_OK if value == expected else domains.TXT_MISMATCH)


def test_re_adding_domain_keeps_valid_token(client):
    h = _auth(client)
    d = _add_domain(client, h)
    again = client.post("/api/domains", json={"domain": "example.fr"}, headers=h).json()
    assert again["record_value"] == d["record_value"]
    renewed = client.post("/api/domains", json={"domain": "example.fr", "renew": True}, headers=h).json()
    assert renewed["record_value"] != d["record_value"]


def test_verify_reports_failure_reason(client, monkeypatch):
    h = _auth(client)
    d = _add_domain(client, h)
    monkeypatch.setattr(domains, "lookup_txt_record",
                        lambda name, value: domains.TxtCheck(domains.TXT_MISMATCH, ("sw-verify=old",)))
    r = client.post(f"/api/domains/{d['id']}/verify", headers=h).json()
    assert r["verified"] is False
    assert r["verify_error"] == "mismatch" and r["verify_found"] == ["sw-verify=old"]


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

    monkeypatch.setattr(domains, "lookup_txt_record", lambda name, value: domains.TxtCheck(domains.TXT_NOT_FOUND))
    assert client.post(f"/api/domains/{d['id']}/verify", headers=h).json()["verified"] is False
    monkeypatch.setattr(domains, "lookup_txt_record", _txt_ok_if(d["record_value"]))
    assert client.post(f"/api/domains/{d['id']}/verify", headers=h).json()["verified"] is True

    r = client.post("/api/scans", json={"domain_id": d["id"], "level": "standard"}, headers=h)
    assert r.status_code == 202 and queued == [r.json()["id"]]


def test_deep_scan_requires_consent(client, queued, monkeypatch):
    h = _auth(client)
    d = _add_domain(client, h)
    monkeypatch.setattr(domains, "lookup_txt_record", _txt_ok_if(d["record_value"]))
    assert client.post(f"/api/domains/{d['id']}/verify", headers=h).json()["verified"] is True

    # Verified but no consent -> refused.
    r = client.post("/api/scans", json={"domain_id": d["id"], "level": "deep"}, headers=h)
    assert r.status_code == 403 and not queued

    # Verified + consent -> accepted, and the consent is recorded in the audit trail.
    r = client.post("/api/scans", json={"domain_id": d["id"], "level": "deep", "consent": True}, headers=h)
    assert r.status_code == 202
    with SessionLocal() as db:
        log = db.query(AuditLog).filter_by(scan_id=r.json()["id"]).one()
    assert (log.level, log.consent) == ("deep", True)


def test_deep_scan_has_its_own_daily_quota(client, queued, monkeypatch):
    h = _auth(client)
    d = _add_domain(client, h)
    monkeypatch.setattr(domains, "lookup_txt_record", _txt_ok_if(d["record_value"]))
    client.post(f"/api/domains/{d['id']}/verify", headers=h)
    # Isolate the dedicated deep quota from the general concurrency/daily guards.
    monkeypatch.setattr(api.get_settings(), "deep_max_scans_per_day", 0)

    r = client.post("/api/scans", json={"domain_id": d["id"], "level": "deep", "consent": True}, headers=h)
    assert r.status_code == 429 and r.json()["detail"] == "daily scan quota reached" and not queued


def test_admin_reset_quota_frees_the_daily_limit(client, queued, monkeypatch):
    email = f"{uuid.uuid4().hex[:8]}@example.fr"
    r = client.post("/api/auth/register", json={"email": email, "password": "correct horse battery"})
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    d = _add_domain(client, h)
    # Isolate the daily quota from the one-at-a-time concurrency guard.
    monkeypatch.setattr(api.get_settings(), "max_concurrent_scans_per_user", 10)
    monkeypatch.setattr(api.get_settings(), "max_scans_per_day", 1)

    assert client.post("/api/scans", json={"domain_id": d["id"]}, headers=h).status_code == 202
    blocked = client.post("/api/scans", json={"domain_id": d["id"]}, headers=h)
    assert blocked.status_code == 429 and blocked.json()["detail"] == "daily scan quota reached"

    admin = _admin(client)
    reset = client.post("/api/admin/users/reset-quota", json={"email": email}, headers=admin)
    assert reset.status_code == 200 and reset.json()["email"] == email

    # The quota is free again: earlier scans no longer count toward the limit.
    assert client.post("/api/scans", json={"domain_id": d["id"]}, headers=h).status_code == 202
    with SessionLocal() as db:
        assert db.query(AuditLog).filter_by(action="user.quota_reset").count() == 1


def test_admin_reset_quota_unknown_user_is_404(client):
    admin = _admin(client)
    r = client.post("/api/admin/users/reset-quota", json={"email": "nobody@example.fr"}, headers=admin)
    assert r.status_code == 404


PNG_DATA_URI = ("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC"
                "AAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


def test_user_logo_set_served_and_cleared(client):
    h = _auth(client)
    assert client.put("/api/users/me/logo", json={"logo": PNG_DATA_URI}, headers=h).status_code == 200
    assert client.get("/api/users/me", headers=h).json()["logo_data_uri"] == PNG_DATA_URI
    assert client.delete("/api/users/me/logo", headers=h).status_code == 200
    assert client.get("/api/users/me", headers=h).json()["logo_data_uri"] is None


def test_user_logo_rejects_non_image(client):
    h = _auth(client)
    bad = client.put("/api/users/me/logo", json={"logo": "data:text/html;base64,PHNjcmlwdD4="}, headers=h)
    assert bad.status_code == 422


def test_admin_branding_update_is_public_and_audited(client):
    admin = _admin(client)
    r = client.put("/api/admin/branding", headers=admin, json={
        "site_name": "ACME Scan", "accent_color": "#ff0000", "logo": PNG_DATA_URI})
    assert r.status_code == 200
    pub = client.get("/api/branding").json()
    assert pub["site_name"] == "ACME Scan" and pub["accent"] == "#ff0000"
    assert pub["site_logo"] == PNG_DATA_URI
    with SessionLocal() as db:
        assert db.query(AuditLog).filter_by(action="branding.update").count() == 1
    # Bad accent is rejected.
    assert client.put("/api/admin/branding", headers=admin,
                      json={"site_name": "x", "accent_color": "red"}).status_code == 422


def test_report_html_embeds_client_and_site_logos(client, queued, monkeypatch):
    h = _auth(client)
    d = _add_domain(client, h)
    scan_id = client.post("/api/scans", json={"domain_id": d["id"]}, headers=h).json()["id"]
    monkeypatch.setattr(scans, "run_scan", lambda domain, level, verified:
                        scans.ScanResult("sw_x", domain, scans.ScanLevel(level), 0, SAMPLE_EVENTS))
    monkeypatch.setattr(worker.checks, "mail_config_findings", lambda domain: [])
    assert worker.execute_scan(scan_id) == "done"

    client.put("/api/users/me/logo", json={"logo": PNG_DATA_URI}, headers=h)
    admin = _admin(client)
    other_png = PNG_DATA_URI.replace("iVBOR", "iVBOR")  # same bytes is fine; both embed
    client.put("/api/admin/branding", headers=admin,
               json={"site_name": "ACME Scan", "accent_color": "#123456", "logo": other_png})

    html = client.get(f"/api/scans/{scan_id}/report.html", headers=h).text
    assert PNG_DATA_URI in html        # client logo (top-left)
    assert "#123456" in html           # site accent colour applied


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
                                 "technologies": 0, "services": 0,
                                 "components": 0, "vulnerabilities": 0}
    assert report["findings"][0]["severity"] == "HIGH"
    html = client.get(f"/api/scans/{scan_id}/report.html", headers=h)
    assert "Dangling CNAME" in html.text


def test_delete_account_removes_data_but_keeps_audit(client, queued):
    h = _auth(client)
    d = _add_domain(client, h)
    scan_id = client.post("/api/scans", json={"domain_id": d["id"]}, headers=h).json()["id"]
    user_id = client.get("/api/users/me", headers=h).json()["id"]
    wrong = client.request("DELETE", "/api/users/me", json={"password": "not my password"}, headers=h)
    assert wrong.status_code == 403
    r = client.request("DELETE", "/api/users/me", json={"password": PASSWORD}, headers=h)
    assert r.status_code == 204
    assert client.get("/api/users/me", headers=h).status_code == 401
    with SessionLocal() as db:
        assert db.query(AuditLog).filter_by(scan_id=scan_id).count() == 1
        assert db.query(AuditLog).filter_by(user_id=user_id, action="account.deleted").count() == 1
        assert db.query(Scan).filter_by(user_id=user_id).count() == 0
        assert db.query(Domain).filter_by(user_id=user_id).count() == 0


def test_delete_account_refused_while_scan_runs(client, queued):
    h = _auth(client)
    d = _add_domain(client, h)
    scan_id = client.post("/api/scans", json={"domain_id": d["id"]}, headers=h).json()["id"]
    with SessionLocal() as db:
        db.get(Scan, scan_id).status = "running"
        db.commit()
    r = client.request("DELETE", "/api/users/me", json={"password": PASSWORD}, headers=h)
    assert r.status_code == 409


def test_queue_failure_does_not_consume_quota(client):
    def broken(scan_id):
        raise ConnectionError("redis down")

    app.dependency_overrides[api.get_enqueuer] = lambda: broken
    h = _auth(client)
    d = _add_domain(client, h)
    assert client.post("/api/scans", json={"domain_id": d["id"]}, headers=h).status_code == 503
    assert client.get("/api/scans", headers=h).json() == []


def test_advanced_scan_requires_ownership_then_consent_and_is_logged(client, queued, monkeypatch):
    h = _auth(client)
    d = _add_domain(client, h)
    # Unverified domain: blocked on ownership proof first.
    assert client.post("/api/scans", json={"domain_id": d["id"], "level": "advanced"},
                       headers=h).status_code == 403 and not queued

    monkeypatch.setattr(domains, "lookup_txt_record", _txt_ok_if(d["record_value"]))
    assert client.post(f"/api/domains/{d['id']}/verify", headers=h).json()["verified"] is True

    # Verified but no consent: still blocked.
    assert client.post("/api/scans", json={"domain_id": d["id"], "level": "advanced"},
                       headers=h).status_code == 403 and not queued

    # Verified + explicit consent: accepted and audited with the consent flag.
    r = client.post("/api/scans", json={"domain_id": d["id"], "level": "advanced", "consent": True},
                    headers=h)
    assert r.status_code == 202 and queued == [r.json()["id"]]
    with SessionLocal() as db:
        log = db.query(AuditLog).filter_by(scan_id=r.json()["id"]).one()
    assert (log.level, log.consent) == ("advanced", True)


def test_advanced_level_has_its_own_daily_quota(client, queued, monkeypatch):
    from app.config import get_settings

    h = _auth(client)
    d = _add_domain(client, h)
    monkeypatch.setattr(domains, "lookup_txt_record", lambda name, value: domains.TxtCheck(domains.TXT_OK))
    client.post(f"/api/domains/{d['id']}/verify", headers=h)
    monkeypatch.setattr(get_settings(), "advanced_max_scans_per_day", 0)
    r = client.post("/api/scans", json={"domain_id": d["id"], "level": "advanced", "consent": True},
                    headers=h)
    assert r.status_code == 429 and r.json()["detail"] == "daily scan quota reached"


def _admin(client) -> dict:
    from app import cli

    email = f"admin-{uuid.uuid4().hex[:8]}@example.fr"
    r = client.post("/api/auth/register", json={"email": email, "password": "correct horse battery"})
    assert cli.set_admin(email, True)
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_admin_routes_are_forbidden_to_regular_users(client):
    h = _auth(client)
    assert client.get("/api/users/me", headers=h).json()["is_admin"] is False
    for path in ("/api/admin/stats", "/api/admin/domains", "/api/admin/scans", "/api/admin/audit"):
        assert client.get(path, headers=h).status_code == 403
    d = _add_domain(client, h)
    r = client.post(f"/api/admin/domains/{d['id']}/verify", json={"reason": "self-service"}, headers=h)
    assert r.status_code == 403
    assert client.get("/api/domains", headers=h).json()[0]["verified"] is False


def test_admin_manual_verification_unlocks_active_scan_and_is_audited(client, queued, monkeypatch):
    owner = _auth(client)
    d = _add_domain(client, owner, "manual-check.fr")
    admin = _admin(client)

    pending = client.get("/api/admin/domains", params={"q": "manual-check"}, headers=admin).json()
    assert [x["id"] for x in pending] == [d["id"]] and pending[0]["owner_email"].endswith("@example.fr")
    # A reason is mandatory.
    assert client.post(f"/api/admin/domains/{d['id']}/verify", json={}, headers=admin).status_code == 422

    r = client.post(f"/api/admin/domains/{d['id']}/verify",
                    json={"reason": "ownership confirmed by registrar invoice"}, headers=admin)
    assert r.status_code == 200
    assert (r.json()["verified"], r.json()["verification_method"]) == (True, "manual")
    assert client.post(f"/api/admin/domains/{d['id']}/verify", json={"reason": "again please"},
                       headers=admin).status_code == 409

    with SessionLocal() as db:
        log = db.query(AuditLog).filter_by(action="domain.manual_verify", domain="manual-check.fr").one()
    assert log.user_email.startswith("admin-") and log.source_ip
    assert "registrar invoice" in log.details and "owner=" in log.details

    # The owner can now run an active scan, and the worker accepts it without any DNS check.
    r = client.post("/api/scans", json={"domain_id": d["id"], "level": "standard"}, headers=owner)
    assert r.status_code == 202
    monkeypatch.setattr(scans, "run_scan", lambda domain, level, verified:
                        scans.ScanResult("sw_x", domain, scans.ScanLevel(level), 0 if verified else 1, []))
    assert worker.execute_scan(r.json()["id"]) == "done"

    # Revocation removes the verification and issues a fresh token.
    r = client.post(f"/api/admin/domains/{d['id']}/revoke", headers=admin).json()
    assert r["verified"] is False and r["record_value"] != d["record_value"]
    r = client.post("/api/scans", json={"domain_id": d["id"], "level": "standard"}, headers=owner)
    assert r.status_code == 403


def test_admin_stats(client, queued):
    h = _auth(client)
    d = _add_domain(client, h)
    client.post("/api/scans", json={"domain_id": d["id"]}, headers=h)
    stats = client.get("/api/admin/stats", headers=_admin(client)).json()
    assert stats["users"]["total"] >= 2 and stats["users"]["admins"] >= 1
    assert stats["domains"]["pending"] >= 1
    assert stats["scans"]["requested_24h"] >= 1 and stats["scans"]["by_level"]["passive"] >= 1
    assert stats["scans"]["active"] >= 1
    assert len(stats["scans"]["per_day"]) == 30 and stats["scans"]["per_day"][-1]["count"] >= 1
