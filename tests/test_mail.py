"""Password reset and e-mail notifications. SMTP is replaced by an in-memory outbox."""

import re
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app import api, mailer, scans, worker
from app.config import get_settings
from app.db import SessionLocal, init_db
from app.main import app
from app.models import AuditLog, PasswordResetToken, Scan, User, utcnow

PASSWORD = "correct horse battery"


@pytest.fixture
def outbox(monkeypatch):
    sent = []
    settings = get_settings()
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.test")
    monkeypatch.setattr(settings, "smtp_from", "noreply@example.test")
    monkeypatch.setattr(settings, "public_url", "https://app.example.test")
    monkeypatch.setattr(mailer, "_transport", sent.append)
    return sent


@pytest.fixture
def client():
    app.dependency_overrides[api.get_enqueuer] = lambda: (lambda scan_id: "job-1")
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def _register(client) -> tuple[str, dict]:
    email = f"{uuid.uuid4().hex[:8]}@example.fr"
    r = client.post("/api/auth/register", json={"email": email, "password": PASSWORD})
    return email, {"Authorization": f"Bearer {r.json()['access_token']}"}


def _token_from(msg) -> str:
    return re.search(r"reset-password\?token=(\S+)", msg.get_content()).group(1)


def test_email_features_disabled_without_smtp(client):
    assert client.get("/api/features").json() == {"email": False}
    r = client.post("/api/auth/forgot-password", json={"email": "a@example.fr"})
    assert r.status_code == 503
    assert mailer.send("a@example.fr", "x", "y") is False


def test_password_reset_flow(client, outbox):
    assert client.get("/api/features").json() == {"email": True}
    email, h = _register(client)
    assert client.post("/api/auth/forgot-password", json={"email": email.upper()}).status_code == 202
    assert len(outbox) == 1 and outbox[0]["To"] == email
    token = _token_from(outbox[0])
    assert "https://app.example.test/reset-password?token=" in outbox[0].get_content()

    r = client.post("/api/auth/reset-password", json={"token": token, "password": "a brand new password"})
    assert r.status_code == 204
    assert "modifié" in outbox[-1]["Subject"]
    # Single use, old password gone, sessions opened before the reset are closed.
    r = client.post("/api/auth/reset-password", json={"token": token, "password": "another password!"})
    assert r.status_code == 400
    assert client.post("/api/auth/login", json={"email": email, "password": PASSWORD}).status_code == 401
    assert client.post("/api/auth/login",
                       json={"email": email, "password": "a brand new password"}).status_code == 200
    with SessionLocal() as db:
        user = db.query(User).filter_by(email=email).one()
        user.password_changed_at = utcnow() + timedelta(seconds=5)
        db.commit()
        actions = {a.action for a in db.query(AuditLog).filter_by(user_id=user.id)}
    assert {"account.password_reset_requested", "account.password_reset"} <= actions
    assert client.get("/api/users/me", headers=h).status_code == 401


def test_reset_unknown_email_is_silent(client, outbox):
    r = client.post("/api/auth/forgot-password", json={"email": "nobody@example.fr"})
    assert r.status_code == 202
    assert outbox == []


def test_only_latest_reset_link_works_and_requests_are_capped(client, outbox):
    email, _ = _register(client)
    for _ in range(get_settings().password_reset_max_per_hour + 2):
        client.post("/api/auth/forgot-password", json={"email": email})
    assert len(outbox) == get_settings().password_reset_max_per_hour
    first, last = _token_from(outbox[0]), _token_from(outbox[-1])
    assert client.post("/api/auth/reset-password",
                       json={"token": first, "password": "a brand new password"}).status_code == 400
    assert client.post("/api/auth/reset-password",
                       json={"token": last, "password": "a brand new password"}).status_code == 204


def test_expired_reset_link_is_refused(client, outbox):
    email, _ = _register(client)
    client.post("/api/auth/forgot-password", json={"email": email})
    token = _token_from(outbox[0])
    with SessionLocal() as db:
        for row in db.query(PasswordResetToken):
            row.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    r = client.post("/api/auth/reset-password", json={"token": token, "password": "a brand new password"})
    assert r.status_code == 400


def test_scan_finished_notification_and_opt_out(client, outbox, monkeypatch):
    monkeypatch.setattr(scans, "run_scan", lambda domain, level, verified: scans.ScanResult(
        scan_id="x", domain=domain, level=level, returncode=0))
    email, h = _register(client)
    d = client.post("/api/domains", json={"domain": "example.fr"}, headers=h).json()

    scan_id = client.post("/api/scans", json={"domain_id": d["id"]}, headers=h).json()["id"]
    assert worker.execute_scan(scan_id) == "done"
    assert outbox[-1]["To"] == email
    assert "Scan terminé : example.fr" in outbox[-1]["Subject"]
    assert f"https://app.example.test/scans/{scan_id}" in outbox[-1].get_content()

    r = client.patch("/api/users/me", json={"notify_scan_done": False}, headers=h)
    assert r.json()["notify_scan_done"] is False
    sent = len(outbox)
    scan_id = client.post("/api/scans", json={"domain_id": d["id"]}, headers=h).json()["id"]
    worker.execute_scan(scan_id)
    assert len(outbox) == sent


def test_account_deletion_sends_confirmation(client, outbox):
    email, h = _register(client)
    r = client.request("DELETE", "/api/users/me", json={"password": PASSWORD}, headers=h)
    assert r.status_code == 204
    assert outbox[-1]["To"] == email and "supprimé" in outbox[-1]["Subject"]


def test_smtp_failure_does_not_break_requests(client, outbox, monkeypatch):
    def broken(msg):
        raise OSError("smtp down")

    monkeypatch.setattr(mailer, "_transport", broken)
    email, _ = _register(client)
    assert client.post("/api/auth/forgot-password", json={"email": email}).status_code == 202


def test_late_columns_are_idempotent():
    init_db()
    init_db()
    with SessionLocal() as db:
        assert db.query(Scan).count() >= 0


# --- SMTP configuration from the admin page -------------------------------------------------

def _admin_headers(client) -> tuple[str, dict]:
    email, h = _register(client)
    with SessionLocal() as db:
        db.query(User).filter_by(email=email).one().is_admin = True
        db.commit()
    return email, h


@pytest.fixture
def admin_smtp(client, monkeypatch):
    sent = []
    monkeypatch.setattr(mailer, "_transport", sent.append)
    email, h = _admin_headers(client)
    yield email, h, sent
    client.delete("/api/admin/smtp", headers=h)


BREVO = {"host": "smtp-relay.brevo.com", "port": 587, "security": "starttls",
         "username": "login@example.com", "password": "xsmtpsib-super-secret",
         "from_address": "noreply@example.com", "public_url": "https://app.example.test/"}


def test_smtp_settings_are_admin_only(client):
    _, h = _register(client)
    assert client.get("/api/admin/smtp", headers=h).status_code == 403
    assert client.put("/api/admin/smtp", json=BREVO, headers=h).status_code == 403
    assert client.post("/api/admin/smtp/test", json={}, headers=h).status_code == 403


def test_admin_smtp_config_overrides_env_and_hides_secret(client, admin_smtp):
    email, h, sent = admin_smtp
    r = client.get("/api/admin/smtp", headers=h).json()
    assert r["source"] == "none" and r["brevo_defaults"]["host"] == "smtp-relay.brevo.com"
    assert client.get("/api/features").json() == {"email": False}

    r = client.put("/api/admin/smtp", json=BREVO, headers=h)
    assert r.status_code == 200
    out = r.json()
    assert out["source"] == "admin" and out["enabled"] and out["password_set"]
    assert "xsmtpsib" not in r.text and "password" not in out
    assert client.get("/api/features").json() == {"email": True}

    # Encrypted at rest, decrypted for sending.
    with SessionLocal() as db:
        from app.models import SmtpSettings
        row = db.get(SmtpSettings, 1)
        assert row.password_encrypted and "xsmtpsib" not in row.password_encrypted
        audit = db.query(AuditLog).filter_by(action="smtp.update").order_by(
            AuditLog.created_at.desc()).first()
    assert audit.user_email == email and "password" in audit.details
    assert "xsmtpsib" not in audit.details
    cfg = mailer.get_config()
    assert cfg.password == "xsmtpsib-super-secret" and cfg.username == "login@example.com"

    # Links use the admin-configured public URL.
    user_email, _ = _register(client)
    client.post("/api/auth/forgot-password", json={"email": user_email})
    assert "https://app.example.test/reset-password?token=" in sent[-1].get_content()
    assert "<noreply@example.com>" in sent[-1]["From"]

    # Omitting the password keeps it; clear_password removes it.
    body = {k: v for k, v in BREVO.items() if k != "password"}
    assert client.put("/api/admin/smtp", json=body, headers=h).json()["password_set"]
    r = client.put("/api/admin/smtp", json={**body, "clear_password": True}, headers=h).json()
    assert r["password_set"] is False

    # Reset falls back to the (empty) environment configuration.
    assert client.delete("/api/admin/smtp", headers=h).json()["source"] == "none"
    assert mailer.enabled() is False


def test_admin_smtp_rejects_header_injection(client, admin_smtp):
    _, h, _ = admin_smtp
    for bad in ({"host": "smtp.example.test\r\nX: y"}, {"username": "a\r\nb"},
                {"from_address": "not-an-email"}, {"security": "tls"}, {"port": 0},
                {"public_url": "javascript:alert(1)"}):
        assert client.put("/api/admin/smtp", json={**BREVO, **bad}, headers=h).status_code == 422


def test_admin_test_email(client, admin_smtp, monkeypatch):
    email, h, sent = admin_smtp
    assert client.post("/api/admin/smtp/test", json={}, headers=h).status_code == 503
    client.put("/api/admin/smtp", json=BREVO, headers=h)
    r = client.post("/api/admin/smtp/test", json={}, headers=h)
    assert r.status_code == 200 and r.json() == {"sent_to": email}
    assert sent[-1]["To"] == email and "test" in sent[-1]["Subject"]

    def broken(msg):
        raise OSError("connection refused")

    monkeypatch.setattr(mailer, "_transport", broken)
    r = client.post("/api/admin/smtp/test", json={"to": "other@example.fr"}, headers=h)
    assert r.status_code == 502 and "connection refused" in r.json()["detail"]
    with SessionLocal() as db:
        results = [a.details for a in db.query(AuditLog).filter_by(action="smtp.test")]
    assert any("result=error" in d for d in results) and any("result=ok" in d for d in results)


def test_unreadable_password_after_secret_key_change(client, admin_smtp, monkeypatch):
    _, h, _ = admin_smtp
    client.put("/api/admin/smtp", json=BREVO, headers=h)
    monkeypatch.setattr(get_settings(), "secret_key", "another-secret-key-of-sufficient-length")
    assert mailer.get_config().password == ""
    monkeypatch.undo()
