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
