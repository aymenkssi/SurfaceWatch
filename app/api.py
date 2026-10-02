"""JSON API consumed by the React front end (mounted under /api)."""

from __future__ import annotations

import hashlib
import secrets
from collections import Counter
from datetime import datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import crypto, domains, mailer, reports, scans
from app.auth import (create_access_token, get_current_admin, get_current_user, hash_password,
                      verify_password)
from app.config import get_settings
from app.db import get_db
from app.models import (AuditLog, Domain, PasswordResetToken, Scan, SmtpSettings, User, as_utc,
                        utcnow)

router = APIRouter(prefix="/api")

ACTIVE_STATUSES = ("queued", "running")


# --- Job queue (overridden in tests) -------------------------------------------------------

def enqueue_scan(scan_id: str) -> str:
    from redis import Redis
    from rq import Queue

    settings = get_settings()
    queue = Queue("scans", connection=Redis.from_url(settings.redis_url))
    # RQ ceiling must clear the longest per-level hard timeout (enforced in scans.run_scan).
    job_timeout = max(settings.scan_timeout_seconds, settings.advanced_scan_timeout_seconds) + 60
    job = queue.enqueue("app.worker.execute_scan", scan_id, job_timeout=job_timeout)
    return job.id


def get_enqueuer():
    return enqueue_scan


# --- Schemas -------------------------------------------------------------------------------

class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)


class ForgotPasswordIn(BaseModel):
    email: EmailStr


class ResetPasswordIn(BaseModel):
    token: str = Field(min_length=20, max_length=100)
    password: str = Field(min_length=10, max_length=128)


class DeleteAccountIn(BaseModel):
    password: str = Field(max_length=128)


class PreferencesIn(BaseModel):
    notify_scan_done: bool


class DomainIn(BaseModel):
    domain: str = Field(max_length=300)
    renew: bool = False  # issue a new token even if the current one is still valid


class ScanIn(BaseModel):
    domain_id: str
    level: scans.ScanLevel = scans.ScanLevel.PASSIVE
    # Explicit opt-in required for active-probing levels (advanced brute-force, deep port scan).
    consent: bool = False


def _user_out(user: User) -> dict:
    return {"id": user.id, "email": user.email, "is_admin": user.is_admin,
            "notify_scan_done": user.notify_scan_done, "created_at": user.created_at}


def _domain_out(d: Domain) -> dict:
    return {
        "id": d.id,
        "name": d.name,
        "record_name": d.record_name,
        "record_value": d.record_value,
        "token_expires_at": as_utc(d.token_expires_at),
        "token_expired": not d.verified and as_utc(d.token_expires_at) < utcnow(),
        "verified": d.verified,
        "verified_at": as_utc(d.verified_at),
        "verification_method": d.verification_method,
        "created_at": as_utc(d.created_at),
    }


def _scan_out(s: Scan) -> dict:
    created = as_utc(s.created_at)
    return {
        "id": s.id,
        "domain": s.domain,
        "level": s.level,
        "status": s.status,
        "error": s.error,
        "created_at": created,
        "started_at": as_utc(s.started_at),
        "finished_at": as_utc(s.finished_at),
        "expires_at": created + timedelta(days=get_settings().retention_days),
    }


def _auth_response(user: User) -> dict:
    return {"access_token": create_access_token(user.id), "token_type": "bearer",
            "user": _user_out(user)}


# --- Auth & account ------------------------------------------------------------------------

@router.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register(body: Credentials, db: Session = Depends(get_db)) -> dict:
    user = User(email=body.email.lower(), password_hash=hash_password(body.password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="email already registered") from exc
    return _auth_response(user)


@router.post("/auth/login")
def login(body: Credentials, db: Session = Depends(get_db)) -> dict:
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="invalid email or password")
    return _auth_response(user)


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _audit_account(db: Session, user: User, action: str, request: Request) -> None:
    db.add(AuditLog(user_id=user.id, user_email=user.email, action=action, domain="",
                    source_ip=_client_ip(request)))


def _hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@router.get("/features")
def features() -> dict:
    """Optional features the front end should show (e.g. "forgot password" needs SMTP)."""
    return {"email": mailer.enabled()}


@router.post("/auth/forgot-password", status_code=status.HTTP_202_ACCEPTED)
def forgot_password(body: ForgotPasswordIn, request: Request, db: Session = Depends(get_db)) -> dict:
    """Mail a single-use reset link. Same answer whether the account exists or not."""
    if not mailer.enabled():
        raise HTTPException(status_code=503, detail="email is not configured")
    settings = get_settings()
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    if user is None:
        return {"status": "accepted"}

    now = utcnow()
    recent = db.scalar(select(func.count()).select_from(PasswordResetToken).where(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.created_at >= now - timedelta(hours=1))) or 0
    if recent >= settings.password_reset_max_per_hour:
        return {"status": "accepted"}

    # Only the latest link works (older rows stay until purge: they feed the rate limit).
    db.execute(update(PasswordResetToken)
               .where(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None),
                      PasswordResetToken.expires_at > now)
               .values(expires_at=now))
    token = secrets.token_urlsafe(32)
    db.add(PasswordResetToken(user_id=user.id, token_hash=_hash_reset_token(token),
                              expires_at=now + timedelta(minutes=settings.password_reset_ttl_minutes)))
    _audit_account(db, user, "account.password_reset_requested", request)
    db.commit()
    mailer.send_password_reset(user.email, token)
    return {"status": "accepted"}


@router.post("/auth/reset-password", status_code=status.HTTP_204_NO_CONTENT)
def reset_password(body: ResetPasswordIn, request: Request, db: Session = Depends(get_db)):
    row = db.scalar(select(PasswordResetToken)
                    .where(PasswordResetToken.token_hash == _hash_reset_token(body.token)))
    if row is None or row.used_at is not None or as_utc(row.expires_at) <= utcnow():
        raise HTTPException(status_code=400, detail="invalid or expired reset link")
    user = row.user
    now = utcnow()
    row.used_at = now
    db.execute(update(PasswordResetToken)
               .where(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None))
               .values(expires_at=now))
    user.password_hash = hash_password(body.password)
    user.password_changed_at = now
    _audit_account(db, user, "account.password_reset", request)
    db.commit()
    mailer.send_password_changed(user.email)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/users/me")
def me(user: User = Depends(get_current_user)) -> dict:
    return _user_out(user)


@router.patch("/users/me")
def update_preferences(body: PreferencesIn, user: User = Depends(get_current_user),
                       db: Session = Depends(get_db)) -> dict:
    user.notify_scan_done = body.notify_scan_done
    db.commit()
    return _user_out(user)


@router.delete("/users/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(body: DeleteAccountIn, request: Request,
                   user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """GDPR erasure: account, domains, scan results and reset tokens.

    The password is asked again so a stolen session cannot wipe the account. The audit log is
    kept (rule 4) and records the deletion itself before the data goes.
    """
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=403, detail="wrong password")
    if db.scalar(select(func.count()).select_from(Scan).where(
            Scan.user_id == user.id, Scan.status == "running")):
        raise HTTPException(status_code=409, detail="wait for the running scan to finish")
    email = user.email
    _audit_account(db, user, "account.deleted", request)
    db.commit()
    db.delete(user)
    db.commit()
    mailer.send_account_deleted(email)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Domains -------------------------------------------------------------------------------

def _get_domain(db: Session, user: User, domain_id: str) -> Domain:
    d = db.get(Domain, domain_id)
    if d is None or d.user_id != user.id:
        raise HTTPException(status_code=404, detail="unknown domain")
    return d


@router.get("/domains")
def list_domains(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list:
    rows = db.scalars(select(Domain).where(Domain.user_id == user.id).order_by(Domain.name))
    return [_domain_out(d) for d in rows]


@router.post("/domains", status_code=status.HTTP_201_CREATED)
def add_domain(body: DomainIn, user: User = Depends(get_current_user),
               db: Session = Depends(get_db)) -> dict:
    """Add a domain, or issue a fresh token for an existing unverified one."""
    try:
        challenge = domains.create_challenge(user.id, body.domain)
    except domains.InvalidDomain as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    d = db.scalar(select(Domain).where(Domain.user_id == user.id, Domain.name == challenge.domain))
    if d is not None and d.verified:
        return _domain_out(d)
    # Keep a still-valid token: re-adding the domain must not silently invalidate
    # a TXT record the user may already have published.
    if d is not None and not body.renew and as_utc(d.token_expires_at) > utcnow():
        return _domain_out(d)
    if d is None:
        d = Domain(user_id=user.id, name=challenge.domain)
        db.add(d)
    d.record_name = challenge.record_name
    d.record_value = challenge.record_value
    d.token_expires_at = challenge.expires_at
    db.commit()
    return _domain_out(d)


@router.post("/domains/{domain_id}/verify")
def verify_domain(domain_id: str, user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)) -> dict:
    d = _get_domain(db, user, domain_id)
    if d.verified:
        return _domain_out(d)
    if as_utc(d.token_expires_at) < utcnow():
        raise HTTPException(status_code=410, detail="token expired, request a new one")
    check = domains.lookup_txt_record(d.record_name, d.record_value)
    if check.ok:
        d.verified = True
        d.verified_at = utcnow()
        d.verification_method = "dns"
        db.commit()
    out = _domain_out(d)
    if not check.ok:
        out["verify_error"] = check.reason
        out["verify_found"] = list(check.found)
    return out


@router.delete("/domains/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_domain(domain_id: str, user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    db.delete(_get_domain(db, user, domain_id))
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Scans ---------------------------------------------------------------------------------

def _get_scan(db: Session, user: User, scan_id: str) -> Scan:
    s = db.get(Scan, scan_id)
    if s is None or s.user_id != user.id:
        raise HTTPException(status_code=404, detail="unknown scan")
    return s


def _count_scans(db: Session, user: User, *conditions) -> int:
    return db.scalar(select(func.count()).select_from(Scan)
                     .where(Scan.user_id == user.id, *conditions)) or 0


@router.get("/scans")
def list_scans(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list:
    rows = db.scalars(select(Scan).where(Scan.user_id == user.id)
                      .order_by(Scan.created_at.desc()).limit(100))
    return [_scan_out(s) for s in rows]


@router.post("/scans", status_code=status.HTTP_202_ACCEPTED)
def start_scan(body: ScanIn, request: Request, user: User = Depends(get_current_user),
               db: Session = Depends(get_db), enqueue=Depends(get_enqueuer)) -> dict:
    settings = get_settings()
    d = _get_domain(db, user, body.domain_id)

    # Rule 1: no active scan without proof of ownership (re-checked in the worker too).
    if body.level in scans.ACTIVE_LEVELS and not d.verified:
        raise HTTPException(status_code=403, detail="active scans require a verified domain")

    # Levels that actively probe the target require an explicit, logged opt-in.
    if body.level in scans.CONSENT_LEVELS and not body.consent:
        raise HTTPException(status_code=403,
                            detail="this level requires explicit consent to actively test the target")

    # Rule 2 + SPEC guardrails: one scan at a time, plus a per-level daily quota.
    if _count_scans(db, user, Scan.status.in_(ACTIVE_STATUSES)) >= settings.max_concurrent_scans_per_user:
        raise HTTPException(status_code=429, detail="a scan is already running")
    since: datetime = utcnow() - timedelta(days=1)
    # An admin quota reset raises the floor: scans before it no longer count.
    reset_at = as_utc(user.scan_quota_reset_at)
    if reset_at is not None and reset_at > since:
        since = reset_at
    if body.level is scans.ScanLevel.ADVANCED:
        daily_limit = settings.advanced_max_scans_per_day
        used = _count_scans(db, user, Scan.created_at >= since, Scan.level == body.level.value)
    elif body.level is scans.ScanLevel.DEEP:
        daily_limit = settings.deep_max_scans_per_day
        used = _count_scans(db, user, Scan.created_at >= since, Scan.level == body.level.value)
    else:
        daily_limit = settings.max_scans_per_day
        used = _count_scans(db, user, Scan.created_at >= since)
    if used >= daily_limit:
        raise HTTPException(status_code=429, detail="daily scan quota reached")

    scan = Scan(user_id=user.id, domain=d.name, level=body.level.value)
    db.add(scan)
    db.flush()
    # Rule 4: audit every scan request (consent recorded for aggressive levels).
    db.add(AuditLog(user_id=user.id, user_email=user.email, action="scan.requested",
                    domain=d.name, level=scan.level, consent=body.consent, scan_id=scan.id,
                    source_ip=_client_ip(request)))
    db.commit()

    try:
        scan.job_id = enqueue(scan.id)
    except Exception as exc:  # noqa: BLE001 - Redis down, etc.
        # Drop the scan so it does not eat the user's quota; the audit row stays.
        db.delete(scan)
        db.commit()
        raise HTTPException(status_code=503, detail="scan queue unavailable") from exc
    db.commit()
    return _scan_out(scan)


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, user: User = Depends(get_current_user),
             db: Session = Depends(get_db)) -> dict:
    return _scan_out(_get_scan(db, user, scan_id))


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: str, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    s = _get_scan(db, user, scan_id)
    if s.status in ACTIVE_STATUSES:
        raise HTTPException(status_code=409, detail="scan still running")
    db.delete(s)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _build_report(db: Session, user: User, scan_id: str) -> reports.Report:
    s = _get_scan(db, user, scan_id)
    if s.status != "done":
        raise HTTPException(status_code=409, detail=f"scan status: {s.status}")
    report = reports.build_report(s.domain, s.level, s.events or [])
    report.generated_at = as_utc(s.finished_at) or report.generated_at
    return report


@router.get("/scans/{scan_id}/report")
def scan_report(scan_id: str, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)) -> dict:
    return reports.report_to_dict(_build_report(db, user, scan_id))


@router.get("/scans/{scan_id}/report.html", response_class=HTMLResponse)
def scan_report_html(scan_id: str, user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    return HTMLResponse(reports.render_html(_build_report(db, user, scan_id)))


@router.get("/scans/{scan_id}/report.pdf")
def scan_report_pdf(scan_id: str, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    report = _build_report(db, user, scan_id)
    try:
        pdf = reports.render_pdf(report)
    except RuntimeError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{report.domain}.pdf"'})


# --- Admin ---------------------------------------------------------------------------------
# Every route below requires users.is_admin (get_current_admin).

class ManualVerifyIn(BaseModel):
    # Why ownership was accepted without the TXT record (kept in the audit log).
    reason: str = Field(min_length=5, max_length=500)


class ResetQuotaIn(BaseModel):
    email: EmailStr


def _admin_domain_out(d: Domain) -> dict:
    return {**_domain_out(d), "owner_email": d.user.email}


@router.get("/admin/stats")
def admin_stats(_: User = Depends(get_current_admin), db: Session = Depends(get_db)) -> dict:
    now = utcnow()
    day_ago, week_ago, month_ago = (now - timedelta(days=n) for n in (1, 7, 30))

    def count(model, *conditions) -> int:
        return db.scalar(select(func.count()).select_from(model).where(*conditions)) or 0

    def grouped(column, *conditions) -> dict:
        return dict(db.execute(select(column, func.count()).where(*conditions).group_by(column)).all())

    # Scan rows are purged after the retention window; the audit log keeps the full history.
    requested = AuditLog.action == "scan.requested"
    days = 30
    per_day = Counter(as_utc(ts).date().isoformat() for ts in db.scalars(
        select(AuditLog.created_at).where(requested, AuditLog.created_at >= month_ago)))
    first_day = now.date() - timedelta(days=days - 1)
    timeline = [{"date": (first_day + timedelta(days=i)).isoformat(),
                 "count": per_day.get((first_day + timedelta(days=i)).isoformat(), 0)}
                for i in range(days)]

    durations: dict[str, list[float]] = {}
    for level, started, finished in db.execute(
            select(Scan.level, Scan.started_at, Scan.finished_at)
            .where(Scan.status == "done", Scan.started_at.is_not(None),
                   Scan.finished_at.is_not(None))):
        durations.setdefault(level, []).append(
            (as_utc(finished) - as_utc(started)).total_seconds())

    return {
        "users": {
            "total": count(User),
            "admins": count(User, User.is_admin.is_(True)),
            "new_7d": count(User, User.created_at >= week_ago),
            "new_30d": count(User, User.created_at >= month_ago),
            "with_verified_domain": db.scalar(select(func.count(func.distinct(Domain.user_id)))
                                              .where(Domain.verified.is_(True))) or 0,
        },
        "domains": {
            "total": count(Domain),
            "verified_dns": count(Domain, Domain.verified.is_(True),
                                  or_(Domain.verification_method != "manual",
                                      Domain.verification_method.is_(None))),
            "verified_manual": count(Domain, Domain.verified.is_(True),
                                     Domain.verification_method == "manual"),
            "pending": count(Domain, Domain.verified.is_(False)),
        },
        "scans": {
            "requested_total": count(AuditLog, requested),
            "requested_24h": count(AuditLog, requested, AuditLog.created_at >= day_ago),
            "requested_7d": count(AuditLog, requested, AuditLog.created_at >= week_ago),
            "requested_30d": count(AuditLog, requested, AuditLog.created_at >= month_ago),
            "by_level": grouped(AuditLog.level, requested),
            "by_status": grouped(Scan.status),  # retention window only
            "active": count(Scan, Scan.status.in_(ACTIVE_STATUSES)),
            "advanced_with_consent": count(AuditLog, requested, AuditLog.level == "advanced",
                                           AuditLog.consent.is_(True)),
            "avg_duration_seconds": {lvl: round(sum(v) / len(v)) for lvl, v in durations.items()},
            "per_day": timeline,
        },
        "retention_days": get_settings().retention_days,
    }


@router.get("/admin/scans")
def admin_active_scans(_: User = Depends(get_current_admin), db: Session = Depends(get_db)) -> list:
    """Queued and running scans across all users."""
    rows = db.scalars(select(Scan).where(Scan.status.in_(ACTIVE_STATUSES))
                      .order_by(Scan.created_at))
    return [{**_scan_out(s), "user_email": s.user.email} for s in rows]


@router.get("/admin/domains")
def admin_domains(q: str = "", status_filter: str = "pending",
                  _: User = Depends(get_current_admin), db: Session = Depends(get_db)) -> list:
    """Domains across all users. status_filter: pending | verified | all; q matches name/email."""
    stmt = select(Domain).join(User)
    if status_filter == "pending":
        stmt = stmt.where(Domain.verified.is_(False))
    elif status_filter == "verified":
        stmt = stmt.where(Domain.verified.is_(True))
    if q.strip():
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(Domain.name.like(like), User.email.like(like)))
    rows = db.scalars(stmt.order_by(Domain.created_at.desc()).limit(200))
    return [_admin_domain_out(d) for d in rows]


@router.post("/admin/domains/{domain_id}/verify")
def admin_verify_domain(domain_id: str, body: ManualVerifyIn, request: Request,
                        admin: User = Depends(get_current_admin),
                        db: Session = Depends(get_db)) -> dict:
    """Manually accept ownership without the DNS TXT record (exception to rule 1).

    Restricted to admins and always written to the audit log with the admin's reason.
    """
    d = db.get(Domain, domain_id)
    if d is None:
        raise HTTPException(status_code=404, detail="unknown domain")
    if d.verified:
        raise HTTPException(status_code=409, detail="domain already verified")
    d.verified = True
    d.verified_at = utcnow()
    d.verification_method = "manual"
    d.verified_by = admin.id
    db.add(AuditLog(user_id=admin.id, user_email=admin.email, action="domain.manual_verify",
                    domain=d.name, source_ip=_client_ip(request),
                    details=f"owner={d.user.email}; reason={body.reason.strip()}"))
    db.commit()
    return _admin_domain_out(d)


@router.post("/admin/domains/{domain_id}/revoke")
def admin_revoke_domain(domain_id: str, request: Request,
                        admin: User = Depends(get_current_admin),
                        db: Session = Depends(get_db)) -> dict:
    """Withdraw a verification (DNS or manual); the owner must prove ownership again."""
    d = db.get(Domain, domain_id)
    if d is None:
        raise HTTPException(status_code=404, detail="unknown domain")
    if not d.verified:
        raise HTTPException(status_code=409, detail="domain not verified")
    previous = d.verification_method or "dns"
    d.verified, d.verified_at, d.verification_method, d.verified_by = False, None, None, None
    # Fresh challenge so the owner can re-verify via DNS.
    challenge = domains.create_challenge(d.user_id, d.name)
    d.record_name, d.record_value = challenge.record_name, challenge.record_value
    d.token_expires_at = challenge.expires_at
    db.add(AuditLog(user_id=admin.id, user_email=admin.email, action="domain.revoke_verify",
                    domain=d.name, source_ip=_client_ip(request),
                    details=f"owner={d.user.email}; previous={previous}"))
    db.commit()
    return _admin_domain_out(d)


@router.post("/admin/users/reset-quota")
def admin_reset_quota(body: ResetQuotaIn, request: Request,
                      admin: User = Depends(get_current_admin),
                      db: Session = Depends(get_db)) -> dict:
    """Reset a user's daily scan quota: scans before now stop counting toward the limit."""
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    if user is None:
        raise HTTPException(status_code=404, detail="unknown user")
    user.scan_quota_reset_at = utcnow()
    db.add(AuditLog(user_id=admin.id, user_email=admin.email, action="user.quota_reset",
                    domain="", source_ip=_client_ip(request),
                    details=f"target={user.email}"))
    db.commit()
    return {"email": user.email, "reset_at": as_utc(user.scan_quota_reset_at)}


@router.get("/admin/audit")
def admin_audit(limit: int = 50, _: User = Depends(get_current_admin),
                db: Session = Depends(get_db)) -> list:
    rows = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc())
                      .limit(max(1, min(limit, 200))))
    return [{"id": a.id, "action": a.action, "user_email": a.user_email, "domain": a.domain,
             "level": a.level, "consent": a.consent, "source_ip": a.source_ip,
             "details": a.details, "created_at": as_utc(a.created_at)} for a in rows]


# --- Admin: outgoing e-mail (SMTP) ----------------------------------------------------------
# Stored in the database so it can be changed without editing .env. The password / API key is
# write-only: it is encrypted at rest and never sent back to the browser.

# Pre-filled in the admin form; any other SMTP provider can be used instead.
BREVO_DEFAULTS = {"host": "smtp-relay.brevo.com", "port": 587, "security": "starttls"}


class SmtpSettingsIn(BaseModel):
    host: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.-]+$")
    port: int = Field(ge=1, le=65535)
    security: Literal["starttls", "ssl", "none"]
    username: str = Field(default="", max_length=254, pattern=r"^[^\r\n]*$")
    # None keeps the stored password; a value replaces it. clear_password removes it.
    password: str | None = Field(default=None, max_length=500)
    clear_password: bool = False
    from_address: EmailStr
    public_url: str = Field(default="", max_length=300, pattern=r"^(https?://[^\s]+)?$")


class SmtpTestIn(BaseModel):
    to: EmailStr | None = None  # defaults to the admin's own address


def _smtp_out(db: Session) -> dict:
    row = db.get(SmtpSettings, 1)
    cfg = mailer.get_config()
    out = {
        "source": cfg.source if cfg.enabled or row else "none",
        "enabled": cfg.enabled,
        "host": cfg.host, "port": cfg.port, "security": cfg.security,
        "username": cfg.username, "from_address": cfg.from_address,
        "public_url": row.public_url if row else "",
        "default_public_url": get_settings().public_url,
        "password_set": bool(cfg.password),
        # Stored but unreadable (SECRET_KEY changed): the admin must enter it again.
        "password_unreadable": bool(row and row.password_encrypted and not cfg.password),
        "updated_at": as_utc(row.updated_at) if row else None,
        "updated_by": row.updated_by if row else None,
        "brevo_defaults": BREVO_DEFAULTS,
    }
    return out


@router.get("/admin/smtp")
def admin_get_smtp(_: User = Depends(get_current_admin), db: Session = Depends(get_db)) -> dict:
    return _smtp_out(db)


@router.put("/admin/smtp")
def admin_update_smtp(body: SmtpSettingsIn, request: Request,
                      admin: User = Depends(get_current_admin),
                      db: Session = Depends(get_db)) -> dict:
    row = db.get(SmtpSettings, 1)
    if row is None:
        row = SmtpSettings(id=1)
        db.add(row)
    new = {"host": body.host.strip().lower(), "port": body.port, "security": body.security,
           "username": body.username.strip(), "from_address": str(body.from_address),
           "public_url": body.public_url.strip().rstrip("/")}
    changed = [k for k, v in new.items() if getattr(row, k, None) != v]
    for key, value in new.items():
        setattr(row, key, value)
    if body.clear_password:
        if row.password_encrypted:
            changed.append("password(cleared)")
        row.password_encrypted = None
    elif body.password:
        row.password_encrypted = crypto.encrypt(body.password)
        changed.append("password")
    row.updated_at = utcnow()
    row.updated_by = admin.email
    # Field names only: the secret never reaches the audit log.
    db.add(AuditLog(user_id=admin.id, user_email=admin.email, action="smtp.update", domain="",
                    source_ip=_client_ip(request),
                    details="changed=" + (",".join(changed) or "nothing")))
    db.commit()
    return _smtp_out(db)


@router.delete("/admin/smtp")
def admin_reset_smtp(request: Request, admin: User = Depends(get_current_admin),
                     db: Session = Depends(get_db)) -> dict:
    """Delete the admin-saved configuration; the SMTP_* environment variables apply again."""
    row = db.get(SmtpSettings, 1)
    if row is not None:
        db.delete(row)
        db.add(AuditLog(user_id=admin.id, user_email=admin.email, action="smtp.reset",
                        domain="", source_ip=_client_ip(request)))
        db.commit()
    return _smtp_out(db)


@router.post("/admin/smtp/test")
def admin_test_smtp(body: SmtpTestIn, request: Request, admin: User = Depends(get_current_admin),
                    db: Session = Depends(get_db)) -> dict:
    """Send a test e-mail with the saved configuration and report the SMTP error, if any."""
    cfg = mailer.get_config()
    if not cfg.enabled:
        raise HTTPException(status_code=503, detail="email is not configured")
    to = str(body.to or admin.email)
    error = None
    try:
        mailer.send_test(cfg, to)
    except Exception as exc:  # noqa: BLE001 - reported to the admin
        error = f"{type(exc).__name__}: {exc}"[:300]
    db.add(AuditLog(user_id=admin.id, user_email=admin.email, action="smtp.test", domain="",
                    source_ip=_client_ip(request),
                    details=f"to={to}; result={'ok' if error is None else 'error'}"))
    db.commit()
    if error is not None:
        raise HTTPException(status_code=502, detail=f"smtp error: {error}")
    return {"sent_to": to}
