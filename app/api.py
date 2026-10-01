"""JSON API consumed by the React front end (mounted under /api)."""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import domains, reports, scans
from app.auth import create_access_token, get_current_user, hash_password, verify_password
from app.config import get_settings
from app.db import get_db
from app.models import AuditLog, Domain, Scan, User, as_utc, utcnow

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


class DomainIn(BaseModel):
    domain: str = Field(max_length=300)


class ScanIn(BaseModel):
    domain_id: str
    level: scans.ScanLevel = scans.ScanLevel.PASSIVE
    # Explicit opt-in required for aggressive levels (advanced brute-force).
    consent: bool = False


def _user_out(user: User) -> dict:
    return {"id": user.id, "email": user.email, "created_at": user.created_at}


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


@router.get("/users/me")
def me(user: User = Depends(get_current_user)) -> dict:
    return _user_out(user)


@router.delete("/users/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """GDPR erasure: account, domains and scan results. The audit log is kept (rule 4)."""
    db.delete(user)
    db.commit()
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
    if domains.check_txt_record(d.record_name, d.record_value):
        d.verified = True
        d.verified_at = utcnow()
        db.commit()
    return _domain_out(d)


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

    # Advanced brute-force requires an explicit, logged opt-in on top of ownership proof.
    if body.level in scans.CONSENT_LEVELS and not body.consent:
        raise HTTPException(status_code=403,
                            detail="advanced scans require explicit consent to brute-force testing")

    # Rule 2 + SPEC guardrails: one scan at a time, plus a per-level daily quota.
    if _count_scans(db, user, Scan.status.in_(ACTIVE_STATUSES)) >= settings.max_concurrent_scans_per_user:
        raise HTTPException(status_code=429, detail="a scan is already running")
    since: datetime = utcnow() - timedelta(days=1)
    if body.level is scans.ScanLevel.ADVANCED:
        daily_limit = settings.advanced_max_scans_per_day
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
                    source_ip=request.client.host if request.client else None))
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
