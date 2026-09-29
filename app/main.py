"""FastAPI entry point.

v0.1: no auth yet — a single demo user, in-memory domain store.
TODO(v0.2): real accounts, SQLAlchemy models, rate limit, audit log.
"""

from __future__ import annotations

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from redis import Redis
from rq import Queue
from rq.job import Job

from app import domains, reports, scans
from app.config import get_settings
from app.reports import TEMPLATES_DIR

settings = get_settings()
app = FastAPI(title=settings.app_name)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

DEMO_USER = "demo"
# domain -> {"challenge": VerificationChallenge, "verified": bool}  (TODO: move to DB)
_domains: dict[str, dict] = {}


def _queue() -> Queue:
    return Queue("scans", connection=Redis.from_url(settings.redis_url))


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"domains": _domains})


@app.post("/domains", response_class=HTMLResponse)
def add_domain(request: Request, domain: str = Form(...)):
    try:
        challenge = domains.create_challenge(DEMO_USER, domain)
    except domains.InvalidDomain as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _domains[challenge.domain] = {"challenge": challenge, "verified": False}
    return templates.TemplateResponse(request, "index.html", {"domains": _domains})


@app.post("/domains/{domain}/verify")
def verify_domain(domain: str) -> dict:
    try:
        entry = _domains.get(domains.normalize_domain(domain))
    except domains.InvalidDomain as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not entry:
        raise HTTPException(status_code=404, detail="unknown domain")
    ch = entry["challenge"]
    entry["verified"] = domains.check_txt_record(ch.record_name, ch.record_value)
    return {"domain": ch.domain, "verified": entry["verified"]}


@app.post("/scans")
def start_scan(domain: str = Form(...), level: str = Form("passive")) -> dict:
    try:
        clean = domains.normalize_domain(domain)
        scan_level = scans.ScanLevel(level)
    except (domains.InvalidDomain, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    verified = _domains.get(clean, {}).get("verified", False)
    if scan_level is not scans.ScanLevel.PASSIVE and not verified:
        raise HTTPException(status_code=403, detail="active scans require a verified domain")

    job = _queue().enqueue(
        scans.run_scan, clean, scan_level.value, verified,
        job_timeout=settings.scan_timeout_seconds + 60,
    )
    return {"job_id": job.id, "status": job.get_status()}


def _finished_result(job_id: str) -> scans.ScanResult:
    job = Job.fetch(job_id, connection=Redis.from_url(settings.redis_url))
    if not job.is_finished:
        raise HTTPException(status_code=409, detail=f"scan status: {job.get_status()}")
    return job.return_value()


@app.get("/scans/{job_id}")
def scan_status(job_id: str) -> dict:
    job = Job.fetch(job_id, connection=Redis.from_url(settings.redis_url))
    return {"job_id": job_id, "status": job.get_status()}


@app.get("/scans/{job_id}/report", response_class=HTMLResponse)
def scan_report(job_id: str):
    result = _finished_result(job_id)
    return reports.render_html(reports.build_report(result.domain, result.level.value, result.events))


@app.get("/scans/{job_id}/report.pdf")
def scan_report_pdf(job_id: str):
    result = _finished_result(job_id)
    pdf = reports.render_pdf(reports.build_report(result.domain, result.level.value, result.events))
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{result.domain}.pdf"'})
