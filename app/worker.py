"""RQ job functions: run a scan stored in the DB, and purge expired results.

Run the worker with:  rq worker scans
Purge manually with:  python -m app.worker purge
"""

from __future__ import annotations

import sys
from datetime import timedelta

from sqlalchemy import delete, select

from app import scans
from app.config import get_settings
from app.db import SessionLocal, init_db
from app.models import Domain, Scan, utcnow


def execute_scan(scan_id: str) -> str:
    """Entry point enqueued by the API. Returns the final scan status."""
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return "missing"

        # Re-check ownership proof at execution time: the domain may have been
        # deleted between the request and the job start.
        verified = db.scalar(
            select(Domain.verified).where(Domain.user_id == scan.user_id, Domain.name == scan.domain)
        ) or False

        scan.status = "running"
        scan.started_at = utcnow()
        db.commit()

        try:
            result = scans.run_scan(scan.domain, scan.level, verified)
        except scans.ScanNotAllowed as exc:
            scan.status, scan.error = "failed", str(exc)
        except Exception as exc:  # noqa: BLE001 - keep the job record consistent
            scan.status, scan.error = "failed", f"internal error: {type(exc).__name__}"
        else:
            scan.events = result.events
            scan.error = result.error
            scan.status = "done" if result.returncode == 0 else "failed"
        scan.finished_at = utcnow()
        db.commit()
        status = scan.status

    purge_expired()
    return status


def purge_expired() -> int:
    """Delete scan results older than RETENTION_DAYS (GDPR). Returns the number deleted."""
    cutoff = utcnow() - timedelta(days=get_settings().retention_days)
    with SessionLocal() as db:
        res = db.execute(delete(Scan).where(Scan.created_at < cutoff))
        db.commit()
        return res.rowcount or 0


if __name__ == "__main__":
    if sys.argv[1:] == ["purge"]:
        init_db()
        print(f"purged {purge_expired()} scan(s)")
    else:
        sys.exit("usage: python -m app.worker purge")
