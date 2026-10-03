"""RQ job functions: run a scan stored in the DB, and purge expired results.

Run the worker with:  rq worker scans
Purge manually with:  python -m app.worker purge
"""

from __future__ import annotations

import sys
from datetime import timedelta

from sqlalchemy import delete, select

from app import audit, checks, mailer, scans, vulns
from app.config import get_settings
from app.db import SessionLocal, init_db
from app.models import Domain, PasswordResetToken, Scan, utcnow


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
            events = list(result.events)
            settings = get_settings()
            # Self-driven web/TLS config audit over the discovered services. Sends packets
            # to the target, so only for active levels on a verified domain. It synthesizes
            # HTTP_RESPONSE / URL / PROTOCOL / FINDING events the checks below already read,
            # filling the gap when BBOT's own web-probe phase produced nothing.
            if (settings.self_audit_enabled and verified
                    and scans.ScanLevel(scan.level) in scans.ACTIVE_LEVELS):
                try:
                    events.extend(audit.audit_endpoints(events, scan.domain, settings))
                except Exception:  # noqa: BLE001 - the audit must never fail a scan
                    pass
            # Passive e-mail authentication checks (public DNS on the scanned domain).
            try:
                for finding in checks.mail_config_findings(scan.domain):
                    events.append({"type": finding["type"], "data": finding})
            except Exception:  # noqa: BLE001 - mail checks must never fail a scan
                pass
            # Vulnerability verdicts for the advertised component versions (CISA KEV +
            # keyless NVD). Best-effort: a feed outage must never fail the scan.
            if get_settings().vuln_lookup_enabled:
                try:
                    kev_ids = vulns.load_kev()
                    components = checks.component_versions(events)
                    for finding in vulns.assess_components(components, kev_ids=kev_ids):
                        events.append({"type": finding["type"], "data": finding})
                except Exception:  # noqa: BLE001 - vuln lookup must never fail a scan
                    pass
            scan.events = events
            scan.error = result.error
            scan.status = "done" if result.returncode == 0 else "failed"
        scan.finished_at = utcnow()
        db.commit()
        status = scan.status
        if scan.user.notify_scan_done:
            mailer.send_scan_finished(scan.user.email, scan.id, scan.domain, scan.level, status)

    purge_expired()
    return status


def purge_expired() -> int:
    """Delete scan results older than RETENTION_DAYS (GDPR). Returns the number deleted.

    Also drops password reset tokens that expired more than a day ago.
    """
    now = utcnow()
    cutoff = now - timedelta(days=get_settings().retention_days)
    with SessionLocal() as db:
        res = db.execute(delete(Scan).where(Scan.created_at < cutoff))
        db.execute(delete(PasswordResetToken)
                   .where(PasswordResetToken.expires_at < now - timedelta(days=1)))
        db.commit()
        return res.rowcount or 0


if __name__ == "__main__":
    if sys.argv[1:] == ["purge"]:
        init_db()
        print(f"purged {purge_expired()} scan(s)")
    else:
        sys.exit("usage: python -m app.worker purge")
