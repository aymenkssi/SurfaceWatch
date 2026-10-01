"""Outgoing e-mail over a self-configured SMTP server (no embedded provider key).

The SMTP configuration is edited by an admin on the /admin page and stored in the database
(`SmtpSettings`, password encrypted). When no configuration was saved there, the SMTP_*
environment variables are used as a fallback.

Every e-mail feature is optional: without a host and a sender address, `enabled()` is False
and `send()` is a no-op. `send()` never raises, so a mail outage cannot break a request or a job.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from app import crypto
from app.config import get_settings

log = logging.getLogger(__name__)

# Replaced in tests to capture messages instead of opening an SMTP connection.
_transport = None

SECURITY_MODES = ("starttls", "ssl", "none")


@dataclass(frozen=True)
class SmtpConfig:
    host: str
    port: int
    security: str
    username: str
    password: str
    from_address: str
    public_url: str
    source: str  # "admin" (database) | "env"

    @property
    def enabled(self) -> bool:
        return bool(self.host and self.from_address)


def _from_env() -> SmtpConfig:
    s = get_settings()
    return SmtpConfig(host=s.smtp_host, port=s.smtp_port, security=s.smtp_security,
                      username=s.smtp_user, password=s.smtp_password, from_address=s.smtp_from,
                      public_url=s.public_url, source="env")


def get_config() -> SmtpConfig:
    """Effective configuration: the admin-saved one if any, else the environment."""
    from app.db import SessionLocal
    from app.models import SmtpSettings

    with SessionLocal() as db:
        row = db.get(SmtpSettings, 1)
    if row is None:
        return _from_env()
    password = ""
    if row.password_encrypted:
        password = crypto.decrypt(row.password_encrypted)
        if password is None:
            log.error("stored SMTP password cannot be decrypted (SECRET_KEY changed?): "
                      "enter it again on the admin page")
            password = ""
    return SmtpConfig(host=row.host, port=row.port, security=row.security,
                      username=row.username, password=password,
                      from_address=row.from_address,
                      public_url=row.public_url or get_settings().public_url, source="admin")


def enabled() -> bool:
    return get_config().enabled


def _smtp_send(cfg: SmtpConfig, msg: EmailMessage) -> None:
    timeout = get_settings().smtp_timeout_seconds
    context = ssl.create_default_context()
    if cfg.security == "ssl":
        smtp = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=timeout, context=context)
    else:
        smtp = smtplib.SMTP(cfg.host, cfg.port, timeout=timeout)
    with smtp:
        if cfg.security == "starttls":
            smtp.starttls(context=context)
        if cfg.username:
            smtp.login(cfg.username, cfg.password)
        smtp.send_message(msg)


def _build(cfg: SmtpConfig, to: str, subject: str, body: str) -> EmailMessage:
    app_name = get_settings().app_name
    msg = EmailMessage()
    msg["From"] = formataddr((app_name, cfg.from_address))
    msg["To"] = to
    msg["Subject"] = f"[{app_name}] {subject}"
    msg["Message-ID"] = make_msgid(domain=cfg.from_address.rpartition("@")[2] or None)
    msg.set_content(f"{body}\n\n--\n{app_name} · {cfg.public_url}\n")
    return msg


def deliver(cfg: SmtpConfig, to: str, subject: str, body: str) -> None:
    """Send with an explicit configuration and let SMTP errors propagate (admin test e-mail)."""
    msg = _build(cfg, to, subject, body)
    if _transport is not None:
        _transport(msg)
    else:
        _smtp_send(cfg, msg)


def send(to: str, subject: str, body: str) -> bool:
    """Send a plain-text e-mail. Returns True when it was handed to the SMTP server."""
    cfg = get_config()
    if not cfg.enabled:
        return False
    try:
        deliver(cfg, to, subject, body)
    except Exception:  # noqa: BLE001 - mail is best effort
        log.exception("failed to send e-mail %r", subject)
        return False
    return True


def _url(path: str) -> str:
    return get_config().public_url.rstrip("/") + path


# --- Messages (French, like the UI) --------------------------------------------------------

def send_password_reset(to: str, token: str) -> bool:
    ttl = get_settings().password_reset_ttl_minutes
    return send(to, "Réinitialisation de votre mot de passe", (
        "Bonjour,\n\n"
        "Une réinitialisation du mot de passe a été demandée pour votre compte. "
        f"Ce lien est valable {ttl} minutes et ne fonctionne qu'une fois :\n\n"
        f"{_url('/reset-password?token=' + token)}\n\n"
        "Si vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail : "
        "votre mot de passe reste inchangé."
    ))


def send_password_changed(to: str) -> bool:
    return send(to, "Votre mot de passe a été modifié", (
        "Bonjour,\n\n"
        "Le mot de passe de votre compte vient d'être modifié et vos sessions ouvertes ont été "
        "fermées.\n\n"
        "Si vous n'êtes pas à l'origine de ce changement, réinitialisez votre mot de passe "
        f"immédiatement : {_url('/forgot-password')}"
    ))


def send_scan_finished(to: str, scan_id: str, domain: str, level: str, status: str) -> bool:
    # Results are deliberately not included: the report stays behind authentication.
    if status == "done":
        subject = f"Scan terminé : {domain}"
        text = f"Le scan {level} de {domain} est terminé. Consultez le rapport :"
    else:
        subject = f"Scan échoué : {domain}"
        text = f"Le scan {level} de {domain} a échoué. Détails :"
    return send(to, subject, (
        f"Bonjour,\n\n{text}\n\n{_url('/scans/' + scan_id)}\n\n"
        "Vous pouvez désactiver ces notifications depuis la page « Mon compte »."
    ))


def send_test(cfg: SmtpConfig, to: str) -> None:
    deliver(cfg, to, "E-mail de test", (
        "Bonjour,\n\n"
        "Cet e-mail confirme que la configuration SMTP enregistrée dans l'administration "
        "fonctionne."
    ))


def send_account_deleted(to: str) -> bool:
    return send(to, "Votre compte a été supprimé", (
        "Bonjour,\n\n"
        "Votre compte, vos domaines et vos résultats de scan ont été supprimés. "
        "Seul le journal légal des scans demandés est conservé.\n\n"
        "Merci d'avoir utilisé le service."
    ))
