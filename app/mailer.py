"""Outgoing e-mail over a self-configured SMTP server (no embedded provider key).

Every e-mail feature is optional: when SMTP_HOST / SMTP_FROM are unset, `enabled()` is False
and `send()` is a no-op. Sending never raises, so a mail outage cannot break a request or a job.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from app.config import get_settings

log = logging.getLogger(__name__)

# Replaced in tests to capture messages instead of opening an SMTP connection.
_transport = None


def enabled() -> bool:
    s = get_settings()
    return bool(s.smtp_host and s.smtp_from)


def _smtp_send(msg: EmailMessage) -> None:
    s = get_settings()
    context = ssl.create_default_context()
    if s.smtp_security == "ssl":
        smtp = smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, timeout=s.smtp_timeout_seconds,
                                context=context)
    else:
        smtp = smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=s.smtp_timeout_seconds)
    with smtp:
        if s.smtp_security == "starttls":
            smtp.starttls(context=context)
        if s.smtp_user:
            smtp.login(s.smtp_user, s.smtp_password)
        smtp.send_message(msg)


def send(to: str, subject: str, body: str) -> bool:
    """Send a plain-text e-mail. Returns True when it was handed to the SMTP server."""
    if not enabled():
        return False
    s = get_settings()
    msg = EmailMessage()
    msg["From"] = formataddr((s.app_name, s.smtp_from))
    msg["To"] = to
    msg["Subject"] = f"[{s.app_name}] {subject}"
    msg["Message-ID"] = make_msgid(domain=s.smtp_from.rpartition("@")[2] or None)
    msg.set_content(f"{body}\n\n--\n{s.app_name} · {s.public_url}\n")
    try:
        (_transport or _smtp_send)(msg)
    except Exception:  # noqa: BLE001 - mail is best effort
        log.exception("failed to send e-mail %r", subject)
        return False
    return True


def _url(path: str) -> str:
    return get_settings().public_url.rstrip("/") + path


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


def send_account_deleted(to: str) -> bool:
    return send(to, "Votre compte a été supprimé", (
        "Bonjour,\n\n"
        "Votre compte, vos domaines et vos résultats de scan ont été supprimés. "
        "Seul le journal légal des scans demandés est conservé.\n\n"
        "Merci d'avoir utilisé le service."
    ))
