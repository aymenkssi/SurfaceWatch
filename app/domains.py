"""Domain normalization, verification tokens and DNS TXT ownership checks.

Every user-supplied domain MUST go through normalize_domain() before any other use.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import dns.exception
import dns.resolver

from app.config import get_settings

# RFC 1035-ish label: 1-63 chars, alnum and hyphens, no leading/trailing hyphen
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class InvalidDomain(ValueError):
    pass


def normalize_domain(raw: str) -> str:
    """Return a clean, lowercase registrable-looking domain or raise InvalidDomain.

    Strips scheme, path, port, trailing dot and leading 'www.'.
    Rejects IPs, single labels, wildcards and anything non-DNS.
    """
    if not raw or not isinstance(raw, str):
        raise InvalidDomain("empty domain")

    value = raw.strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)  # scheme
    value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in value:
        raise InvalidDomain("credentials or e-mail not allowed")
    value = value.split(":", 1)[0].rstrip(".")
    if value.startswith("www."):
        value = value[4:]

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidDomain("invalid internationalized domain") from exc

    if len(value) > 253:
        raise InvalidDomain("domain too long")

    labels = value.split(".")
    if len(labels) < 2:
        raise InvalidDomain("a full domain is required (e.g. example.fr)")
    if not all(_LABEL_RE.match(label) for label in labels):
        raise InvalidDomain("invalid characters in domain")
    if labels[-1].isdigit():
        raise InvalidDomain("IP addresses are not accepted")

    return value


@dataclass(frozen=True)
class VerificationChallenge:
    domain: str
    record_name: str
    record_value: str
    expires_at: datetime


def make_token(user_id: str, domain: str) -> str:
    """Deterministic per (user, domain) token, bound to the server secret.

    A random nonce is mixed in so a user can regenerate a new token.
    """
    nonce = secrets.token_hex(8)
    key = get_settings().secret_key.encode()
    digest = hmac.new(key, f"{user_id}|{domain}|{nonce}".encode(), hashlib.sha256).hexdigest()
    return f"{nonce}{digest[:24]}"


def create_challenge(user_id: str, raw_domain: str) -> VerificationChallenge:
    settings = get_settings()
    domain = normalize_domain(raw_domain)
    token = make_token(user_id, domain)
    return VerificationChallenge(
        domain=domain,
        record_name=f"{settings.verify_record_prefix}.{domain}",
        record_value=f"{settings.verify_token_prefix}{token}",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=settings.verify_token_ttl_hours),
    )


def check_txt_record(record_name: str, expected_value: str, timeout: float = 5.0) -> bool:
    """Return True if a TXT record at record_name contains exactly expected_value."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(record_name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout):
        return False

    for rdata in answers:
        # A TXT record can be split into several strings; join them.
        value = b"".join(rdata.strings).decode("utf-8", errors="replace")
        if hmac.compare_digest(value, expected_value):
            return True
    return False
