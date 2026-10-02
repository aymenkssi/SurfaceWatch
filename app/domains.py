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


# Why a verification failed, so the UI can say what to fix instead of a generic message.
TXT_OK = "ok"
TXT_NOT_FOUND = "not_found"          # no TXT record at the expected name
TXT_MISMATCH = "mismatch"            # TXT record(s) found, none with the expected token
TXT_DOUBLED_NAME = "doubled_name"    # record created at <name>.<domain> (provider appended the zone)


@dataclass(frozen=True)
class TxtCheck:
    reason: str
    found: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.reason == TXT_OK


def _clean_txt(value: str) -> str:
    # Some DNS panels store the quotes or stray spaces the user pasted along with the token.
    return value.strip().strip('"').strip()


def _authoritative_resolver(name: str, timeout: float) -> dns.resolver.Resolver | None:
    """Resolver pointed at the zone's authoritative servers, or None if they can't be found.

    Asking them directly avoids negative caching: a resolver that answered NXDOMAIN
    before the record was created would keep saying so until the SOA minimum TTL expires.
    """
    system = dns.resolver.Resolver()
    system.lifetime = timeout
    try:
        zone = dns.resolver.zone_for_name(name, resolver=system)
        addresses: list[str] = []
        for ns in system.resolve(zone, "NS"):
            for rtype in ("A", "AAAA"):
                try:
                    addresses += [a.to_text() for a in system.resolve(ns.target, rtype)]
                except dns.exception.DNSException:
                    continue
    except dns.exception.DNSException:
        return None
    if not addresses:
        return None
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = addresses
    resolver.lifetime = timeout
    return resolver


def _txt_values(resolver: dns.resolver.Resolver, name: str) -> list[str] | None:
    """TXT values at name ([] if none), or None if the lookup itself failed."""
    try:
        answers = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        return None
    # A TXT record can be split into several strings; join them.
    return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]


def lookup_txt_record(record_name: str, expected_value: str, timeout: float = 5.0) -> TxtCheck:
    """Check that a TXT record at record_name holds expected_value, and say why not."""
    resolvers = [r for r in (_authoritative_resolver(record_name, timeout),) if r is not None]
    system = dns.resolver.Resolver()
    system.lifetime = timeout
    resolvers.append(system)

    values: list[str] = []
    for resolver in resolvers:
        found = _txt_values(resolver, record_name)
        if found is not None:
            values = found
            break

    if any(hmac.compare_digest(_clean_txt(v), expected_value) for v in values):
        return TxtCheck(TXT_OK, tuple(values))
    if values:
        return TxtCheck(TXT_MISMATCH, tuple(values))

    # Most DNS panels append the zone to the name: pasting the full name creates
    # _surfacewatch-verify.example.fr.example.fr. Detect it to tell the user.
    domain = record_name.split(".", 1)[1]
    doubled = _txt_values(resolvers[0], f"{record_name}.{domain}") or []
    if any(_clean_txt(v) == expected_value for v in doubled):
        return TxtCheck(TXT_DOUBLED_NAME, tuple(doubled))
    return TxtCheck(TXT_NOT_FOUND)


def check_txt_record(record_name: str, expected_value: str, timeout: float = 5.0) -> bool:
    """Return True if a TXT record at record_name contains expected_value."""
    return lookup_txt_record(record_name, expected_value, timeout).ok
