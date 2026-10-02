"""Database models: users, domains (ownership challenge), scans and the audit log."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime | None) -> datetime | None:
    """SQLite drops tzinfo; treat naive datetimes read back from the DB as UTC."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(100))
    # Admins can see platform stats and manually validate domain ownership.
    # Granted only from the server CLI (python -m app.cli make-admin), never through the API.
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    # E-mail when one of the user's scans finishes (only if SMTP is configured).
    notify_scan_done: Mapped[bool] = mapped_column(Boolean, default=True)
    # Access tokens issued before this instant are rejected (set on password reset).
    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    # When an admin last reset this user's daily scan quota: scans created at or before
    # this instant no longer count toward the per-level daily limit.
    scan_quota_reset_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    domains: Mapped[list[Domain]] = relationship(
        back_populates="user", cascade="all, delete-orphan")
    scans: Mapped[list[Scan]] = relationship(back_populates="user", cascade="all, delete-orphan")
    reset_tokens: Mapped[list[PasswordResetToken]] = relationship(
        back_populates="user", cascade="all, delete-orphan")


class Domain(Base):
    __tablename__ = "domains"
    __table_args__ = (UniqueConstraint("user_id", "name"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(253))  # always normalize_domain() output
    record_name: Mapped[str] = mapped_column(String(300))
    record_value: Mapped[str] = mapped_column(String(100))
    token_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # "dns" (TXT record checked) or "manual" (validated by an admin, see AuditLog).
    verification_method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    verified_by: Mapped[str | None] = mapped_column(String(32), nullable=True)  # admin user id
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped[User] = relationship(back_populates="domains")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    domain: Mapped[str] = mapped_column(String(253))
    level: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued/running/done/failed
    job_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    events: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="scans")


class PasswordResetToken(Base):
    """Single-use, expiring password reset token. Only its SHA-256 hash is stored."""

    __tablename__ = "password_reset_tokens"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped[User] = relationship(back_populates="reset_tokens")


class AuditLog(Base):
    """One row per scan request (CLAUDE.md rule 4), per admin action on a domain and per
    sensitive account action (password reset, account deletion).

    Deliberately not a foreign key to users: the trail must survive account deletion.
    """

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(32), index=True)
    user_email: Mapped[str] = mapped_column(String(254))
    action: Mapped[str] = mapped_column(String(40))
    domain: Mapped[str] = mapped_column(String(253))
    level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Explicit user consent recorded for aggressive levels (advanced brute-force).
    consent: Mapped[bool] = mapped_column(Boolean, default=False)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Free-form context, e.g. the domain owner and the admin's reason for a manual validation.
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class SmtpSettings(Base):
    """Outgoing e-mail configuration edited from the admin page (single row, id=1).

    When this row exists it takes precedence over the SMTP_* environment variables.
    The SMTP password / API key is stored encrypted (see app.crypto), never in clear.
    """

    __tablename__ = "smtp_settings"

    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    host: Mapped[str] = mapped_column(String(253), default="")
    port: Mapped[int] = mapped_column(default=587)
    security: Mapped[str] = mapped_column(String(10), default="starttls")  # starttls|ssl|none
    username: Mapped[str] = mapped_column(String(254), default="")
    password_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    from_address: Mapped[str] = mapped_column(String(254), default="")
    public_url: Mapped[str] = mapped_column(String(300), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(254), nullable=True)  # admin e-mail
