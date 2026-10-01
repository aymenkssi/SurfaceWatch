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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    domains: Mapped[list[Domain]] = relationship(
        back_populates="user", cascade="all, delete-orphan")
    scans: Mapped[list[Scan]] = relationship(back_populates="user", cascade="all, delete-orphan")


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


class AuditLog(Base):
    """One row per scan request (CLAUDE.md rule 4).

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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
