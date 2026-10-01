"""SQLAlchemy engine and session helpers."""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def _make_engine(url: str):
    kwargs = {"future": True}
    if url.startswith("sqlite"):
        # SQLite is only used in dev/tests; the web app and worker share the file.
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(url, **kwargs)


engine = _make_engine(get_settings().database_url)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    """Create tables. TODO(v0.3): switch to Alembic migrations."""
    from app import models  # noqa: F401  (register models on Base.metadata)

    Base.metadata.create_all(engine)
    _add_missing_columns()


# Columns added after the first deployment: create_all() does not alter existing tables.
_LATE_COLUMNS = {
    "users": {"is_admin": "BOOLEAN NOT NULL DEFAULT FALSE"},
    "domains": {"verification_method": "VARCHAR(10)", "verified_by": "VARCHAR(32)"},
    "audit_log": {"details": "TEXT"},
}


def _add_missing_columns() -> None:
    inspector = inspect(engine)
    with engine.begin() as conn:
        for table, columns in _LATE_COLUMNS.items():
            existing = {c["name"] for c in inspector.get_columns(table)}
            for name, ddl in columns.items():
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
        # Domains verified before the column existed were all checked via DNS.
        conn.execute(text("UPDATE domains SET verification_method = 'dns' "
                          "WHERE verified AND verification_method IS NULL"))


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
