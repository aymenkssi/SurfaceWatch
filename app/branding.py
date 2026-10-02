"""Branding for reports: the site logo (configured by an admin) and each user's own
logo. Both are stored as small `data:` URIs so they embed directly in the HTML/PDF
report with no file storage or external request.
"""

from __future__ import annotations

import base64
import binascii
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Branding

# Logos are embedded in every report, so they must stay small.
MAX_LOGO_BYTES = 256 * 1024
ALLOWED_LOGO_TYPES = {"image/png", "image/jpeg", "image/webp", "image/svg+xml", "image/gif"}
_DATA_URI = re.compile(r"^data:(?P<type>[\w.+/-]+);base64,(?P<payload>[A-Za-z0-9+/=\s]+)$")

DEFAULT_SITE_NAME = "SurfaceAttackWatch"
DEFAULT_ACCENT = "#2563eb"
_HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


def validate_logo(data_uri: str) -> str:
    """Return the cleaned `data:` URI for a logo, or raise ValueError.

    Only raster/vector image types are accepted and the decoded size is capped. An
    image used as <img src> never executes scripts, so an SVG logo is safe to embed.
    """
    match = _DATA_URI.match((data_uri or "").strip())
    if not match:
        raise ValueError("logo must be a base64 data URI")
    media_type = match.group("type").lower()
    if media_type not in ALLOWED_LOGO_TYPES:
        raise ValueError(f"unsupported image type: {media_type}")
    payload = re.sub(r"\s+", "", match.group("payload"))
    try:
        raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("logo is not valid base64") from exc
    if not raw:
        raise ValueError("logo is empty")
    if len(raw) > MAX_LOGO_BYTES:
        raise ValueError(f"logo is too large (max {MAX_LOGO_BYTES // 1024} KB)")
    return f"data:{media_type};base64,{payload}"


def validate_accent(color: str) -> str:
    color = (color or "").strip()
    if not _HEX_COLOR.match(color):
        raise ValueError("accent must be a hex colour like #2563eb")
    return color.lower()


def load_branding(db: Session) -> dict:
    """Site-level branding (logo, name, accent) with defaults when unset."""
    row = db.get(Branding, 1)
    return {
        "site_name": (row.site_name if row and row.site_name else DEFAULT_SITE_NAME),
        "site_logo": row.logo_data_uri if row else None,
        "accent": (row.accent_color if row and row.accent_color else DEFAULT_ACCENT),
    }
