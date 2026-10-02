"""Symmetric encryption of secrets stored in the database (e.g. the SMTP password).

The key is derived from SECRET_KEY, so a database dump alone does not reveal the secret.
Changing SECRET_KEY makes stored secrets unreadable: they must then be entered again.
"""

from __future__ import annotations

import base64
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import get_settings


@lru_cache
def _fernet(secret_key: str) -> Fernet:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"surfacewatch/db-secrets/v1").derive(secret_key.encode())
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(value: str) -> str:
    return _fernet(get_settings().secret_key).encrypt(value.encode()).decode()


def decrypt(token: str) -> str | None:
    """Return the clear value, or None if it was encrypted with another SECRET_KEY."""
    try:
        return _fernet(get_settings().secret_key).decrypt(token.encode()).decode()
    except InvalidToken:
        return None
