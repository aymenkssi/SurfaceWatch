"""Password hashing and JWT bearer auth (same scheme as the Waselni backend)."""

from __future__ import annotations

from datetime import timedelta

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import User, as_utc, utcnow

JWT_ALGORITHM = "HS256"
_bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


def create_access_token(user_id: str) -> str:
    settings = get_settings()
    now = utcnow()
    payload = {
        "sub": user_id,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_ttl_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=JWT_ALGORITHM)


def _unauthorized(detail: str = "not authenticated") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail,
                         headers={"WWW-Authenticate": "Bearer"})


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise _unauthorized()
    try:
        payload = jwt.decode(credentials.credentials, get_settings().secret_key,
                             algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise _unauthorized("token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise _unauthorized("invalid token") from exc
    if payload.get("type") != "access":
        raise _unauthorized("invalid token")
    user = db.get(User, payload.get("sub"))
    if user is None:
        raise _unauthorized("unknown user")
    # A password reset closes every session opened before it.
    changed = as_utc(user.password_changed_at)
    if changed is not None and payload.get("iat", 0) < int(changed.timestamp()):
        raise _unauthorized("token expired")
    return user


def get_current_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin only")
    return user
