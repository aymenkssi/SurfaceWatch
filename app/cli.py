"""Server-side admin commands (never exposed through the API).

    python -m app.cli make-admin <email>
    python -m app.cli revoke-admin <email>
"""

from __future__ import annotations

import sys

from sqlalchemy import select

from app.db import SessionLocal, init_db
from app.models import User


def set_admin(email: str, value: bool) -> bool:
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == email.strip().lower()))
        if user is None:
            return False
        user.is_admin = value
        db.commit()
        return True


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in ("make-admin", "revoke-admin"):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    init_db()
    if not set_admin(argv[1], argv[0] == "make-admin"):
        print(f"unknown user: {argv[1]}", file=sys.stderr)
        return 1
    print(f"{argv[1]}: admin={'yes' if argv[0] == 'make-admin' else 'no'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
