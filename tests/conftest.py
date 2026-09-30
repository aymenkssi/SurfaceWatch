import os
import tempfile

# Isolated SQLite DB for the whole test session; must be set before app modules import.
_tmp = tempfile.mkdtemp(prefix="sw-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["SECRET_KEY"] = "test-secret-key-with-enough-length-for-hs256"
os.environ["FRONTEND_DIST"] = f"{_tmp}/no-dist"
