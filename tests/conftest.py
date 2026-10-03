import os
import tempfile

# Isolated SQLite DB for the whole test session; must be set before app modules import.
_tmp = tempfile.mkdtemp(prefix="sw-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["SECRET_KEY"] = "test-secret-key-with-enough-length-for-hs256"
os.environ["FRONTEND_DIST"] = f"{_tmp}/no-dist"
# Keep the worker hermetic: never reach the live CISA KEV / NVD feeds during tests.
# The vulnerability-inference logic is covered directly with injected lookups.
os.environ["VULN_LOOKUP_ENABLED"] = "false"
# Likewise never open real sockets to audit discovered services during tests; the audit
# logic is covered directly in test_audit.py with an injected probe.
os.environ["SELF_AUDIT_ENABLED"] = "false"
