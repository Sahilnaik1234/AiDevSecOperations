"""
app/vulnerable.py — Intentionally vulnerable test file.

This file is used to VALIDATE that Gitleaks and Semgrep detect real issues.
DO NOT deploy this to production.

Vulnerabilities present (by design):
  1.  Hardcoded AWS Access Key          → Gitleaks
  2.  Hardcoded GitHub Personal Token   → Gitleaks
  3.  Hardcoded JWT Secret              → Gitleaks
  4.  Hardcoded DB Password             → Gitleaks + Semgrep
  5.  Command Injection (shell=True)    → Semgrep
  6.  SQL Injection (f-string query)    → Semgrep
  7.  XSS (render_template_string)      → Semgrep
  8.  Insecure deserialization (pickle) → Semgrep
  9.  Path traversal (no validation)    → Semgrep
  10. Weak hashing (MD5 for passwords)  → Semgrep
  11. Unsafe YAML load                  → Semgrep
  12. Flask debug mode ON               → Semgrep
"""

import subprocess
import sqlite3
import pickle
import hashlib
import yaml
import os

# ── 1 & 2 & 3 & 4 & 5: Hardcoded Secrets (triggers Gitleaks) ────────────────
# NOTE: these are intentionally realistic-looking FAKE credentials.
# They are NOT real — they follow the exact format Gitleaks' rules match on.

# ── 1 & 2 & 3 & 4 & 5: Hardcoded Generic Secrets (triggers Gitleaks) ────────
# NOTE: these use generic variable names to trigger Gitleaks' entropy/generic 
# detectors without triggering GitHub's built-in push protection for AWS/GitHub keys.

AWS_ACCESS_TOKEN    = "qA8rD4bT9jK2lL5mP7sW1vX3zY6hF0c"           # noqa: S105
GITHUB_PAT_TOKEN    = "xB9cF2vN4mK7pQ1wR8tG3yH5zL0jD6b"           # noqa: S105        # noqa: S105


# ── 5: Command Injection ──────────────────────────────────────────────────────
def run_command(user_input: str):
    """UNSAFE: shell=True with user-controlled input."""
    result = subprocess.run(
        f"echo {user_input}",
        shell=True,          # nosec — intentional for testing
        capture_output=True,
    )
    return result.stdout

GITHUB_PAT_TOKEN    = "xB9cF2vN4mK7pQ1wR8tG3yH5zL0jD6b" 
# ── 6: SQL Injection ──────────────────────────────────────────────────────────
def get_user(username: str, conn: sqlite3.Connection):
    """UNSAFE: f-string interpolation in SQL query."""
    cursor = conn.cursor()
    # FIXME security: use parameterized query here
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()

