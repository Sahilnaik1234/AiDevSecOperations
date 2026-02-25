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

# Gitleaks rule: aws-access-key-id  (AKIA[0-9A-Z]{16})
AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7FKTEST"           # noqa: S105

# Gitleaks rule: aws-secret-access-key  (40-char base64-ish)
AWS_SECRET_ACCESS_KEY = "kWqH7zLm3nPxRvT9uYsD2aJgF5oK8cBt1eWqXmZl"  # noqa: S105

# Gitleaks rule: github-pat  (ghp_ + 36 alphanumeric)
GITHUB_TOKEN          = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"    # noqa: S105

# Gitleaks rule: jwt  (three base64 segments separated by dots)
JWT_SECRET            = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  # noqa: S105

# Gitleaks rule: generic-password (variable named 'password' with high-entropy value)
DB_PASSWORD           = "Tr0ub4dor&3_SecureDBPass#2024!"              # noqa: S105


# ── 5: Command Injection ──────────────────────────────────────────────────────
def run_command(user_input: str):
    """UNSAFE: shell=True with user-controlled input."""
    result = subprocess.run(
        f"echo {user_input}",
        shell=True,          # nosec — intentional for testing
        capture_output=True,
    )
    return result.stdout


# ── 6: SQL Injection ──────────────────────────────────────────────────────────
def get_user(username: str, conn: sqlite3.Connection):
    """UNSAFE: f-string interpolation in SQL query."""
    cursor = conn.cursor()
    # FIXME security: use parameterized query here
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()


# ── 7: XSS via render_template_string ────────────────────────────────────────
try:
    from flask import Flask, request, render_template_string
    app = Flask(__name__)

    @app.route("/greet")
    def greet():
        """UNSAFE: user input rendered directly into HTML template."""
        name = request.args.get("name", "")
        return render_template_string(f"<h1>Hello, {name}!</h1>")  # nosec

except ImportError:
    app = None  # Flask not installed; skip


# ── 8: Insecure Deserialization ───────────────────────────────────────────────
def deserialize_data(raw_bytes: bytes):
    """UNSAFE: pickle.loads with untrusted data."""
    return pickle.loads(raw_bytes)  # nosec — intentional


# ── 9: Path Traversal ─────────────────────────────────────────────────────────
def read_file(filename: str) -> str:
    """UNSAFE: no path validation — allows reading /etc/passwd etc."""
    with open(filename, "r") as f:  # nosec
        return f.read()


# ── 10: Weak Hashing ─────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    """UNSAFE: MD5 is cryptographically broken for password hashing."""
    return hashlib.md5(password.encode()).hexdigest()  # nosec


# ── 11: Unsafe YAML Load ──────────────────────────────────────────────────────
def parse_config(yaml_string: str):
    """UNSAFE: yaml.load without a safe Loader allows arbitrary code execution."""
    return yaml.load(yaml_string)  # nosec


# ── 12: Flask Debug Mode ON ───────────────────────────────────────────────────
if __name__ == "__main__" and app:
    app.run(debug=True, host="0.0.0.0")  # nosec — intentional for testing
