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


# Standard Secrets (will trigger Gitleaks)
AWS_ACCESS_TOKEN    = "qA8rD4bT9jK2lL5mP7sW1vX3zY6hF0c"
GITHUB_PAT_TOKEN    = "xB9cF2vN4mK7pQ1wR8tG3yH5zL0jD6b"

# High-Confidence Secrets (will trigger TruffleHog)
# Note: These are fake decoy strings in the correct format.
AWS_KEY_ID          = "AKIA2J5F6B7C8D9E0A1B"
AWS_SECRET_KEY      = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_CONNECTION_URL   = "postgres://admin:SuperSecretPassword123!@localhost:5432/production_db"


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
# ── 15: Insecure Deserialization (Technical Safeguard Violation) ──────────────
def insecure_deserialization(user_data):
    """
    VULNERABLE (Compliance): Using pickle.loads on untrusted data.
    This is a critical security violation that also fails HIPAA technical safeguards.
    """
    # Semgrep p/security-audit SHOULD catch this
    return pickle.loads(user_data) # nosec

# ── 13: HIPAA Compliance Violations ───────────────────────────────────────────
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def insecure_api_call():
    """
    VULNERABLE (HIPAA): Using insecure HTTP transmission for sensitive data.
    """
    import requests
    # HIPAA requires encryption in transit (HTTPS)
    requests.get("http://internal-health-system.local/api/records")

# ── 14: Cloud/Infra HIPAA Violations ──────────────────────────────────────────
import boto3

def insecure_s3_phi_storage():
    """
    VULNERABLE (HIPAA): Creating an S3 bucket for PHI without server-side encryption.
    HIPAA Requires Encryption at Rest.
    """
    s3 = boto3.client('s3')
    # Violation: No 'ServerSideEncryption' specified
    s3.create_bucket(Bucket='patient-medical-records-backup')


def hipaa_phi_eval_violation(patient_record_string):
    """
    ULTRA-VULNERABLE (HIPAA): Using eval() on PHI.
    This is a critical violation of technical safeguards.
    """
    # This WILL be caught by p/security-audit
    return eval(patient_record_string) # nosec
