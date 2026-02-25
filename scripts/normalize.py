#!/usr/bin/env python3
"""
normalize.py — Merges Gitleaks, Semgrep, and Dependabot scan reports
into a single final-security-report.json.

Run locally:  python scripts/normalize.py
Run in CI:    python scripts/normalize.py   (after download-artifact step)

Directory layout expected (produced by download-artifact@v4 with path=scan-reports):
  scan-reports/
    gitleaks-report/gitleaks-report.json
    semgrep-report/semgrep-report.json
    dependency-report/dependency-report.json
"""

import json
import os
import sys
from datetime import datetime, timezone

REPORTS_DIR   = os.path.join(os.path.dirname(__file__), "..", "scan-reports")
OUTPUT_FILE   = os.path.join(os.path.dirname(__file__), "..", "final-security-report.json")


# ─────────────────────────────────────────────────────────────────────────────
# GITLEAKS  — JSON output schema: list of "leak" objects
# ─────────────────────────────────────────────────────────────────────────────
def process_gitleaks(report_path: str) -> list:
    findings = []
    if not os.path.isfile(report_path):
        print(f"[normalize] ⚠️  Gitleaks report not found at {report_path} — skipping")
        return findings

    with open(report_path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[normalize] ⚠️  Could not parse Gitleaks report: {e}")
            return findings

    if not isinstance(data, list):
        print("[normalize] ⚠️  Unexpected Gitleaks report format — expected a list")
        return findings

    for leak in data:
        findings.append({
            "tool"        : "gitleaks",
            "severity"    : "CRITICAL",
            "title"       : leak.get("Description", "Secret found"),
            "rule_id"     : leak.get("RuleID", "unknown"),
            "file"        : leak.get("File", ""),
            "line"        : leak.get("StartLine", 0),
            "commit"      : leak.get("Commit", ""),
            "author"      : leak.get("Author", ""),
            "match"       : leak.get("Match", ""),
            "fingerprint" : leak.get("Fingerprint", ""),
        })

    print(f"[normalize] Gitleaks: {len(findings)} finding(s)")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# SEMGREP  — JSON output schema: {"results": [...], "errors": [...]}
# ─────────────────────────────────────────────────────────────────────────────
def process_semgrep(report_path: str) -> list:
    findings = []
    if not os.path.isfile(report_path):
        print(f"[normalize] ⚠️  Semgrep report not found at {report_path} — skipping")
        return findings

    with open(report_path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[normalize] ⚠️  Could not parse Semgrep report: {e}")
            return findings

    results = data.get("results", [])
    for r in results:
        meta     = r.get("extra", {})
        severity = meta.get("severity", "WARNING").upper()
        findings.append({
            "tool"       : "semgrep",
            "severity"   : severity,
            "title"      : meta.get("message", r.get("check_id", "Finding")),
            "rule_id"    : r.get("check_id", ""),
            "file"       : r.get("path", ""),
            "line"       : r.get("start", {}).get("line", 0),
            "code"       : meta.get("lines", ""),
            "cwe"        : meta.get("metadata", {}).get("cwe", ""),
            "owasp"      : meta.get("metadata", {}).get("owasp", ""),
        })

    errors = data.get("errors", [])
    if errors:
        print(f"[normalize] ⚠️  Semgrep reported {len(errors)} error(s) during scan")

    print(f"[normalize] Semgrep: {len(findings)} finding(s)")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# PIP-AUDIT — JSON output schema
# ─────────────────────────────────────────────────────────────────────────────
def process_pip_audit(report_path: str) -> list:
    findings = []
    if not os.path.isfile(report_path):
        print(f"[normalize] ⚠️  Dependency report not found at {report_path} — skipping")
        return findings

    with open(report_path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[normalize] ⚠️  Could not parse Dependency report: {e}")
            return findings

    # Data is expected to be {"dependencies": [{"name": "...", "version": "...", "vulns": [...]}]}
    dependencies = data.get("dependencies", [])

    for dep in dependencies:
        pkg_name = dep.get("name", "")
        pkg_vers = dep.get("version", "")
        vulns = dep.get("vulns", [])
        
        for v in vulns:
            # pip-audit currently doesn't map full descriptions to a unified severity directly in all JSONs,
            # but usually it's considered HIGH/CRITICAL if it has a CVE.
            findings.append({
                "tool"             : "pip-audit",
                "severity"         : "CRITICAL",
                "title"            : v.get("fix_versions", ["No fix"])[0] + " fix available",
                "rule_id"          : v.get("id", ""),
                "cve"              : v.get("id", ""),
                "package"          : pkg_name,
                "ecosystem"        : "pip",
                "affected_range"   : pkg_vers,
                "fixed_in"         : ", ".join(v.get("fix_versions", [])),
                "manifest_path"    : "requirements.txt",
                "alert_url"        : f"https://osv.dev/vulnerability/{v.get('id', '')}",
            })

    print(f"[normalize] pip-audit: {len(findings)} finding(s)")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    gitleaks_path   = os.path.join(REPORTS_DIR, "gitleaks-report",    "gitleaks-report.json")
    semgrep_path    = os.path.join(REPORTS_DIR, "semgrep-report",     "semgrep-report.json")
    dependency_path = os.path.join(REPORTS_DIR, "dependency-report",  "dependency-report.json")

    all_findings  = []
    all_findings += process_gitleaks(gitleaks_path)
    all_findings += process_semgrep(semgrep_path)
    all_findings += process_pip_audit(dependency_path)

    # Count by tool
    gitleaks_count     = sum(1 for f in all_findings if f["tool"] == "gitleaks")
    semgrep_count      = sum(1 for f in all_findings if f["tool"] == "semgrep")
    dependency_count   = sum(1 for f in all_findings if f["tool"] == "pip-audit")

    # Count by severity
    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    report = {
        "generated_at" : datetime.now(timezone.utc).isoformat(),
        "summary"      : {
            "total_findings" : len(all_findings),
            "gitleaks"       : gitleaks_count,
            "semgrep"        : semgrep_count,
            "dependabot"     : dependency_count,
            "by_severity"    : severity_counts,
        },
        "findings"     : all_findings,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n[normalize] ✅  Final report written to: {os.path.abspath(OUTPUT_FILE)}")
    print(f"[normalize]     Total findings: {len(all_findings)}")
    print(f"[normalize]     Breakdown — Gitleaks: {gitleaks_count} | Semgrep: {semgrep_count} | pip-audit: {dependency_count}")


if __name__ == "__main__":
    main()
