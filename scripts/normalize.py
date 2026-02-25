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
        rule_id  = r.get("check_id", "")
        
        # Categorize HIPAA findings for the Compliance section in UI
        tool_name = "semgrep"
        if "hipaa" in rule_id.lower():
            tool_name = "checkov" # Map to the compliance filter/card

        findings.append({
            "tool"       : tool_name,
            "severity"   : severity,
            "title"      : meta.get("message", rule_id),
            "rule_id"    : rule_id,
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
# TRIVY — JSON output schema
# ─────────────────────────────────────────────────────────────────────────────
def process_trivy(report_path: str) -> list:
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

    # Trivy exports {"Results": [{"Target": "package.json", "Vulnerabilities": [...]}]}
    results = data.get("Results", [])

    for r in results:
        target = r.get("Target", "")
        vulns  = r.get("Vulnerabilities", [])
        
        for v in vulns:
            findings.append({
                "tool"             : "trivy",
                "severity"         : v.get("Severity", "UNKNOWN").upper(),
                "title"            : v.get("Title", "Dependency vulnerability"),
                "rule_id"          : v.get("VulnerabilityID", ""),
                "cve"              : v.get("VulnerabilityID", ""),
                "package"          : v.get("PkgName", ""),
                "ecosystem"        : target.split(".")[-1], # generic fallback
                "affected_range"   : v.get("InstalledVersion", ""),
                "fixed_in"         : v.get("FixedVersion", ""),
                "manifest_path"    : target,
                "alert_url"        : v.get("PrimaryURL", ""),
            })

    print(f"[normalize] Trivy: {len(findings)} finding(s)")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# CHECKOV (Compliance) — JSON output schema
# ─────────────────────────────────────────────────────────────────────────────
def process_checkov(report_path: str) -> list:
    findings = []
    if not os.path.isfile(report_path):
        print(f"[normalize] ⚠️  Compliance report not found at {report_path} — skipping")
        return findings

    with open(report_path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[normalize] ⚠️  Could not parse Compliance report: {e}")
            return findings

    # Checkov can return a single object or a list of objects if multiple frameworks used
    results_list = [data] if isinstance(data, dict) else data

    for result in results_list:
        # Robust access logic to handle null results/findings
        res_inner = result.get("results")
        if not res_inner:
            continue
            
        failed_checks = res_inner.get("failed_checks") or []
        
        for check in failed_checks:
            findings.append({
                "tool"       : "checkov",
                "severity"   : "HIGH", 
                "title"      : check.get("check_name", "Compliance violation"),
                "rule_id"    : check.get("check_id", ""),
                "file"       : check.get("file_path", ""),
                "line"       : check.get("file_line_range", [0, 0])[0], 
                "description": f"Compliance Check: {check.get('check_id')}",
                "alert_url"  : check.get("guideline", "")
            })

    print(f"[normalize] Checkov: {len(findings)} finding(s)")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    gitleaks_path   = os.path.join(REPORTS_DIR, "gitleaks-report",    "gitleaks-report.json")
    semgrep_path    = os.path.join(REPORTS_DIR, "semgrep-report",     "semgrep-report.json")
    dependency_path = os.path.join(REPORTS_DIR, "dependency-report",  "dependency-report.json")
    compliance_path = os.path.join(REPORTS_DIR, "compliance-report",  "compliance-report.json")

    all_findings  = []
    all_findings += process_gitleaks(gitleaks_path)
    all_findings += process_semgrep(semgrep_path)
    all_findings += process_trivy(dependency_path)
    all_findings += process_checkov(compliance_path)

    # Count by tool
    gitleaks_count     = sum(1 for f in all_findings if f["tool"] == "gitleaks")
    semgrep_count      = sum(1 for f in all_findings if f["tool"] == "semgrep")
    dependency_count   = sum(1 for f in all_findings if f["tool"] == "trivy")
    compliance_count   = sum(1 for f in all_findings if f["tool"] == "checkov")

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
            "dependency"     : dependency_count,
            "compliance"     : compliance_count,
            "by_severity"    : severity_counts,
        },
        "findings"     : all_findings,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n[normalize] ✅  Final report written to: {os.path.abspath(OUTPUT_FILE)}")
    print(f"[normalize]     Total findings: {len(all_findings)}")
    print(f"[normalize]     Breakdown — Gitleaks: {gitleaks_count} | Semgrep: {semgrep_count} | Trivy: {dependency_count} | Checkov: {compliance_count}")


if __name__ == "__main__":
    main()
