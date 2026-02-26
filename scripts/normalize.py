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
# SOC2 COMPLIANCE — Semgrep
# ─────────────────────────────────────────────────────────────────────────────
def process_soc2(report_path: str) -> list:
    findings = []
    if not os.path.isfile(report_path):
        print(f"[normalize] ⚠️  SOC2 report MISSING at {report_path}")
        return findings

    with open(report_path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return findings

    results = data.get("results", [])
    for r in results:
        meta = r.get("extra", {})
        findings.append({
            "tool"       : "compliance", # Tagged for the compliance dashboard tab
            "severity"   : meta.get("severity", "WARNING").upper(),
            "title"      : f"SOC2: {meta.get('message', r.get('check_id'))}",
            "rule_id"    : r.get("check_id", ""),
            "file"       : r.get("path", ""),
            "line"       : r.get("start", {}).get("line", 0),
        })
    print(f"[normalize] ✅ Added {len(findings)} targeted SOC2 findings.")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# HIPAA COMPLIANCE — Semgrep
# ─────────────────────────────────────────────────────────────────────────────
def process_hipaa(report_path: str) -> list:
    findings = []
    if not os.path.isfile(report_path):
        print(f"[normalize] ⚠️  HIPAA report MISSING at {report_path}")
        return findings

    with open(report_path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return findings

    results = data.get("results", [])
    for r in results:
        meta = r.get("extra", {})
        findings.append({
            "tool"       : "compliance", # Shared with SOC2 for the dashboard
            "severity"   : meta.get("severity", "WARNING").upper(),
            "title"      : f"HIPAA: {meta.get('message', r.get('check_id'))}",
            "rule_id"    : r.get("check_id", ""),
            "file"       : r.get("path", ""),
            "line"       : r.get("start", {}).get("line", 0),
        })
    print(f"[normalize] ✅ Added {len(findings)} targeted HIPAA findings.")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print(f"\n[normalize] Dashboard Merging Started...")
    
    # In CI, artifacts are downloaded into subdirectories. Locally, they might be flat.
    # We check multiple possible locations.
    report_locations = {
        "gitleaks"    : ["gitleaks-report/gitleaks-report.json", "gitleaks-report.json"],
        "semgrep"     : ["semgrep-report/semgrep-report.json",   "semgrep-report.json"],
        "dependency"  : ["dependency-report/dependency-report.json", "dependency-report.json"],
        "soc2"        : ["soc2-report/soc2-report.json",         "soc2-report.json"],
        "hipaa"       : ["hipaa-report/hipaa-report.json",       "hipaa-report.json"]
    }

    all_findings = []

    def get_path(key):
        for subpath in report_locations.get(key, []):
            full = os.path.join(REPORTS_DIR, subpath)
            if os.path.isfile(full): 
                print(f"[normalize] 📥 Located {key} report at: {subpath}")
                return full
        return ""

    # 1. Process all available reports
    all_findings += process_gitleaks(get_path("gitleaks"))
    all_findings += process_semgrep(get_path("semgrep"))
    all_findings += process_trivy(get_path("dependency"))
    all_findings += process_soc2(get_path("soc2"))
    all_findings += process_hipaa(get_path("hipaa"))

    # 2. COMPLIANCE UPGRADES (Capture issues from other tools)
    soc2_keywords = ["audit", "logging", "encryption", "tls", "ssl", "auth", "login"]
    hipaa_keywords = ["hipaa", "phi", "patient", "medical", "health", "history", "ssn"]
    
    upgrades = 0
    for f in all_findings:
        text = (f.get("title", "") + " " + f.get("rule_id", "")).lower()
        
        # Upgrade to Compliance for SOC2
        if any(kw in text for kw in soc2_keywords) and f["tool"] != "compliance":
            f["tool"] = "compliance"
            upgrades += 1
            
        # Upgrade for HIPAA (already categorized as compliance usually, but ensures prefix)
        elif any(kw in text for kw in hipaa_keywords):
            if f["tool"] != "compliance":
                f["tool"] = "compliance"
                upgrades += 1
            if not f["title"].startswith("HIPAA:") and not f["title"].startswith("SOC2:"):
                f["title"] = f"HIPAA: {f['title']}"

    if upgrades > 0:
        print(f"[normalize] 🧠 {upgrades} findings upgraded to 'Compliance' category.")

    # 3. Aggregation & Summary
    gitleaks_count     = sum(1 for f in all_findings if f["tool"] == "gitleaks")
    semgrep_count      = sum(1 for f in all_findings if f["tool"] == "semgrep")
    dependency_count   = sum(1 for f in all_findings if f["tool"] == "trivy")
    compliance_count   = sum(1 for f in all_findings if f["tool"] == "compliance")
    
    # Specific breakdown for summary JSON (Optional but useful)
    soc2_count = sum(1 for f in all_findings if "SOC2" in f["title"] and f["tool"] == "compliance")
    hipaa_count = sum(1 for f in all_findings if "HIPAA" in f["title"] and f["tool"] == "compliance")

    print(f"[normalize] 📊 Final Counts — Secrets: {gitleaks_count} | SAST: {semgrep_count} | SCA: {dependency_count} | Compliance: {compliance_count}")

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
            "soc2_count"     : soc2_count,
            "hipaa_count"    : hipaa_count,
            "by_severity"    : severity_counts,
        },
        "findings"     : all_findings,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n[normalize] ✅  Final report written to: {os.path.abspath(OUTPUT_FILE)}")
    print(f"[normalize]     Total findings: {len(all_findings)}")
    print(f"[normalize]     Breakdown — Secrets: {gitleaks_count} | SAST: {semgrep_count} | SCA: {dependency_count}")


if __name__ == "__main__":
    main()
