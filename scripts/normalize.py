#!/usr/bin/env python3
"""
normalize.py — Modularized Universal Parser
Merges any tool's JSON output into a single final-security-report.json.
"""

import json
import os
import sys
from datetime import datetime, timezone

# Resolve base directories
BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
OUTPUT_FILE = os.path.join(BASE_DIR, "final-security-report.json")

def process_trufflehog(report_path: str) -> list:
    findings = []
    if not os.path.isfile(report_path): return findings
    with open(report_path, encoding="utf-8") as f:
        # TruffleHog outputs NDJSON (newline-delimited JSON)
        for line in f:
            if not line.strip(): continue
            try:
                data = json.loads(line)
                # TruffleHog v3 schema
                source_info = data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
                findings.append({
                    "tool"        : "trufflehog",
                    "severity"    : "CRITICAL",
                    "title"       : f"Secret found: {data.get('DetectorName', 'Unknown')}",
                    "rule_id"     : data.get("DetectorName", "unknown"),
                    "file"        : source_info.get("file", ""),
                    "line"        : source_info.get("line", 0),
                    "match"       : data.get("Raw", "Redacted")[:50],
                })
            except: continue
    return findings

def process_gitleaks(report_path: str) -> list:
    findings = []
    if not os.path.isfile(report_path): return findings
    with open(report_path, encoding="utf-8") as f:
        try:
            data = json.load(f)
            for leak in data:
                findings.append({
                    "tool"        : "gitleaks",
                    "severity"    : "CRITICAL",
                    "title"       : leak.get("Description", "Secret found"),
                    "rule_id"     : leak.get("RuleID", "unknown"),
                    "file"        : leak.get("File", ""),
                    "line"        : leak.get("StartLine", 0),
                    "match"       : leak.get("Match", ""),
                })
        except: pass
    return findings

def process_semgrep(report_path: str) -> list:
    findings = []
    if not os.path.isfile(report_path): return findings
    with open(report_path, encoding="utf-8") as f:
        try:
            data = json.load(f)
            for r in data.get("results", []):
                meta = r.get("extra", {})
                findings.append({
                    "tool"       : "semgrep",
                    "severity"   : meta.get("severity", "WARNING").upper(),
                    "title"      : meta.get("message", r.get("check_id", "Finding")),
                    "rule_id"    : r.get("check_id", ""),
                    "file"       : r.get("path", ""),
                    "line"       : r.get("start", {}).get("line", 0),
                    "code"       : meta.get("lines", ""),
                })
        except: pass
    return findings

def process_trivy(report_path: str) -> list:
    findings = []
    if not os.path.isfile(report_path): return findings
    with open(report_path, encoding="utf-8") as f:
        try:
            data = json.load(f)
            for r in data.get("Results", []):
                target = r.get("Target", "")
                for v in r.get("Vulnerabilities", []):
                    findings.append({
                        "tool"             : "trivy",
                        "severity"         : v.get("Severity", "UNKNOWN").upper(),
                        "title"            : v.get("Title", "Dependency vulnerability"),
                        "rule_id"          : v.get("VulnerabilityID", ""),
                        "package"          : v.get("PkgName", ""),
                        "manifest_path"    : target,
                    })
        except: pass
    return findings

def process_compliance(report_path: str, type_prefix: str) -> list:
    findings = []
    if not os.path.isfile(report_path): return findings
    with open(report_path, encoding="utf-8") as f:
        try:
            data = json.load(f)
            for r in data.get("results", []):
                meta = r.get("extra", {})
                findings.append({
                    "tool"       : "compliance",
                    "severity"   : meta.get("severity", "WARNING").upper(),
                    "title"      : f"{type_prefix}: {meta.get('message', r.get('check_id'))}",
                    "rule_id"    : r.get("check_id", ""),
                    "file"       : r.get("path", ""),
                    "line"       : r.get("start", {}).get("line", 0),
                })
        except: pass
    return findings

def process_claude(report_path: str) -> list:
    findings = []
    if not os.path.isfile(report_path): return findings
    with open(report_path, encoding="utf-8") as f:
        try:
            data = json.load(f)
            for leaf in data:
                findings.append({
                    "tool"        : "claude",
                    "severity"    : leaf.get("severity", "MEDIUM").upper(),
                    "title"       : leaf.get("title", "Claude Finding"),
                    "rule_id"     : leaf.get("rule_id", "unknown"),
                    "file"        : leaf.get("file", ""),
                    "line"        : leaf.get("line", 0),
                    "match"       : leaf.get("match", ""),
                })
        except: pass
    return findings

def main():
    print(f"[normalize] 🚀 Normalizing findings...")
    
    # Search in current directory (CI) or root (Local)
    search_dirs = [".", BASE_DIR, os.path.join(BASE_DIR, "scan-reports")]
    
    def find_report(filename):
        for d in search_dirs:
            p = os.path.join(d, filename)
            if os.path.isfile(p): return p
        return ""

    all_findings = []
    all_findings += process_trufflehog(find_report("truffhog-report.json"))
    all_findings += process_trufflehog(find_report("trufflehog-report.json"))
    all_findings += process_gitleaks(find_report("gitleaks-report.json"))
    all_findings += process_semgrep(find_report("semgrep-report.json"))
    all_findings += process_trivy(find_report("dependency-report.json"))
    all_findings += process_compliance(find_report("soc2-report.json"), "SOC2")
    all_findings += process_compliance(find_report("hipaa-report.json"), "HIPAA")
    all_findings += process_claude(find_report("claude-report.json"))

    # Smart Upgrades (e.g. if Semgrep finds an 'audit' issue, tag it as compliance)
    soc2_keywords = ["audit", "logging", "encryption", "tls", "ssl", "auth", "login"]
    hipaa_keywords = ["hipaa", "phi", "patient", "medical", "health", "history", "ssn"]
    
    for f in all_findings:
        text = (f.get("title", "") + " " + f.get("rule_id", "")).lower()
        if any(kw in text for kw in soc2_keywords) and f["tool"] != "compliance":
            f["tool"] = "compliance"
        elif any(kw in text for kw in hipaa_keywords):
            if f["tool"] != "compliance": f["tool"] = "compliance"
            if not any(f["title"].startswith(p) for p in ["HIPAA:", "SOC2:"]):
                f["title"] = f"HIPAA: {f['title']}"

    # Calculate Summary
    summary = {
        "total_findings": len(all_findings),
        "gitleaks":  sum(1 for f in all_findings if f["tool"] in ["gitleaks", "trufflehog"]),
        "semgrep":   sum(1 for f in all_findings if f["tool"] == "semgrep"),
        "dependency": sum(1 for f in all_findings if f["tool"] == "trivy"),
        "compliance": sum(1 for f in all_findings if f["tool"] == "compliance"),
        "claude":     sum(1 for f in all_findings if f["tool"] == "claude"),
        "soc2_count":  sum(1 for f in all_findings if "SOC2" in f["title"] and f["tool"] == "compliance"),
        "hipaa_count": sum(1 for f in all_findings if "HIPAA" in f["title"] and f["tool"] == "compliance"),
        "by_severity": {}
    }
    
    for f in all_findings:
        sev = f.get("severity", "UNKNOWN")
        summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(), "summary": summary, "findings": all_findings}, f, indent=2)

    print(f"[normalize] ✅ Report merged: {len(all_findings)} findings.")

if __name__ == "__main__":
    main()
