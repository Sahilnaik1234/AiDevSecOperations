#!/usr/bin/env python3
import os
import sys
import json
import anthropic

def run_scan():
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("[Claude Scan] ❌ ANTHROPIC_API_KEY is not set.")
        sys.exit(1)
        
    client = anthropic.Anthropic(api_key=api_key)
    results = []
    
    # Files to scan
    SCAN_DIRS = ["app"]
    exts = [".js", ".py", ".java", ".go", ".php", ".rb"]
    
    files_to_scan = []
    for d in SCAN_DIRS:
        if not os.path.isdir(d): continue
        for root, _, files in os.walk(d):
            for f in files:
                if any(f.endswith(ext) for ext in exts):
                    files_to_scan.append(os.path.join(root, f))
                    
    if not files_to_scan:
        print("[Claude Scan] No files found to scan.")
        os.system("echo '[]' > claude-report.json")
        return

    print(f"[Claude Scan] 🚀 Scanning {len(files_to_scan)} files...")
    
    for f_path in files_to_scan:
        print(f"  - Analyzing: {f_path}")
        with open(f_path, "r", encoding="utf-8") as f:
            code = f.read()
            
        prompt = f"""You are a professional security researcher. Analyze the following source code for security vulnerabilities.
        Return ONLY a JSON array of objects with the following keys:
        - "severity": "CRITICAL", "HIGH", "MEDIUM", or "LOW"
        - "title": A short summary of the vulnerability
        - "rule_id": A concise ID for your rule
        - "file": "{f_path}"
        - "line": The approximate line number where the issue exists
        - "match": The specific snippet of code that is vulnerable (limit to 50 chars)
        
        If no vulnerabilities are found, return an empty array [].
        Do NOT wrap the JSON in Markdown or additional text.
        
        Source code from {f_path}:
        {code}
        """
        
        try:
            message = client.messages.create(
                model="claude-3-5-sonnet-20240620",
                max_tokens=2048,
                system="You are a security vulnerability scanner. Output MUST be valid JSON array of findings only.",
                messages=[{"role": "user", "content": prompt}]
            )
            
            resp_text = message.content[0].text.strip()
            # Basic cleanup if Claude adds markdown code blocks
            if resp_text.startswith("```json"):
                resp_text = resp_text.replace("```json", "").replace("```", "").strip()
            
            findings = json.loads(resp_text)
            for f in findings:
                f["tool"] = "claude"
                results.append(f)
                
        except Exception as e:
            print(f"  ❌ Error scanning {f_path}: {e}")
            
    # Save results
    with open("claude-report.json", "w", encoding="utf-8") as out:
        json.dump(results, out, indent=2)
    
    print(f"[Claude Scan] ✅ Done. {len(results)} findings saved to claude-report.json")

if __name__ == "__main__":
    run_scan()
