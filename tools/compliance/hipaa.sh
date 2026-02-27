#!/bin/bash
# Tool: HIPAA Compliance
# Output: hipaa-report.json

echo "[Toolbox] 🏥 Running HIPAA Compliance Scan..."
docker run --rm -v "$(pwd):/src" semgrep/semgrep semgrep \
  --config=/src/tools/configs/.semgrep-hipaa.yml \
  --json --output=/src/hipaa-report.json /src
echo "[Toolbox] ✅ HIPAA scan complete."
