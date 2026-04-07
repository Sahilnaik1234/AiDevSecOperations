#!/bin/bash
# Tool: Gitleaks
# Output: gitleaks-report.json

echo "[Toolbox]  Running Gitleaks..."
# Simplify Gitleaks: Scan the root /src which contains everything
echo "[Gitleaks] Performing full filesystem scan on /src..."

docker run --rm -v "$(pwd):/src" zricethezav/gitleaks:latest detect --no-git --source="/src" --report-format=json --report-path=/src/gitleaks-report.json
echo "[Toolbox]  Gitleaks scan complete."
