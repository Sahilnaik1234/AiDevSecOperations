#!/bin/bash
# Tool: Gitleaks
# Output: gitleaks-report.json

echo "[Toolbox]  Running Gitleaks..."
# Debug: Show runner's filesystem snapshot
echo "[Gitleaks] Local file structure check:"
ls -R . | grep ":$" | sed -e 's/:$//' -e 's/[^-][^\/]*\//--/g' -e 's/^/   /'
du -sh .

docker run --rm -v "$(pwd):/src" zricethezav/gitleaks:latest detect --no-git --source="/src" --report-format=json --report-path=/src/gitleaks-report.json --verbose
echo "[Toolbox]  Gitleaks scan complete."
