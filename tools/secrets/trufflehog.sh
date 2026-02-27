#!/bin/bash
# Tool: TruffleHog
# Output: trufflehog-report.json

echo "[Toolbox]  Running TruffleHog..."
# Run TruffleHog via Docker, scanning the current directory filesystem
docker run --rm -v "$(pwd):/src" trufflesecurity/trufflehog:latest filesystem /src --json > trufflehog-report.json

if [ -f trufflehog-report.json ]; then
  echo "[Toolbox]  TruffleHog scan complete. Report created."
  ls -lh trufflehog-report.json
else
  echo "[Toolbox]  TruffleHog FAILED to create report."
fi
