#!/bin/bash
# Tool: TruffleHog
# Output: trufflehog-report.json

echo "[Toolbox]  Running TruffleHog..."
# Run TruffleHog via Docker, scanning the current directory filesystem
# Reset report
> trufflehog-report.json

IFS=',' read -ra INCS <<< "$SCAN_INCLUDE"
for i in "${INCS[@]}"; do
  i=$(echo "$i" | xargs)
  if [ -n "$i" ]; then
    echo "[Trufflehog] Scanning: /src/$i"
    docker run --rm -v "$(pwd):/src" trufflesecurity/trufflehog:latest filesystem "/src/$i" --json >> trufflehog-report.json
  fi
done

if [ -f trufflehog-report.json ]; then
  echo "[Toolbox]  TruffleHog scan complete. Report created."
  ls -lh trufflehog-report.json
else
  echo "[Toolbox]  TruffleHog FAILED to create report."
fi
