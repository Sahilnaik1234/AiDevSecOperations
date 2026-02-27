#!/bin/bash
# Tool: TruffleHog
# Output: trufflehog-report.json

echo "[Toolbox] 🐷 Running TruffleHog..."
# Run TruffleHog via Docker, scanning the current directory filesystem
docker run --rm -v "$(pwd):/src" trufflesecurity/trufflehog:latest filesystem /src --json > trufflehog-report.json 2>/dev/null

echo "[Toolbox] ✅ TruffleHog scan complete."
