#!/bin/bash
# Tool: Semgrep SAST
# Output: semgrep-report.json

echo "[Toolbox]  Running Semgrep SAST..."
# Using the semgrep image directly via docker to keep it consistent with the modular approach
docker run --rm -v "$(pwd):/src" -e SEMGREP_APP_TOKEN=$SEMGREP_APP_TOKEN semgrep/semgrep semgrep --config=auto --json --output=/src/semgrep-report.json /src
echo "[Toolbox]  Semgrep SAST complete."
