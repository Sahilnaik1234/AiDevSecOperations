#!/bin/bash
# Tool: Trivy SCA
# Output: dependency-report.json

echo "[Toolbox]  Running Trivy Dependency Scan..."
# Convert comma-separated excludes for trivy
EXC_FLAGS=""
if [ -n "$SCAN_EXCLUDE" ]; then
  EXC_FLAGS="--skip-dirs ${SCAN_EXCLUDE}"
fi

docker run --rm -v "$(pwd):/src" aquasec/trivy:latest fs --format json --output /src/dependency-report.json $EXC_FLAGS "/src/${SCAN_INCLUDE:-.}"
echo "[Toolbox]  Trivy scan complete."
