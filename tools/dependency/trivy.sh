#!/bin/bash
# Tool: Trivy SCA
# Output: dependency-report.json

echo "[Toolbox]  Running Trivy Dependency Scan..."
docker run --rm -v "$(pwd):/src" aquasec/trivy:latest fs --format json --output /src/dependency-report.json /src
echo "[Toolbox]  Trivy scan complete."
