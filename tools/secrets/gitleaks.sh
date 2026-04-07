#!/bin/bash
# Tool: Gitleaks
# Output: gitleaks-report.json

echo "[Toolbox]  Running Gitleaks..."
# Handle multiple directories by iterating and merging
echo "[]" > gitleaks-report.json # Initialize empty array

IFS=',' read -ra INCS <<< "$SCAN_INCLUDE"
for i in "${INCS[@]}"; do
  i=$(echo "$i" | xargs) # Trim spaces
  if [ -n "$i" ]; then
    echo "[Gitleaks] Scanning: /src/$i"
    # Run gitleaks and append results to temporary file
    docker run --rm -v "$(pwd):/src" zricethezav/gitleaks:latest detect --no-git --source="/src/$i" --report-format=json --report-path=/src/temp-report.json
    
    # Simple JSON merge (since it is an array of objects)
    if [ -f temp-report.json ] && [ "$(cat temp-report.json)" != "null" ]; then
      if [ "$(cat gitleaks-report.json)" == "[]" ]; then
        mv temp-report.json gitleaks-report.json
      else
        # Use jq or simple node/python script to merge if needed
        python3 -c "import json; a=json.load(open('gitleaks-report.json')); b=json.load(open('temp-report.json')); json.dump(a+b, open('gitleaks-report.json', 'w'))"
        rm temp-report.json
      fi
    fi
  fi
done
echo "[Toolbox]  Gitleaks scan complete."
