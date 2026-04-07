#!/bin/bash
# Tool: Semgrep SAST
# Output: semgrep-report.json

echo "[Toolbox]  Running Semgrep SAST..."
# Using the semgrep image directly via docker to keep it consistent with the modular approach
# Handle comma-separated SCAN_INCLUDE
TARGET_PATHS=""
IFS=',' read -ra INCS <<< "$SCAN_INCLUDE"
for i in "${INCS[@]}"; do
  # Trim spaces
  i=$(echo "$i" | xargs)
  if [ -n "$i" ]; then
    TARGET_PATHS="$TARGET_PATHS /src/$i"
  fi
done

# Default to /src if nothing specified
if [ -z "$TARGET_PATHS" ]; then TARGET_PATHS="/src"; fi

docker run --rm -v "$(pwd):/src" -e SEMGREP_APP_TOKEN=$SEMGREP_APP_TOKEN semgrep/semgrep semgrep --config=auto --json --output=/src/semgrep-report.json $EXCLUDE_FLAGS $TARGET_PATHS
echo "[Toolbox]  Semgrep SAST complete."
