# tools/sast/claude.sh
# Real-time Claude Code Security Scan

echo "[Claude Scan] Starting Real-time analysis with Claude 3.5..."

# Ensure we have the analyzer
if [ ! -f "tools/sast/claude_analyzer.py" ]; then
  echo "❌ Error: tools/sast/claude_analyzer.py not found."
  exit 1
fi

python3 tools/sast/claude_analyzer.py

echo "[Claude Scan] ✅ Done."
