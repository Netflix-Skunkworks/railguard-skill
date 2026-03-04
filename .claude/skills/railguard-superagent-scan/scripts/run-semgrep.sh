#!/usr/bin/env bash
# run-semgrep.sh — Run Semgrep static analysis and output summary
# Usage: bash run-semgrep.sh <REPO_PATH>

set -euo pipefail

REPO_PATH="${1:?Usage: run-semgrep.sh <REPO_PATH>}"
TIMEOUT="${2:-300}"

if [ ! -d "$REPO_PATH" ]; then
  echo "ERROR: Directory not found: $REPO_PATH" >&2
  exit 1
fi

if ! command -v semgrep &>/dev/null; then
  echo "SKIP: semgrep is not installed. Install with: pip install semgrep"
  echo "Semgrep analysis will be skipped — LLM analysis in Phase 3 covers the same ground."
  exit 0
fi

echo "=== Semgrep Static Analysis ==="
echo "Repository: $REPO_PATH"
echo "Timeout: ${TIMEOUT}s"
echo ""

TMPFILE=$(mktemp /tmp/semgrep-results-XXXXXX.json)
trap 'rm -f "$TMPFILE"' EXIT

cd "$REPO_PATH"

if timeout "$TIMEOUT" semgrep scan --json --config auto --timeout 30 \
    --exclude 'node_modules' --exclude '.git' --exclude 'venv' \
    --exclude 'dist' --exclude 'build' --exclude 'vendor' \
    . > "$TMPFILE" 2>/dev/null; then
  SCAN_OK=true
elif [ $? -eq 1 ]; then
  # Exit code 1 means findings were found (not an error)
  SCAN_OK=true
else
  SCAN_OK=false
fi

if [ "$SCAN_OK" = false ]; then
  echo "WARNING: Semgrep scan failed or timed out"
  echo "Proceeding without semgrep findings."
  exit 0
fi

python3 -c "
import json, sys

with open('$TMPFILE') as f:
    data = json.load(f)

results = data.get('results', [])
errors = data.get('errors', [])

print(f'Findings: {len(results)}')
print(f'Errors: {len(errors)}')
print()

if not results:
    print('No semgrep findings.')
    sys.exit(0)

by_severity = {}
for r in results:
    sev = r.get('extra', {}).get('severity', 'WARNING')
    by_severity[sev] = by_severity.get(sev, 0) + 1

print('By severity:')
for sev in ['ERROR', 'WARNING', 'INFO']:
    if sev in by_severity:
        print(f'  {sev}: {by_severity[sev]}')

print()
print('Findings:')
for r in results:
    rule = r.get('check_id', 'unknown')
    path = r.get('path', '')
    line = r.get('start', {}).get('line', 0)
    sev = r.get('extra', {}).get('severity', 'WARNING')
    msg = r.get('extra', {}).get('message', '')[:120]
    print(f'  [{sev}] {rule}')
    print(f'    {path}:{line} — {msg}')
    print()
" 2>/dev/null || echo "WARNING: Failed to parse semgrep output"
