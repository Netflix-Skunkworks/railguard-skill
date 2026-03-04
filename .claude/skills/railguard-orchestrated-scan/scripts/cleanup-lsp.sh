#!/usr/bin/env bash
# cleanup-lsp.sh — Remove LSP artifacts created during a scan
# Usage: bash cleanup-lsp.sh <REPO_PATH> <SCAN_ID>
#
# Removes pyrightconfig.json (restoring backup if one existed) and temp venv.

set -euo pipefail

REPO_PATH="${1:?Usage: cleanup-lsp.sh <REPO_PATH> <SCAN_ID>}"
SCAN_ID="${2:?Usage: cleanup-lsp.sh <REPO_PATH> <SCAN_ID>}"

REPO_PATH="$(cd "$REPO_PATH" && pwd)"

# Restore original pyrightconfig.json if we backed one up
BACKUP="$REPO_PATH/pyrightconfig.json.rgs-backup-${SCAN_ID}"
if [ -f "$BACKUP" ]; then
  mv "$BACKUP" "$REPO_PATH/pyrightconfig.json"
  echo "Restored original pyrightconfig.json from backup."
elif [ -f "$REPO_PATH/pyrightconfig.json" ]; then
  rm -f "$REPO_PATH/pyrightconfig.json"
  echo "Removed scanner-generated pyrightconfig.json."
fi

# Remove temporary venv if we created one
TEMP_VENV="/tmp/rgs-lsp-env-${SCAN_ID}"
if [ -d "$TEMP_VENV" ]; then
  rm -rf "$TEMP_VENV"
  echo "Removed temporary venv: $TEMP_VENV"
fi

echo "LSP cleanup for scan $SCAN_ID complete."
