#!/usr/bin/env bash
# tool-log.sh — Lightweight append-only log for LSP/ast-grep usage during scans
# Usage: bash tool-log.sh <REPO_PATH> <SCAN_ID> <AGENT> <TOOL> <OPERATION> [DETAIL]
#
# Appends a single TSV line to <REPO_PATH>/scan-results/tool-usage-<SCAN_ID>.log
# This file is NOT cleaned up after scans — it persists for manual review.
#
# To disable logging, set RAILGUARD_TOOL_LOG=0 in the environment.

[ "${RAILGUARD_TOOL_LOG:-1}" = "0" ] && exit 0

REPO_PATH="${1:?Usage: tool-log.sh <REPO_PATH> <SCAN_ID> <AGENT> <TOOL> <OPERATION> [DETAIL]}"
SCAN_ID="${2:?}"
AGENT="${3:?}"
TOOL="${4:?}"
OPERATION="${5:?}"
DETAIL="${6:-}"

LOG_DIR="${REPO_PATH}/scan-results"
mkdir -p "$LOG_DIR" 2>/dev/null
LOG_FILE="${LOG_DIR}/tool-usage-${SCAN_ID}.log"

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$TIMESTAMP" "$AGENT" "$TOOL" "$OPERATION" "$DETAIL" "$SCAN_ID" >> "$LOG_FILE"
