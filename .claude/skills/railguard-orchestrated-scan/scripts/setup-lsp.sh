#!/usr/bin/env bash
# setup-lsp.sh — Configure LSP environment for a target repository scan
# Usage: bash setup-lsp.sh <REPO_PATH> [SCAN_ID]
#
# Creates a pyrightconfig.json in the target repo and optionally sets up a
# temporary venv with dependencies for full type resolution.
#
# Outputs a JSON status block to stdout for the orchestrator to parse.

set -euo pipefail

REPO_PATH="${1:?Usage: setup-lsp.sh <REPO_PATH> [SCAN_ID]}"
SCAN_ID="${2:-$(date +%s)}"

if [ ! -d "$REPO_PATH" ]; then
  echo '{"lsp_status": "error", "reason": "repo not found"}' 
  exit 1
fi

REPO_PATH="$(cd "$REPO_PATH" && pwd)"

detect_languages() {
  local langs=()
  local py_count js_count ts_count go_count java_count kt_count rb_count php_count rs_count
  py_count=$(find "$REPO_PATH" -name '*.py' -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/venv/*' -not -path '*/.venv/*' 2>/dev/null | head -200 | wc -l)
  js_count=$(find "$REPO_PATH" \( -name '*.js' -o -name '*.jsx' \) -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null | head -200 | wc -l)
  ts_count=$(find "$REPO_PATH" \( -name '*.ts' -o -name '*.tsx' \) -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null | head -200 | wc -l)
  go_count=$(find "$REPO_PATH" -name '*.go' -not -path '*/.git/*' -not -path '*/vendor/*' 2>/dev/null | head -200 | wc -l)
  java_count=$(find "$REPO_PATH" -name '*.java' -not -path '*/.git/*' -not -path '*/build/*' -not -path '*/target/*' 2>/dev/null | head -200 | wc -l)
  kt_count=$(find "$REPO_PATH" -name '*.kt' -not -path '*/.git/*' 2>/dev/null | head -200 | wc -l)
  rb_count=$(find "$REPO_PATH" -name '*.rb' -not -path '*/.git/*' 2>/dev/null | head -200 | wc -l)
  php_count=$(find "$REPO_PATH" -name '*.php' -not -path '*/.git/*' -not -path '*/vendor/*' 2>/dev/null | head -200 | wc -l)
  rs_count=$(find "$REPO_PATH" -name '*.rs' -not -path '*/.git/*' -not -path '*/target/*' 2>/dev/null | head -200 | wc -l)

  [ "$py_count" -gt 0 ] && langs+=("python:$py_count")
  [ "$js_count" -gt 0 ] && langs+=("javascript:$js_count")
  [ "$ts_count" -gt 0 ] && langs+=("typescript:$ts_count")
  [ "$go_count" -gt 0 ] && langs+=("go:$go_count")
  [ "$java_count" -gt 0 ] && langs+=("java:$java_count")
  [ "$kt_count" -gt 0 ] && langs+=("kotlin:$kt_count")
  [ "$rb_count" -gt 0 ] && langs+=("ruby:$rb_count")
  [ "$php_count" -gt 0 ] && langs+=("php:$php_count")
  [ "$rs_count" -gt 0 ] && langs+=("rust:$rs_count")

  echo "${langs[*]}"
}

check_lsp_binaries() {
  local results=()
  local lang binary
  declare -A lang_binaries=(
    [python]="pyright-langserver"
    [javascript]="typescript-language-server"
    [typescript]="typescript-language-server"
    [go]="gopls"
    [java]="jdtls"
    [kotlin]="kotlin-language-server"
    [php]="intelephense"
    [rust]="rust-analyzer"
  )

  for lang in "$@"; do
    local lang_name="${lang%%:*}"
    binary="${lang_binaries[$lang_name]:-}"
    if [ -n "$binary" ]; then
      if command -v "$binary" &>/dev/null; then
        results+=("$lang_name:available")
      else
        results+=("$lang_name:missing_binary:$binary")
      fi
    else
      results+=("$lang_name:no_lsp_support")
    fi
  done
  echo "${results[*]}"
}

check_existing_venv() {
  for venv_dir in "$REPO_PATH/venv" "$REPO_PATH/.venv" "$REPO_PATH/env"; do
    if [ -f "$venv_dir/bin/python" ] || [ -f "$venv_dir/bin/python3" ]; then
      echo "$venv_dir"
      return 0
    fi
  done
  return 1
}

DETECTED_LANGS=$(detect_languages)
if [ -z "$DETECTED_LANGS" ]; then
  echo '{"lsp_status": "skipped", "reason": "no recognized source files"}'
  exit 0
fi

read -ra LANG_ARRAY <<< "$DETECTED_LANGS"
LSP_STATUS=$(check_lsp_binaries "${LANG_ARRAY[@]}")

HAS_PYTHON=false
for lang in "${LANG_ARRAY[@]}"; do
  [ "${lang%%:*}" = "python" ] && HAS_PYTHON=true
done

VENV_PATH=""
VENV_NAME=""
VENV_SOURCE="none"
DEPS_INSTALLED=false
CREATED_PYRIGHTCONFIG=false
EXISTING_PYRIGHTCONFIG=false

if $HAS_PYTHON && command -v pyright-langserver &>/dev/null; then
  # Check for existing pyrightconfig.json -- back it up if present
  if [ -f "$REPO_PATH/pyrightconfig.json" ]; then
    EXISTING_PYRIGHTCONFIG=true
    cp "$REPO_PATH/pyrightconfig.json" "$REPO_PATH/pyrightconfig.json.rgs-backup-${SCAN_ID}"
  fi

  # Check for existing venv
  if EXISTING_VENV=$(check_existing_venv); then
    VENV_PATH="$(dirname "$EXISTING_VENV")"
    VENV_NAME="$(basename "$EXISTING_VENV")"
    VENV_SOURCE="existing"
  else
    # Create temporary venv and install deps if requirements exist
    TEMP_VENV="/tmp/rgs-lsp-env-${SCAN_ID}"
    if python3 -m venv "$TEMP_VENV" 2>/dev/null; then
      VENV_PATH="/tmp"
      VENV_NAME="rgs-lsp-env-${SCAN_ID}"
      VENV_SOURCE="temporary"

      # Install dependencies if manifest exists
      if [ -f "$REPO_PATH/requirements.txt" ]; then
        "$TEMP_VENV/bin/pip" install -q -r "$REPO_PATH/requirements.txt" 2>/dev/null && DEPS_INSTALLED=true || true
      elif [ -f "$REPO_PATH/pyproject.toml" ]; then
        "$TEMP_VENV/bin/pip" install -q "$REPO_PATH" 2>/dev/null && DEPS_INSTALLED=true || true
      elif [ -f "$REPO_PATH/setup.py" ]; then
        "$TEMP_VENV/bin/pip" install -q -e "$REPO_PATH" 2>/dev/null && DEPS_INSTALLED=true || true
      fi
    fi
  fi

  # Write pyrightconfig.json into the target repo root
  if [ -n "$VENV_PATH" ]; then
    cat > "$REPO_PATH/pyrightconfig.json" <<PYRIGHT_EOF
{
  "venvPath": "$VENV_PATH",
  "venv": "$VENV_NAME",
  "extraPaths": ["$REPO_PATH"]
}
PYRIGHT_EOF
    CREATED_PYRIGHTCONFIG=true
  else
    # No venv but still set extraPaths for intra-project resolution
    cat > "$REPO_PATH/pyrightconfig.json" <<PYRIGHT_EOF
{
  "extraPaths": ["$REPO_PATH"]
}
PYRIGHT_EOF
    CREATED_PYRIGHTCONFIG=true
  fi
fi

# Build JSON output
cat <<OUTPUT_EOF
{
  "lsp_status": "configured",
  "scan_id": "$SCAN_ID",
  "repo_path": "$REPO_PATH",
  "detected_languages": "$DETECTED_LANGS",
  "lsp_binary_status": "$LSP_STATUS",
  "python_lsp": {
    "has_python": $HAS_PYTHON,
    "venv_source": "$VENV_SOURCE",
    "venv_path": "$VENV_PATH",
    "venv_name": "$VENV_NAME",
    "deps_installed": $DEPS_INSTALLED,
    "created_pyrightconfig": $CREATED_PYRIGHTCONFIG,
    "backed_up_existing": $EXISTING_PYRIGHTCONFIG
  },
  "cleanup_required": [
    $(if $CREATED_PYRIGHTCONFIG; then echo "\"$REPO_PATH/pyrightconfig.json\""; fi)
    $(if [ "$VENV_SOURCE" = "temporary" ]; then
      if $CREATED_PYRIGHTCONFIG; then echo ","; fi
      echo "\"/tmp/rgs-lsp-env-${SCAN_ID}\""
    fi)
    $(if $EXISTING_PYRIGHTCONFIG; then
      if $CREATED_PYRIGHTCONFIG || [ "$VENV_SOURCE" = "temporary" ]; then echo ","; fi
      echo "\"restore:$REPO_PATH/pyrightconfig.json.rgs-backup-${SCAN_ID}\""
    fi)
  ]
}
OUTPUT_EOF
