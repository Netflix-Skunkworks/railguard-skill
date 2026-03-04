#!/usr/bin/env bash
# enumerate-files.sh — List analyzable source files in a repository
# Usage: bash enumerate-files.sh <REPO_PATH>

set -euo pipefail

REPO_PATH="${1:?Usage: enumerate-files.sh <REPO_PATH>}"

if [ ! -d "$REPO_PATH" ]; then
  echo "ERROR: Directory not found: $REPO_PATH" >&2
  exit 1
fi

EXCLUDED_DIRS=(
  node_modules __pycache__ .git .svn .hg
  venv .venv env .env virtualenv
  dist build target out bin obj
  .idea .vscode .eclipse
  vendor third_party external
  coverage .coverage htmlcov
  .pytest_cache .mypy_cache .tox
  .circleci .gitlab
)

EXCLUDED_EXTENSIONS=(
  exe dll so dylib o a lib bin pyc pyo class jar war
  png jpg jpeg gif bmp ico svg webp tiff psd ai
  mp3 mp4 wav avi mov mkv flac ogg
  zip tar gz rar 7z bz2 xz
  pdf doc docx xls xlsx ppt pptx
  ttf otf woff woff2 eot
  lock
  map
)

PRUNE_ARGS=()
for dir in "${EXCLUDED_DIRS[@]}"; do
  PRUNE_ARGS+=(-name "$dir" -o)
done
# Remove trailing -o
unset 'PRUNE_ARGS[${#PRUNE_ARGS[@]}-1]'

EXCLUDE_PATTERN=""
for ext in "${EXCLUDED_EXTENSIONS[@]}"; do
  EXCLUDE_PATTERN+=".*\\.${ext}$|"
done
EXCLUDE_PATTERN+=".*\\.min\\.js$|.*\\.min\\.css$"

cd "$REPO_PATH"

echo "=== File Manifest for: $REPO_PATH ==="
echo ""

find . \( "${PRUNE_ARGS[@]}" \) -prune -o -type f -print 2>/dev/null \
  | grep -Ev "$EXCLUDE_PATTERN" \
  | sort \
  | while IFS= read -r file; do
    size=$(wc -c < "$file" 2>/dev/null || echo 0)
    ext="${file##*.}"
    echo "${ext}|${size}|${file}"
  done \
  | sort -t'|' -k1,1 \
  | awk -F'|' '
    BEGIN { current_lang = ""; count = 0; total = 0 }
    {
      if ($1 != current_lang) {
        if (current_lang != "") printf "  (%d files)\n\n", count
        current_lang = $1
        printf "## .%s\n", $1
        count = 0
      }
      printf "  %s (%s bytes)\n", $3, $2
      count++
      total++
    }
    END {
      if (current_lang != "") printf "  (%d files)\n\n", count
      printf "=== Total: %d files ===\n", total
    }
  '
