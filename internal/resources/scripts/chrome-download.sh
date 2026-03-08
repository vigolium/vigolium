#!/usr/bin/env bash
#
# chrome-download.sh — Download all browser archives listed in versions.go
#
# Usage: chrome-download.sh [CHROME_DIR] [VERSIONS_FILE]
#
# Defaults are relative to the repository root (auto-detected).

set -euo pipefail

PREFIX='\033[36m[*]\033[0m'

# Locate repo root
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "$0")/../../.." && pwd))"

CHROME_DIR="${1:-${REPO_ROOT}/internal/resources/spitolas/chromium}"
VERSIONS_FILE="${2:-${REPO_ROOT}/internal/resources/spitolas/versions.go}"

if [ ! -f "$VERSIONS_FILE" ]; then
    echo -e "\033[31m[!] versions.go not found: ${VERSIONS_FILE}\033[0m"
    exit 1
fi

echo -e "${PREFIX} Downloading browser archives..."
mkdir -p "$CHROME_DIR"

awk -F'"' '/\{Name:/{print $10, $8}' "$VERSIONS_FILE" | while read -r archive url; do
    echo -e "${PREFIX} Downloading ${archive}..."
    curl -fSL --progress-bar -o "${CHROME_DIR}/${archive}" "${url}"
done

echo -e "${PREFIX} All browser archives downloaded"
