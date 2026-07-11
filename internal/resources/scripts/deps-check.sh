#!/usr/bin/env bash
#
# deps-check.sh — Ensure jstangle binaries and Chromium archives are present
#
# Usage: deps-check.sh
#
# Copies jstangle binaries from the sibling jstangle project when missing,
# and verifies Chromium browser archives are downloaded.

set -euo pipefail

PREFIX='\033[36m[*]\033[0m'
OK='\033[32m[✓]\033[0m'
FAIL='\033[31m[✗]\033[0m'

# Locate repo root
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "$0")/../../.." && pwd))"

JSTANGLE_DST_DIR="${REPO_ROOT}/internal/resources/deparos/jstangle"
JSTANGLE_SRC_DIR="${REPO_ROOT}/platform/jstangle/bin"
CHROME_DIR="${REPO_ROOT}/internal/resources/spitolas/chromium"
VERSIONS_FILE="${REPO_ROOT}/internal/resources/spitolas/versions.go"

JSTANGLE_BINS="jstangle-darwin-amd64 jstangle-darwin-arm64 jstangle-linux-amd64 jstangle-linux-arm64 jstangle-windows-amd64.exe"

errors=0

# ---------------------------------------------------------------------------
# 1. Ensure jstangle binaries
# ---------------------------------------------------------------------------
echo -e "${PREFIX} Checking jstangle binaries in ${JSTANGLE_DST_DIR}..."
mkdir -p "$JSTANGLE_DST_DIR"

jstangle_missing=0
for bin in $JSTANGLE_BINS; do
    if [ ! -f "${JSTANGLE_DST_DIR}/${bin}" ]; then
        jstangle_missing=1
        break
    fi
done

if [ $jstangle_missing -eq 0 ]; then
    echo -e "  ${OK} All jstangle binaries present"
else
    if [ ! -d "$JSTANGLE_SRC_DIR" ]; then
        echo -e "  ${FAIL} Missing jstangle binaries. Build with: cd platform/jstangle && bun install --linker isolated && bun run build:bin"
        errors=1
    else
        echo -e "${PREFIX} Copying jstangle binaries from ${JSTANGLE_SRC_DIR}..."
        for bin in $JSTANGLE_BINS; do
            cp -R "${JSTANGLE_SRC_DIR}/${bin}" "${JSTANGLE_DST_DIR}/"
        done
        echo -e "  ${OK} jstangle binaries copied successfully"
    fi
fi

echo ""

# ---------------------------------------------------------------------------
# 2. Check Chromium archives
# ---------------------------------------------------------------------------
WARN='\033[33m[!]\033[0m'

echo -e "${PREFIX} Checking Chromium browser archives in ${CHROME_DIR}..."

if [ ! -f "$VERSIONS_FILE" ]; then
    echo -e "  ${WARN} versions.go not found: ${VERSIONS_FILE}"
    echo -e "\033[33m  Chromium archives are optional. The spider will auto-download a browser at runtime.\033[0m"
    echo -e "\033[33m  To embed Chromium: run 'make deps-chrome' then build with 'make build-embedded'.\033[0m"
else
    chrome_missing=0
    while read -r archive; do
        if [ ! -f "${CHROME_DIR}/${archive}" ]; then
            echo -e "  ${WARN} Missing: ${archive}"
            chrome_missing=1
        fi
    done < <(awk -F'"' '/\{Name:/{print $10}' "$VERSIONS_FILE")

    if [ $chrome_missing -eq 0 ]; then
        echo -e "  ${OK} All Chromium archives present"
    else
        echo ""
        echo -e "\033[33m  Chromium archives are optional. The spider will auto-download a browser at runtime.\033[0m"
        echo -e "\033[33m  To embed Chromium: run 'make deps-chrome' then build with 'make build-embedded'.\033[0m"
    fi
fi

echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
if [ $errors -eq 0 ]; then
    echo -e "${OK} All dependencies are ready"
    exit 0
else
    echo -e "${FAIL} Some dependencies are missing — see messages above."
    exit 1
fi
