#!/usr/bin/env bash
#
# deps-check.sh — Ensure jsscan binaries and Chromium archives are present
#
# Usage: deps-check.sh
#
# Copies jsscan binaries from the sibling jsscan project when missing,
# and verifies Chromium browser archives are downloaded.

set -euo pipefail

PREFIX='\033[36m[*]\033[0m'
OK='\033[32m[✓]\033[0m'
FAIL='\033[31m[✗]\033[0m'

# Locate repo root
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "$0")/../../.." && pwd))"

JSSCAN_DST_DIR="${REPO_ROOT}/internal/resources/deparos/jsscan"
JSSCAN_SRC_DIR="${REPO_ROOT}/platform/jsscan/bin"
CHROME_DIR="${REPO_ROOT}/internal/resources/spitolas/chromium"
VERSIONS_FILE="${REPO_ROOT}/internal/resources/spitolas/versions.go"

JSSCAN_BINS="jsscan-darwin-amd64 jsscan-darwin-arm64 jsscan-linux-amd64 jsscan-linux-arm64 jsscan-windows-amd64.exe"

errors=0

# ---------------------------------------------------------------------------
# 1. Ensure jsscan binaries
# ---------------------------------------------------------------------------
echo -e "${PREFIX} Checking jsscan binaries in ${JSSCAN_DST_DIR}..."
mkdir -p "$JSSCAN_DST_DIR"

jsscan_missing=0
for bin in $JSSCAN_BINS; do
    if [ ! -f "${JSSCAN_DST_DIR}/${bin}" ]; then
        jsscan_missing=1
        break
    fi
done

if [ $jsscan_missing -eq 0 ]; then
    echo -e "  ${OK} All jsscan binaries present"
else
    if [ ! -d "$JSSCAN_SRC_DIR" ]; then
        echo -e "  ${FAIL} Missing jsscan binaries. Build with: cd platform/jsscan && bun install --linker isolated && bun run build:bin"
        errors=1
    else
        echo -e "${PREFIX} Copying jsscan binaries from ${JSSCAN_SRC_DIR}..."
        for bin in $JSSCAN_BINS; do
            cp -R "${JSSCAN_SRC_DIR}/${bin}" "${JSSCAN_DST_DIR}/"
        done
        echo -e "  ${OK} jsscan binaries copied successfully"
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
