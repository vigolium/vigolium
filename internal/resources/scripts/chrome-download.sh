#!/usr/bin/env bash
#
# chrome-download.sh — Download all browser archives for embedding
#
# Downloads:
#   1. Chromium/Ungoogled/Fingerprint archives from URLs in versions.go
#   2. Chrome for Testing (stable) from the official CfT JSON API
#
# Usage: chrome-download.sh [CHROME_DIR] [VERSIONS_FILE]
#
# Defaults are relative to the repository root (auto-detected).

set -euo pipefail

PREFIX='\033[36m[*]\033[0m'
OK='\033[32m[✓]\033[0m'
FAIL='\033[31m[✗]\033[0m'

# Hardened curl flags. --http1.1 sidesteps the intermittent
# "curl: (16) Error in the HTTP2 framing layer" seen on GitHub release-asset
# redirects; the retry flags ride out transient transport errors.
CURL_DL=(--fail --location --http1.1 --retry 5 --retry-delay 2 --retry-all-errors --progress-bar)
CURL_API=(--fail --silent --show-error --location --http1.1 --retry 5 --retry-delay 2 --retry-all-errors)

# Locate repo root
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "$0")/../../.." && pwd))"

CHROME_DIR="${1:-${REPO_ROOT}/internal/resources/spitolas/chromium}"
VERSIONS_FILE="${2:-${REPO_ROOT}/internal/resources/spitolas/versions.go}"

mkdir -p "$CHROME_DIR"

# ---------------------------------------------------------------------------
# 1. Download archives from versions.go
# ---------------------------------------------------------------------------
if [ -f "$VERSIONS_FILE" ]; then
    echo -e "${PREFIX} Downloading browser archives from versions.go..."
    awk -F'"' '/\{Name:/{print $10, $8}' "$VERSIONS_FILE" | while read -r archive url; do
        echo -e "${PREFIX} Downloading ${archive}..."
        curl "${CURL_DL[@]}" -o "${CHROME_DIR}/${archive}" "${url}"
    done
    echo -e "${OK} versions.go archives downloaded"
else
    echo -e "${FAIL} versions.go not found: ${VERSIONS_FILE}"
    exit 1
fi

echo ""

# ---------------------------------------------------------------------------
# 2. Download Chrome for Testing (stable) from the CfT JSON API
# ---------------------------------------------------------------------------
CFT_API_URL="https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"
CFT_PLATFORMS="linux64 mac-arm64 mac-x64 win64"

echo -e "${PREFIX} Fetching Chrome for Testing version info..."
API_JSON=$(curl "${CURL_API[@]}" "$CFT_API_URL")
if [ -z "$API_JSON" ]; then
    echo -e "${FAIL} Failed to fetch CfT API"
    exit 1
fi

CFT_VERSION=$(echo "$API_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['channels']['Stable']['version'])")
echo -e "${PREFIX} Chrome for Testing stable: v${CFT_VERSION}"

for PLATFORM in $CFT_PLATFORMS; do
    URL=$(echo "$API_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for dl in data['channels']['Stable']['downloads']['chrome']:
    if dl['platform'] == '${PLATFORM}':
        print(dl['url'])
        break
")

    if [ -z "$URL" ]; then
        echo -e "  ${FAIL} No download URL for platform: ${PLATFORM}"
        continue
    fi

    ARCHIVE="chrome-${PLATFORM}.zip"
    echo -e "${PREFIX} Downloading Chrome for Testing (${PLATFORM}) v${CFT_VERSION}..."
    curl "${CURL_DL[@]}" -o "${CHROME_DIR}/${ARCHIVE}" "$URL"
    echo -e "  ${OK} ${ARCHIVE} ($(du -h "${CHROME_DIR}/${ARCHIVE}" | cut -f1))"
done

echo ""
echo -e "${OK} All browser archives downloaded to ${CHROME_DIR}"
