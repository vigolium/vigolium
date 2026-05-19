#!/usr/bin/env bash
#
# chrome-download-cft.sh — Download Chrome for Testing (stable) for all platforms
#
# Uses the official CfT JSON API to fetch the latest stable version and
# download browser archives. Downloaded zips can be used for embedding or
# as a runtime fallback.
#
# Usage: chrome-download-cft.sh [PLATFORM]
#
#   PLATFORM  Optional — download a single platform: linux64, mac-arm64, mac-x64, win64, win32
#             If omitted, downloads all platforms.
#
# Downloaded to: internal/resources/spitolas/chromium/chrome-<platform>.zip

set -euo pipefail

PREFIX='\033[36m[*]\033[0m'
OK='\033[32m[✓]\033[0m'
FAIL='\033[31m[✗]\033[0m'

# Hardened curl flags. --http1.1 sidesteps the intermittent
# "curl: (16) Error in the HTTP2 framing layer" seen on GitHub/GCS redirects;
# the retry flags ride out transient transport errors.
CURL_DL=(--fail --location --http1.1 --retry 5 --retry-delay 2 --retry-all-errors --progress-bar)
CURL_API=(--fail --silent --show-error --location --http1.1 --retry 5 --retry-delay 2 --retry-all-errors)

API_URL="https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"

# Locate repo root
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "$0")/../../.." && pwd))"
CHROME_DIR="${REPO_ROOT}/internal/resources/spitolas/chromium"

FILTER_PLATFORM="${1:-}"

# Fetch the JSON API
echo -e "${PREFIX} Fetching Chrome for Testing version info..."
API_JSON=$(curl "${CURL_API[@]}" "$API_URL")
if [ -z "$API_JSON" ]; then
    echo -e "${FAIL} Failed to fetch CfT API"
    exit 1
fi

VERSION=$(echo "$API_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['channels']['Stable']['version'])")
echo -e "${PREFIX} Latest stable version: ${VERSION}"

mkdir -p "$CHROME_DIR"

# Extract download URLs for each platform
ALL_PLATFORMS="linux64 mac-arm64 mac-x64 win64 win32"

if [ -n "$FILTER_PLATFORM" ]; then
    PLATFORMS="$FILTER_PLATFORM"
else
    PLATFORMS="$ALL_PLATFORMS"
fi

for PLATFORM in $PLATFORMS; do
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
    echo -e "${PREFIX} Downloading Chrome for Testing (${PLATFORM}) v${VERSION}..."
    curl "${CURL_DL[@]}" -o "${CHROME_DIR}/${ARCHIVE}" "$URL"
    echo -e "  ${OK} ${ARCHIVE} ($(du -h "${CHROME_DIR}/${ARCHIVE}" | cut -f1))"
done

echo ""
echo -e "${OK} Chrome for Testing v${VERSION} downloaded to ${CHROME_DIR}"
echo -e "${PREFIX} Platforms: ${PLATFORMS}"
