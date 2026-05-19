#!/usr/bin/env bash
#
# chrome-update.sh — Update a browser entry's version + URL in versions.go
#                    and the corresponding embed file.
#
# Usage: chrome-update.sh NAME PLATFORM VERSION URL
#
# Example:
#   chrome-update.sh ungoogled linux64 146.0.8000.100 https://github.com/ungoogled-software/...tar.xz

set -euo pipefail

PREFIX='\033[36m[*]\033[0m'

NAME="${1:-}"
PLATFORM="${2:-}"
VERSION="${3:-}"
URL="${4:-}"

if [ -z "$NAME" ] || [ -z "$PLATFORM" ] || [ -z "$VERSION" ] || [ -z "$URL" ]; then
    echo -e "\033[31m[!] Usage: chrome-update.sh NAME PLATFORM VERSION URL\033[0m"
    echo ""
    echo "  NAME      Browser name (chromium, ungoogled, fingerprint)"
    echo "  PLATFORM  Target platform (macosarm, linux64, linuxarm64, macos)"
    echo "  VERSION   New version string"
    echo "  URL       New download URL"
    echo ""
    echo "Example:"
    echo "  chrome-update.sh ungoogled linux64 146.0.8000.100 https://github.com/ungoogled-software/...tar.xz"
    exit 1
fi

# Locate repo root
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "$0")/../../.." && pwd))"

VERSIONS_FILE="${REPO_ROOT}/internal/resources/spitolas/versions.go"

if [ ! -f "$VERSIONS_FILE" ]; then
    echo -e "\033[31m[!] versions.go not found: ${VERSIONS_FILE}\033[0m"
    exit 1
fi

echo -e "${PREFIX} Updating ${NAME}/${PLATFORM} to version ${VERSION}..."

# Update versions.go — match line by Name+Platform, replace Version and URL
sed -i.bak "/Name: \"${NAME}\", Platform: \"${PLATFORM}\"/{s|Version: \"[^\"]*\"|Version: \"${VERSION}\"|;s|URL: \"[^\"]*\"|URL: \"${URL}\"|;}" "$VERSIONS_FILE" && rm -f "${VERSIONS_FILE}.bak"

# Map NAME-PLATFORM to embed file and version constant
case "${NAME}-${PLATFORM}" in
    chromium-macosarm)
        EMBED_FILE="${REPO_ROOT}/internal/resources/spitolas/embed_darwin.go"
        CONST_NAME="chromiumVersion"
        ;;
    ungoogled-linux64)
        EMBED_FILE="${REPO_ROOT}/internal/resources/spitolas/embed_linux_ungoogled.go"
        CONST_NAME="ungoogledVersion"
        ;;
    ungoogled-linuxarm64)
        EMBED_FILE="${REPO_ROOT}/internal/resources/spitolas/embed_linux_ungoogled_arm64.go"
        CONST_NAME="ungoogledVersion"
        ;;
    fingerprint-linux64)
        EMBED_FILE="${REPO_ROOT}/internal/resources/spitolas/embed_linux_fingerprint.go"
        CONST_NAME="fingerprintVersion"
        ;;
    fingerprint-macos)
        # macOS fingerprint-chromium uses a DMG — no embed file, download only
        echo -e "${PREFIX} Updated versions.go for ${NAME}/${PLATFORM}"
        echo -e "${PREFIX} Note: macOS fingerprint-chromium (DMG) is download-only, no embed file to update"
        echo -e "${PREFIX} Run 'make deps-chrome' to download the new archive"
        exit 0
        ;;
    *)
        echo -e "\033[31m[!] Unknown NAME/PLATFORM combo: ${NAME}-${PLATFORM}\033[0m"
        exit 1
        ;;
esac

if [ ! -f "$EMBED_FILE" ]; then
    echo -e "\033[31m[!] Embed file not found: ${EMBED_FILE}\033[0m"
    exit 1
fi

sed -i.bak "s/${CONST_NAME} = \"[^\"]*\"/${CONST_NAME} = \"${VERSION}\"/" "$EMBED_FILE" && rm -f "${EMBED_FILE}.bak"

echo -e "${PREFIX} Updated ${NAME}/${PLATFORM} to ${VERSION}"
echo -e "${PREFIX} Run 'make deps-chrome' to download the new archive"
