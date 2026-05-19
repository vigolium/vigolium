#!/usr/bin/env bash
set -euo pipefail

# install-deps.sh — install host tools that `vigolium doctor --fix` does not
# cover: semgrep (Python) and codeql (glibc binary). Idempotent. Designed to
# run as root inside Docker build stages, but also runs standalone on any
# Debian/Ubuntu host with python3-pip + unzip + curl available.
#
# Multi-arch caveat: CodeQL CLI only ships Linux x86_64 builds upstream
# (https://github.com/github/codeql-cli-binaries/releases). On Linux ARM64
# we skip codeql with a log line — semgrep still installs.

log()  { echo "[install-deps] $*" >&2; }
fail() { echo "[install-deps] ERROR: $*" >&2; exit 1; }

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo amd64 ;;
        aarch64|arm64)  echo arm64 ;;
        *) fail "unsupported arch: $(uname -m)" ;;
    esac
}

install_semgrep() {
    if command -v semgrep >/dev/null 2>&1; then
        log "semgrep already present: $(semgrep --version 2>/dev/null || echo unknown)"
        return
    fi
    log "installing semgrep via pip"
    pip install --break-system-packages --no-cache-dir semgrep
    log "semgrep installed: $(semgrep --version 2>/dev/null || echo unknown)"
}

install_codeql() {
    if [ -x /opt/codeql/codeql ]; then
        log "codeql already present at /opt/codeql"
        return
    fi

    local arch
    arch=$(detect_arch)
    if [ "$arch" != "amd64" ]; then
        log "codeql: skipping — upstream ships no Linux $arch build (Linux x86_64 only)"
        return
    fi

    local url tmp
    url="https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip"
    tmp=$(mktemp -d)

    log "downloading codeql ($arch) from ${url}"
    if ! curl -fsSL "$url" -o "$tmp/codeql.zip"; then
        rm -rf "$tmp"
        fail "codeql download failed"
    fi

    log "extracting codeql to /opt"
    mkdir -p /opt
    if ! unzip -q "$tmp/codeql.zip" -d /opt/; then
        rm -rf "$tmp"
        fail "codeql archive extract failed"
    fi
    rm -rf "$tmp"

    [ -x /opt/codeql/codeql ] || fail "codeql archive did not produce /opt/codeql/codeql"

    ln -sf /opt/codeql/codeql /usr/local/bin/codeql
    log "codeql installed: $(/opt/codeql/codeql --version 2>/dev/null | head -1 || echo present)"
}

main() {
    install_semgrep
    install_codeql
    log "done"
}

main "$@"
