#!/usr/bin/env bash
# Bootstrap installer for vigolium-audit.
#
# Usage:
#   curl -fsSL <base-url>/install.sh | bash
#
# What it does:
#   1. Detects the host platform (darwin/linux × arm64/x64), with Rosetta-aware
#      fallback on macOS.
#   2. Primary path: resolves @vigolium/vigolium-audit@<tag> from the npm
#      registry, downloads the tarball, verifies its sha1 against dist.shasum,
#      and extracts the matching brotli-compressed binary for this platform.
#   3. Fallback path: pulls vigolium-audit_<version>_<platform>.tar.gz from the
#      CDN (cdn.vigolium.com/vigolium-audit), verifying sha256 against
#      checksums.txt.
#   4. Installs the decompressed `vigolium-audit` binary into
#      $VIGOLIUM_AUDIT_BIN_DIR (default ~/.local/bin) and ensures that
#      directory is on PATH via the user's shell rc.
#
# Env overrides:
#   VIGOLIUM_AUDIT_NPM_REGISTRY    npm registry base URL.
#                                  Default: https://registry.npmjs.org
#   VIGOLIUM_AUDIT_NPM_TAG         npm dist-tag to install.
#                                  Default: latest
#   VIGOLIUM_AUDIT_SKIP_NPM        Set to 1 to skip the npm path and go
#                                  straight to the CDN fallback.
#   VIGOLIUM_AUDIT_BASE_URL        CDN URL prefix used by the fallback path.
#                                  Default: https://cdn.vigolium.com/vigolium-audit
#   VIGOLIUM_AUDIT_LOCAL_DIST_DIR  Local directory containing the CDN-style
#                                  tarballs + checksums (highest priority).
#                                  Default: auto-detects the install.sh
#                                  directory when a matching tarball is
#                                  present next to it.
#   VIGOLIUM_AUDIT_HOME            Runtime home for transient install state.
#                                  Default: $HOME/.vigolium-audit
#   VIGOLIUM_AUDIT_BIN_DIR         Directory to drop the `vigolium-audit`
#                                  binary into.
#                                  Default: $HOME/.local/bin
#   VIGOLIUM_AUDIT_VERSION         Pinned version (e.g. 0.1.0 or v0.1.0).
#                                  Default: resolved from npm dist-tag or
#                                  $VIGOLIUM_AUDIT_BASE_URL/metadata.json.
#   VIGOLIUM_AUDIT_SHELL_RC        Shell startup file to update with PATH.
#                                  Default: ~/.zshrc for zsh, ~/.bashrc for
#                                  bash, ~/.profile otherwise.
#   SKIP_PATH_SETUP                Set to 1 to skip adding
#                                  VIGOLIUM_AUDIT_BIN_DIR to shell config.
#   NO_COLOR                       Set to disable ANSI colors.

set -euo pipefail

DEFAULT_VIGOLIUM_AUDIT_BASE_URL="https://cdn.vigolium.com/vigolium-audit"
VIGOLIUM_AUDIT_BASE_URL="${VIGOLIUM_AUDIT_BASE_URL:-}"
VIGOLIUM_AUDIT_LOCAL_DIST_DIR="${VIGOLIUM_AUDIT_LOCAL_DIST_DIR:-}"
VIGOLIUM_AUDIT_HOME="${VIGOLIUM_AUDIT_HOME:-$HOME/.vigolium-audit}"
VIGOLIUM_AUDIT_BIN_DIR="${VIGOLIUM_AUDIT_BIN_DIR:-$HOME/.local/bin}"
VIGOLIUM_AUDIT_VERSION="${VIGOLIUM_AUDIT_VERSION:-}"
VIGOLIUM_AUDIT_SHELL_RC="${VIGOLIUM_AUDIT_SHELL_RC:-}"
SKIP_PATH_SETUP="${SKIP_PATH_SETUP:-0}"
VIGOLIUM_AUDIT_PATH_RC_PATH=""
VIGOLIUM_AUDIT_PATH_RC_UPDATED=0
VIGOLIUM_AUDIT_PATH_RC_CONFIGURED=0

# npm path config
NPM_REGISTRY="${VIGOLIUM_AUDIT_NPM_REGISTRY:-https://registry.npmjs.org}"
NPM_PKG="@vigolium/vigolium-audit"
NPM_PKG_ENC="@vigolium%2Fvigolium-audit"
NPM_DIST_TAG="${VIGOLIUM_AUDIT_NPM_TAG:-latest}"
SKIP_NPM="${VIGOLIUM_AUDIT_SKIP_NPM:-0}"

# Resolved during npm flow
NPM_VERSION=""
NPM_TARBALL_URL=""
NPM_TARBALL_SHA1=""

# ---- color helpers -----------------------------------------------------------
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
	C_INFO=$'\033[36m'   # cyan
	C_OK=$'\033[32m'     # green
	C_WARN=$'\033[33m'   # yellow
	C_ERR=$'\033[31m'    # red
	C_DIM=$'\033[2m'     # dim
	C_BOLD=$'\033[1m'    # bold
	C_RESET=$'\033[0m'
else
	C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""; C_DIM=""; C_BOLD=""; C_RESET=""
fi

log()  { printf "%s[vigolium-audit]%s %s\n"     "$C_INFO" "$C_RESET" "$1" >&2; }
ok()   { printf "%s[vigolium-audit]%s %s%s%s\n" "$C_OK"   "$C_RESET" "$C_OK" "$1" "$C_RESET" >&2; }
warn() { printf "%s[vigolium-audit]%s %s%s%s\n" "$C_WARN" "$C_RESET" "$C_WARN" "$1" "$C_RESET" >&2; }
err()  { printf "%s[vigolium-audit]%s %s%s%s\n" "$C_ERR"  "$C_RESET" "$C_ERR" "$1" "$C_RESET" >&2; }
dim()  { printf "%s%s%s\n" "$C_DIM" "$1" "$C_RESET" >&2; }

host_of() {
	local u="${1#http://}"
	u="${u#https://}"
	printf '%s' "${u%%/*}"
}

# ---- platform detection ------------------------------------------------------
detect_platform() {
	local p target
	p="$(uname -s) $(uname -m)"
	case $p in
		'Darwin x86_64')                  target=darwin_x64 ;;
		'Darwin arm64')                   target=darwin_arm64 ;;
		'Linux aarch64' | 'Linux arm64')  target=linux_arm64 ;;
		'Linux riscv64')                  err "vigolium-audit doesn't support riscv64 yet"; exit 1 ;;
		'Linux x86_64' | *)               target=linux_x64 ;;
	esac
	# Rosetta 2: a darwin_x64 shell on Apple Silicon should pull arm64.
	if [[ "$target" == "darwin_x64" ]]; then
		if [[ $(sysctl -n sysctl.proc_translated 2>/dev/null) = 1 ]]; then
			target=darwin_arm64
			log "Rosetta 2 detected — using ${target} instead"
		fi
	fi
	printf '%s' "$target"
}

# Map detected platform tag to the npm-style suffix used inside the npm
# tarball (e.g. linux_x64 → linux-x64). cli.cjs uses `process.platform-arch`,
# which is the same shape.
npm_platform_suffix() {
	case "$1" in
		darwin_arm64) printf '%s' "darwin-arm64" ;;
		darwin_x64)   printf '%s' "darwin-x64" ;;
		linux_arm64)  printf '%s' "linux-arm64" ;;
		linux_x64)    printf '%s' "linux-x64" ;;
		*) return 1 ;;
	esac
}

detect_local_dist_dir() {
	local script_path="${BASH_SOURCE[0]:-$0}"
	[[ -f "$script_path" ]] || return 1
	local script_dir
	script_dir="$(cd "$(dirname "$script_path")" && pwd)"
	# Heuristic: a release bundle dir contains at least one tarball + checksums.txt
	if compgen -G "$script_dir/vigolium-audit_*_*.tar.gz" >/dev/null \
		&& [[ -f "$script_dir/checksums.txt" ]]; then
		printf '%s' "$script_dir"
		return 0
	fi
	return 1
}

# ---- shell rc / PATH setup ---------------------------------------------------
detect_shell_rc() {
	if [[ -n "$VIGOLIUM_AUDIT_SHELL_RC" ]]; then
		printf "%s\n" "$VIGOLIUM_AUDIT_SHELL_RC"
		return 0
	fi
	case "${SHELL##*/}" in
		zsh)        printf "%s\n" "$HOME/.zshrc" ;;
		bash | "")  printf "%s\n" "$HOME/.bashrc" ;;
		*)          printf "%s\n" "$HOME/.profile" ;;
	esac
}

vigolium_audit_path_export_line() {
	if [[ "$VIGOLIUM_AUDIT_BIN_DIR" == "$HOME/.local/bin" ]]; then
		printf 'export PATH=$HOME/.local/bin:"$PATH"\n'
	else
		local quoted_bin
		printf -v quoted_bin "%q" "$VIGOLIUM_AUDIT_BIN_DIR"
		printf 'export PATH=%s:"$PATH"\n' "$quoted_bin"
	fi
}

add_vigolium_audit_to_path() {
	[[ -n "$VIGOLIUM_AUDIT_BIN_DIR" ]] || return 0
	case ":$PATH:" in
		*":$VIGOLIUM_AUDIT_BIN_DIR:"*) ;;
		*) export PATH="$VIGOLIUM_AUDIT_BIN_DIR:$PATH" ;;
	esac
}

configure_vigolium_audit_path() {
	add_vigolium_audit_to_path
	if [[ "$SKIP_PATH_SETUP" == "1" ]]; then
		return 0
	fi
	local rc_path
	rc_path="$(detect_shell_rc)"
	[[ -n "$rc_path" ]] || return 0
	VIGOLIUM_AUDIT_PATH_RC_PATH="$rc_path"
	local rc_dir
	rc_dir="$(dirname "$rc_path")"
	mkdir -p "$rc_dir"
	touch "$rc_path"
	local vigolium_audit_export
	vigolium_audit_export="$(vigolium_audit_path_export_line)"
	if grep -Fqs "$vigolium_audit_export" "$rc_path"; then
		VIGOLIUM_AUDIT_PATH_RC_CONFIGURED=1
		return 0
	fi
	{
		printf "\n# vigolium-audit\n"
		printf "%s\n" "$vigolium_audit_export"
	} >> "$rc_path"
	VIGOLIUM_AUDIT_PATH_RC_UPDATED=1
	log "added ${VIGOLIUM_AUDIT_BIN_DIR} PATH setup to ${rc_path}"
}

# ---- checksums ---------------------------------------------------------------
if command -v shasum >/dev/null 2>&1; then
	SHA256=(shasum -a 256)
	SHA1=(shasum -a 1)
elif command -v sha256sum >/dev/null 2>&1; then
	SHA256=(sha256sum)
	SHA1=()
	command -v sha1sum >/dev/null 2>&1 && SHA1=(sha1sum)
else
	SHA256=()
	SHA1=()
fi

# ---- brotli decoder detection ------------------------------------------------
# Find something that can read a brotli-compressed stdin and write the
# decompressed bytes to stdout. Tried in order; first hit wins. Sets:
#   BROTLI_DECODER=("cmd" "arg" ...) — argv array
#   BROTLI_DECODER_NAME=label        — for log output
BROTLI_DECODER=()
BROTLI_DECODER_NAME=""
detect_brotli_decoder() {
	if command -v brotli >/dev/null 2>&1; then
		BROTLI_DECODER=(brotli -d -c)
		BROTLI_DECODER_NAME="brotli"
		return 0
	fi
	if command -v bun >/dev/null 2>&1; then
		BROTLI_DECODER=(bun -e 'require("zlib").pipeline(process.stdin,require("zlib").createBrotliDecompress(),process.stdout,e=>{if(e){console.error(e.message);process.exit(1)}})')
		BROTLI_DECODER_NAME="bun"
		return 0
	fi
	if command -v node >/dev/null 2>&1; then
		BROTLI_DECODER=(node -e 'require("zlib").pipeline(process.stdin,require("zlib").createBrotliDecompress(),process.stdout,e=>{if(e){console.error(e.message);process.exit(1)}})')
		BROTLI_DECODER_NAME="node"
		return 0
	fi
	if command -v python3 >/dev/null 2>&1; then
		if python3 -c 'import brotli' >/dev/null 2>&1; then
			BROTLI_DECODER=(python3 -c 'import sys,brotli; sys.stdout.buffer.write(brotli.decompress(sys.stdin.buffer.read()))')
			BROTLI_DECODER_NAME="python3+brotli"
			return 0
		fi
		if python3 -c 'import brotlicffi' >/dev/null 2>&1; then
			BROTLI_DECODER=(python3 -c 'import sys,brotlicffi; sys.stdout.buffer.write(brotlicffi.decompress(sys.stdin.buffer.read()))')
			BROTLI_DECODER_NAME="python3+brotlicffi"
			return 0
		fi
	fi
	return 1
}

# Read a tiny JSON field from a flat document. $1=file, $2=key.
json_string_field() {
	local file="$1" key="$2"
	sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$file" | head -1
}

# ---- npm install path --------------------------------------------------------
# Resolve VIGOLIUM_AUDIT_VERSION (or the dist-tag) → NPM_VERSION,
# NPM_TARBALL_URL, NPM_TARBALL_SHA1 from the registry.
fetch_npm_manifest() {
	local ref="${VIGOLIUM_AUDIT_VERSION:-$NPM_DIST_TAG}"
	ref="${ref#v}"
	local manifest_url="${NPM_REGISTRY%/}/${NPM_PKG_ENC}/${ref}?cache-buster=${CB}"
	local manifest_path="$TMPDIR_REAL/npm-manifest.json"

	log "resolving ${C_BOLD}${NPM_PKG}@${ref}${C_RESET} ${C_DIM}from $(host_of "$NPM_REGISTRY")${C_RESET}"
	if ! curl -fsSL --retry 3 --retry-delay 2 -o "$manifest_path" "$manifest_url"; then
		warn "npm registry fetch failed for ${NPM_PKG}@${ref}"
		return 1
	fi

	NPM_VERSION="$(json_string_field "$manifest_path" version)"
	NPM_TARBALL_URL="$(json_string_field "$manifest_path" tarball)"
	NPM_TARBALL_SHA1="$(json_string_field "$manifest_path" shasum)"

	if [[ -z "$NPM_VERSION" || -z "$NPM_TARBALL_URL" ]]; then
		warn "could not parse npm manifest for ${NPM_PKG}@${ref}"
		return 1
	fi

	ok "resolved version: ${C_BOLD}${NPM_VERSION}${C_RESET} ${C_DIM}(npm)${C_RESET}"
	return 0
}

# Download + verify the npm tarball, extract the matching brotli binary,
# decompress it, install into BIN_DIR. Returns 0 on success, 1 to fall through.
install_from_npm() {
	if [[ "$SKIP_NPM" == "1" ]]; then
		log "VIGOLIUM_AUDIT_SKIP_NPM=1 — skipping npm path"
		return 1
	fi
	if ! command -v curl >/dev/null 2>&1; then
		warn "curl missing — cannot use npm registry path"
		return 1
	fi
	if ! detect_brotli_decoder; then
		warn "no brotli decoder found (brotli/bun/node/python3+brotli) — skipping npm path"
		return 1
	fi
	log "brotli decoder: ${C_DIM}${BROTLI_DECODER_NAME}${C_RESET}"

	if ! fetch_npm_manifest; then
		return 1
	fi

	local platform="$1"
	local suffix
	if ! suffix="$(npm_platform_suffix "$platform")"; then
		warn "no npm binary suffix for platform ${platform}"
		return 1
	fi

	local tarball_path="$TMPDIR_REAL/npm-pkg.tgz"
	log "fetching ${C_BOLD}$(basename "$NPM_TARBALL_URL")${C_RESET} ${C_DIM}from $(host_of "$NPM_TARBALL_URL")${C_RESET}"
	if ! curl -fsSL --retry 3 --retry-delay 2 -o "$tarball_path" "$NPM_TARBALL_URL"; then
		warn "npm tarball download failed"
		return 1
	fi

	# npm dist.shasum is sha1.
	if [[ -n "$NPM_TARBALL_SHA1" && ${#SHA1[@]} -gt 0 ]]; then
		local actual
		actual=$("${SHA1[@]}" "$tarball_path" | awk '{print $1}')
		if [[ "$actual" != "$NPM_TARBALL_SHA1" ]]; then
			err "sha1 mismatch on npm tarball"
			err "  expected: $NPM_TARBALL_SHA1"
			err "  actual:   $actual"
			return 1
		fi
		ok "sha1 verified ${C_DIM}(${actual:0:12}…)${C_RESET}"
	else
		warn "skipping sha1 verification of npm tarball (no shasum/sha1sum tool or no dist.shasum)"
	fi

	local extract_dir="$TMPDIR_REAL/npm-extract"
	mkdir -p "$extract_dir"
	log "extracting npm tarball"
	if ! tar -xzf "$tarball_path" -C "$extract_dir" 2> >(
		grep -vE 'Ignoring unknown extended header keyword .LIBARCHIVE\.xattr' >&2 || true
	); then
		warn "tar extract failed on npm tarball"
		return 1
	fi

	# Tarball lays out as package/bin/vigolium-audit-<version>-<suffix>.br
	local br_path="$extract_dir/package/bin/vigolium-audit-${NPM_VERSION}-${suffix}.br"
	if [[ ! -f "$br_path" ]]; then
		# Be lenient about exact pathing in case publish layout shifts.
		br_path="$(find "$extract_dir" -type f -name "vigolium-audit-${NPM_VERSION}-${suffix}.br" -print 2>/dev/null | head -1)"
	fi
	if [[ -z "$br_path" || ! -f "$br_path" ]]; then
		warn "npm tarball did not contain a brotli binary for ${suffix} (version ${NPM_VERSION})"
		return 1
	fi

	mkdir -p "$VIGOLIUM_AUDIT_BIN_DIR"
	local target="$VIGOLIUM_AUDIT_BIN_DIR/vigolium-audit"
	local tmp_bin="$TMPDIR_REAL/vigolium-audit.bin"

	log "decompressing $(basename "$br_path") ${C_DIM}(${BROTLI_DECODER_NAME})${C_RESET}"
	if ! "${BROTLI_DECODER[@]}" < "$br_path" > "$tmp_bin"; then
		warn "brotli decompression failed (${BROTLI_DECODER_NAME})"
		return 1
	fi
	if [[ ! -s "$tmp_bin" ]]; then
		warn "decompressed binary is empty"
		return 1
	fi

	if [[ -f "$target" ]]; then
		log "replacing existing ${C_DIM}${target}${C_RESET}"
	fi
	mv -f "$tmp_bin" "$target"
	chmod +x "$target"

	VIGOLIUM_AUDIT_VERSION="$NPM_VERSION"
	ok "installed ${C_BOLD}${target}${C_RESET} ${C_DIM}(npm ${NPM_PKG}@${NPM_VERSION})${C_RESET}"
	return 0
}

# ---- CDN fallback path -------------------------------------------------------
# Resolve VERSION from $VIGOLIUM_AUDIT_BASE_URL/metadata.json (or local dir).
resolve_version_cdn() {
	if [[ -n "$VIGOLIUM_AUDIT_VERSION" ]]; then
		log "using pinned version: ${C_BOLD}${VIGOLIUM_AUDIT_VERSION}${C_RESET}"
		return 0
	fi

	local source_label
	if [[ -n "$VIGOLIUM_AUDIT_LOCAL_DIST_DIR" ]]; then
		source_label="local: ${VIGOLIUM_AUDIT_LOCAL_DIST_DIR}/metadata.json"
	else
		source_label="$(host_of "$VIGOLIUM_AUDIT_BASE_URL")/metadata.json"
	fi
	log "resolving latest version from ${C_DIM}${source_label}${C_RESET}"

	local meta_path
	meta_path="$TMPDIR_REAL/metadata.json"

	if [[ -n "$VIGOLIUM_AUDIT_LOCAL_DIST_DIR" && -f "$VIGOLIUM_AUDIT_LOCAL_DIST_DIR/metadata.json" ]]; then
		cp "$VIGOLIUM_AUDIT_LOCAL_DIST_DIR/metadata.json" "$meta_path"
	else
		local meta_url="${VIGOLIUM_AUDIT_BASE_URL%/}/metadata.json?cache-buster=${CB}"
		if ! curl -fsSL --retry 3 --retry-delay 2 -o "$meta_path" "$meta_url"; then
			err "failed to fetch metadata.json from $(host_of "$VIGOLIUM_AUDIT_BASE_URL")"
			err "set VIGOLIUM_AUDIT_VERSION=<version> to bypass."
			exit 1
		fi
	fi

	VIGOLIUM_AUDIT_VERSION=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$meta_path" | head -1)
	if [[ -z "$VIGOLIUM_AUDIT_VERSION" ]]; then
		err "could not parse 'version' from metadata.json"
		exit 1
	fi
	ok "resolved version: ${C_BOLD}${VIGOLIUM_AUDIT_VERSION}${C_RESET} ${C_DIM}(cdn)${C_RESET}"
}

download_artifact_cdn() {
	local platform="$1"
	local version_no_v="${VIGOLIUM_AUDIT_VERSION#v}"
	local tarball_name="vigolium-audit_${version_no_v}_${platform}.tar.gz"

	local source_label
	if [[ -n "$VIGOLIUM_AUDIT_LOCAL_DIST_DIR" ]]; then
		source_label="local: ${VIGOLIUM_AUDIT_LOCAL_DIST_DIR}"
	else
		source_label="$(host_of "$VIGOLIUM_AUDIT_BASE_URL")"
	fi
	log "fetching ${C_BOLD}${tarball_name}${C_RESET} ${C_DIM}from ${source_label}${C_RESET}"

	local tarball_path="$TMPDIR_REAL/$tarball_name"
	local checksums_path="$TMPDIR_REAL/checksums.txt"

	if [[ -n "$VIGOLIUM_AUDIT_LOCAL_DIST_DIR" ]]; then
		[[ -f "$VIGOLIUM_AUDIT_LOCAL_DIST_DIR/$tarball_name" ]] \
			|| { err "tarball not found in local dist: $tarball_name"; exit 1; }
		cp "$VIGOLIUM_AUDIT_LOCAL_DIST_DIR/$tarball_name" "$tarball_path"
		[[ -f "$VIGOLIUM_AUDIT_LOCAL_DIST_DIR/checksums.txt" ]] \
			&& cp "$VIGOLIUM_AUDIT_LOCAL_DIST_DIR/checksums.txt" "$checksums_path"
	else
		local tarball_url="${VIGOLIUM_AUDIT_BASE_URL%/}/${tarball_name}?cache-buster=${CB}"
		local checksums_url="${VIGOLIUM_AUDIT_BASE_URL%/}/checksums.txt?cache-buster=${CB}"
		if ! curl -fsSL --retry 3 --retry-delay 2 -o "$tarball_path" "$tarball_url"; then
			err "download failed: ${tarball_name}"
			exit 1
		fi
		curl -fsSL --retry 2 -o "$checksums_path" "$checksums_url" 2>/dev/null || true
	fi

	if [[ ${#SHA256[@]} -gt 0 && -f "$checksums_path" ]]; then
		local expected
		expected=$(grep -F "$tarball_name" "$checksums_path" | awk '{print $1}' | head -1)
		if [[ -n "$expected" ]]; then
			local actual
			actual=$("${SHA256[@]}" "$tarball_path" | awk '{print $1}')
			if [[ "$expected" != "$actual" ]]; then
				err "sha256 mismatch for $tarball_name"
				err "  expected: $expected"
				err "  actual:   $actual"
				exit 1
			fi
			ok "sha256 verified ${C_DIM}(${actual:0:12}…)${C_RESET}"
		else
			warn "no checksum entry for $tarball_name in checksums.txt — skipping verification"
		fi
	else
		warn "skipping sha256 verification (no shasum tool or checksums.txt)"
	fi

	printf '%s' "$tarball_path"
}

install_from_cdn() {
	local platform="$1"
	resolve_version_cdn
	local tarball_path
	tarball_path="$(download_artifact_cdn "$platform")"

	mkdir -p "$VIGOLIUM_AUDIT_BIN_DIR"
	local extract_dir="$TMPDIR_REAL/cdn-extract"
	mkdir -p "$extract_dir"

	log "extracting ${C_BOLD}vigolium-audit${C_RESET} to ${C_BOLD}${VIGOLIUM_AUDIT_BIN_DIR}${C_RESET}"
	tar -xzf "$tarball_path" -C "$extract_dir" 2> >(
		grep -vE 'Ignoring unknown extended header keyword .LIBARCHIVE\.xattr' >&2 || true
	)

	local extracted="$extract_dir/vigolium-audit"
	[[ -f "$extracted" ]] || { err "tarball did not contain 'vigolium-audit' binary"; exit 1; }

	local target="$VIGOLIUM_AUDIT_BIN_DIR/vigolium-audit"
	if [[ -f "$target" ]]; then
		log "replacing existing ${C_DIM}${target}${C_RESET}"
	fi
	mv -f "$extracted" "$target"
	chmod +x "$target"
	ok "installed ${C_BOLD}${target}${C_RESET} ${C_DIM}(cdn ${VIGOLIUM_AUDIT_VERSION})${C_RESET}"
}

# ---- main --------------------------------------------------------------------
if [[ -z "$VIGOLIUM_AUDIT_BASE_URL" && -z "$VIGOLIUM_AUDIT_LOCAL_DIST_DIR" ]]; then
	VIGOLIUM_AUDIT_LOCAL_DIST_DIR="$(detect_local_dist_dir || true)"
fi
if [[ -z "$VIGOLIUM_AUDIT_BASE_URL" && -z "$VIGOLIUM_AUDIT_LOCAL_DIST_DIR" ]]; then
	VIGOLIUM_AUDIT_BASE_URL="$DEFAULT_VIGOLIUM_AUDIT_BASE_URL"
fi

# A local dist bundle next to install.sh takes priority over both npm and
# remote CDN — preserves the original "run from an unpacked release" workflow.
if [[ -n "$VIGOLIUM_AUDIT_LOCAL_DIST_DIR" ]]; then
	SKIP_NPM=1
fi

CB="$(date +%s)-$$"
TMPDIR_REAL="$(mktemp -d -t vigolium-audit-install.XXXXXX)"
trap 'rm -rf "$TMPDIR_REAL"' EXIT
mkdir -p "$VIGOLIUM_AUDIT_HOME"

printf "%s%s%s vigolium-audit installer\n" "$C_BOLD" "▸" "$C_RESET" >&2
if [[ -n "$VIGOLIUM_AUDIT_LOCAL_DIST_DIR" ]]; then
	log "source:  ${C_DIM}local: ${VIGOLIUM_AUDIT_LOCAL_DIST_DIR}${C_RESET}"
else
	log "primary: ${C_DIM}npm ${NPM_PKG}@${NPM_DIST_TAG} ($(host_of "$NPM_REGISTRY"))${C_RESET}"
	log "fallback:${C_DIM} $(host_of "$VIGOLIUM_AUDIT_BASE_URL")${C_RESET}"
fi
log "dest:    ${C_DIM}${VIGOLIUM_AUDIT_BIN_DIR}/vigolium-audit${C_RESET}"

if ! command -v curl >/dev/null 2>&1 && [[ -z "$VIGOLIUM_AUDIT_LOCAL_DIST_DIR" ]]; then
	err "curl is required to download from $(host_of "$VIGOLIUM_AUDIT_BASE_URL") or the npm registry"
	exit 1
fi
for cmd in uname mktemp tar mv chmod awk sed find; do
	command -v "$cmd" >/dev/null 2>&1 || { err "need '$cmd' (command not found)"; exit 1; }
done

PLATFORM="$(detect_platform)"
log "platform: ${C_BOLD}${PLATFORM}${C_RESET}"

# Try npm first, fall through to CDN on any failure.
if install_from_npm "$PLATFORM"; then
	:
else
	[[ "$SKIP_NPM" == "1" ]] || warn "npm path failed — falling back to CDN"
	install_from_cdn "$PLATFORM"
fi

configure_vigolium_audit_path

# Final hint.
echo ""
case ":$PATH:" in
	*":$VIGOLIUM_AUDIT_BIN_DIR:"*)
		ok "done. run: ${C_BOLD}vigolium-audit --help${C_RESET}"
		;;
	*)
		ok "done."
		warn "${VIGOLIUM_AUDIT_BIN_DIR} is not on PATH for this shell yet."
		log  "run: ${C_BOLD}export PATH=\"${VIGOLIUM_AUDIT_BIN_DIR}:\$PATH\"${C_RESET}"
		;;
esac

if [[ "$VIGOLIUM_AUDIT_PATH_RC_UPDATED" == "1" ]]; then
	log "PATH updated in ${C_BOLD}${VIGOLIUM_AUDIT_PATH_RC_PATH}${C_RESET}; restart your shell or run:"
	log "  ${C_BOLD}source ${VIGOLIUM_AUDIT_PATH_RC_PATH}${C_RESET}"
elif [[ "$VIGOLIUM_AUDIT_PATH_RC_CONFIGURED" == "1" ]]; then
	log "PATH already configured in ${C_BOLD}${VIGOLIUM_AUDIT_PATH_RC_PATH}${C_RESET}"
elif [[ "$SKIP_PATH_SETUP" == "1" ]]; then
	warn "SKIP_PATH_SETUP=1 — shell PATH config was not updated."
fi

log "next: ${C_BOLD}vigolium-audit verify claude${C_RESET} ${C_DIM}then${C_RESET} ${C_BOLD}vigolium-audit run --mode lite --target ./your-repo${C_RESET}"
