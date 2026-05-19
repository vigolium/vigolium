#!/usr/bin/env bash
# Bootstrap installer for archon.
#
# Usage:
#   curl -fsSL <base-url>/install.sh | bash
#
# What it does:
#   1. Detects the host platform (darwin/linux × arm64/x64), with Rosetta-aware
#      fallback on macOS.
#   2. Resolves the latest version from <base-url>/metadata.json (or honors a
#      pinned ARCHON_VERSION).
#   3. Downloads archon-audit_<version>_<platform>.tar.gz from R2, or uses a tarball
#      next to this installer when running from a local release bundle.
#   4. Verifies sha256 against checksums.txt (skipped only if no shasum tool).
#   5. Extracts the `archon-audit` binary into $ARCHON_BIN_DIR (default ~/.local/bin)
#      and ensures that directory is on PATH via the user's shell rc.
#
# Env overrides:
#   ARCHON_BASE_URL   Public URL prefix where install.sh + tarballs live.
#                     Default: https://cdn.vigolium.com/archon-audit
#   ARCHON_LOCAL_DIST_DIR Local directory containing the tarballs + checksums.
#                     Default: auto-detects the install.sh directory when
#                     a matching tarball is present next to it.
#   ARCHON_HOME       Runtime home for transient install state.
#                     Default: $HOME/.archon
#   ARCHON_BIN_DIR    Directory to drop the `archon-audit` binary into.
#                     Default: $HOME/.local/bin
#   ARCHON_VERSION    Pinned version (e.g. 0.1.0 or v0.1.0).
#                     Default: resolved from $ARCHON_BASE_URL/metadata.json.
#   ARCHON_SHELL_RC   Shell startup file to update with PATH.
#                     Default: ~/.zshrc for zsh, ~/.bashrc for bash, ~/.profile otherwise.
#   SKIP_PATH_SETUP   Set to 1 to skip adding ARCHON_BIN_DIR to shell config.
#   NO_COLOR          Set to disable ANSI colors.

set -euo pipefail

DEFAULT_ARCHON_BASE_URL="https://cdn.vigolium.com/archon-audit"
ARCHON_BASE_URL="${ARCHON_BASE_URL:-}"
ARCHON_LOCAL_DIST_DIR="${ARCHON_LOCAL_DIST_DIR:-}"
ARCHON_HOME="${ARCHON_HOME:-$HOME/.archon}"
ARCHON_BIN_DIR="${ARCHON_BIN_DIR:-$HOME/.local/bin}"
ARCHON_VERSION="${ARCHON_VERSION:-}"
ARCHON_SHELL_RC="${ARCHON_SHELL_RC:-}"
SKIP_PATH_SETUP="${SKIP_PATH_SETUP:-0}"
ARCHON_PATH_RC_PATH=""
ARCHON_PATH_RC_UPDATED=0
ARCHON_PATH_RC_CONFIGURED=0

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

log()  { printf "%s[archon]%s %s\n"     "$C_INFO" "$C_RESET" "$1" >&2; }
ok()   { printf "%s[archon]%s %s%s%s\n" "$C_OK"   "$C_RESET" "$C_OK" "$1" "$C_RESET" >&2; }
warn() { printf "%s[archon]%s %s%s%s\n" "$C_WARN" "$C_RESET" "$C_WARN" "$1" "$C_RESET" >&2; }
err()  { printf "%s[archon]%s %s%s%s\n" "$C_ERR"  "$C_RESET" "$C_ERR" "$1" "$C_RESET" >&2; }
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
		'Linux riscv64')                  err "archon doesn't support riscv64 yet"; exit 1 ;;
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

detect_local_dist_dir() {
	local script_path="${BASH_SOURCE[0]:-$0}"
	[[ -f "$script_path" ]] || return 1
	local script_dir
	script_dir="$(cd "$(dirname "$script_path")" && pwd)"
	# Heuristic: a release bundle dir contains at least one tarball + checksums.txt
	if compgen -G "$script_dir/archon-audit_*_*.tar.gz" >/dev/null \
		&& [[ -f "$script_dir/checksums.txt" ]]; then
		printf '%s' "$script_dir"
		return 0
	fi
	return 1
}

# ---- shell rc / PATH setup ---------------------------------------------------
detect_shell_rc() {
	if [[ -n "$ARCHON_SHELL_RC" ]]; then
		printf "%s\n" "$ARCHON_SHELL_RC"
		return 0
	fi
	case "${SHELL##*/}" in
		zsh)        printf "%s\n" "$HOME/.zshrc" ;;
		bash | "")  printf "%s\n" "$HOME/.bashrc" ;;
		*)          printf "%s\n" "$HOME/.profile" ;;
	esac
}

archon_path_export_line() {
	if [[ "$ARCHON_BIN_DIR" == "$HOME/.local/bin" ]]; then
		printf 'export PATH=$HOME/.local/bin:"$PATH"\n'
	else
		local quoted_bin
		printf -v quoted_bin "%q" "$ARCHON_BIN_DIR"
		printf 'export PATH=%s:"$PATH"\n' "$quoted_bin"
	fi
}

add_archon_to_path() {
	[[ -n "$ARCHON_BIN_DIR" ]] || return 0
	case ":$PATH:" in
		*":$ARCHON_BIN_DIR:"*) ;;
		*) export PATH="$ARCHON_BIN_DIR:$PATH" ;;
	esac
}

configure_archon_path() {
	add_archon_to_path
	if [[ "$SKIP_PATH_SETUP" == "1" ]]; then
		return 0
	fi
	local rc_path
	rc_path="$(detect_shell_rc)"
	[[ -n "$rc_path" ]] || return 0
	ARCHON_PATH_RC_PATH="$rc_path"
	local rc_dir
	rc_dir="$(dirname "$rc_path")"
	mkdir -p "$rc_dir"
	touch "$rc_path"
	local archon_export
	archon_export="$(archon_path_export_line)"
	if grep -Fqs "$archon_export" "$rc_path"; then
		ARCHON_PATH_RC_CONFIGURED=1
		return 0
	fi
	{
		printf "\n# archon\n"
		printf "%s\n" "$archon_export"
	} >> "$rc_path"
	ARCHON_PATH_RC_UPDATED=1
	log "added ${ARCHON_BIN_DIR} PATH setup to ${rc_path}"
}

# ---- pick a sha256 binary ----------------------------------------------------
if command -v shasum >/dev/null 2>&1; then
	SHA256=(shasum -a 256)
elif command -v sha256sum >/dev/null 2>&1; then
	SHA256=(sha256sum)
else
	SHA256=()
fi

# ---- resolve VERSION ---------------------------------------------------------
resolve_version() {
	if [[ -n "$ARCHON_VERSION" ]]; then
		log "using pinned version: ${C_BOLD}${ARCHON_VERSION}${C_RESET}"
		return 0
	fi

	local source_label
	if [[ -n "$ARCHON_LOCAL_DIST_DIR" ]]; then
		source_label="local: ${ARCHON_LOCAL_DIST_DIR}/metadata.json"
	else
		source_label="$(host_of "$ARCHON_BASE_URL")/metadata.json"
	fi
	log "resolving latest version from ${C_DIM}${source_label}${C_RESET}"

	local meta_path
	meta_path="$TMPDIR_REAL/metadata.json"

	if [[ -n "$ARCHON_LOCAL_DIST_DIR" && -f "$ARCHON_LOCAL_DIST_DIR/metadata.json" ]]; then
		cp "$ARCHON_LOCAL_DIST_DIR/metadata.json" "$meta_path"
	else
		local meta_url="${ARCHON_BASE_URL%/}/metadata.json?cache-buster=${CB}"
		if ! curl -fsSL --retry 3 --retry-delay 2 -o "$meta_path" "$meta_url"; then
			err "failed to fetch metadata.json from $(host_of "$ARCHON_BASE_URL")"
			err "set ARCHON_VERSION=<version> to bypass."
			exit 1
		fi
	fi

	ARCHON_VERSION=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$meta_path" | head -1)
	if [[ -z "$ARCHON_VERSION" ]]; then
		err "could not parse 'version' from metadata.json"
		exit 1
	fi
	ok "resolved version: ${C_BOLD}${ARCHON_VERSION}${C_RESET}"
}

# ---- download + verify -------------------------------------------------------
download_artifact() {
	local platform="$1"
	local version_no_v="${ARCHON_VERSION#v}"
	local tarball_name="archon-audit_${version_no_v}_${platform}.tar.gz"

	local source_label
	if [[ -n "$ARCHON_LOCAL_DIST_DIR" ]]; then
		source_label="local: ${ARCHON_LOCAL_DIST_DIR}"
	else
		source_label="$(host_of "$ARCHON_BASE_URL")"
	fi
	log "fetching ${C_BOLD}${tarball_name}${C_RESET} ${C_DIM}from ${source_label}${C_RESET}"

	local tarball_path="$TMPDIR_REAL/$tarball_name"
	local checksums_path="$TMPDIR_REAL/checksums.txt"

	if [[ -n "$ARCHON_LOCAL_DIST_DIR" ]]; then
		[[ -f "$ARCHON_LOCAL_DIST_DIR/$tarball_name" ]] \
			|| { err "tarball not found in local dist: $tarball_name"; exit 1; }
		cp "$ARCHON_LOCAL_DIST_DIR/$tarball_name" "$tarball_path"
		[[ -f "$ARCHON_LOCAL_DIST_DIR/checksums.txt" ]] \
			&& cp "$ARCHON_LOCAL_DIST_DIR/checksums.txt" "$checksums_path"
	else
		local tarball_url="${ARCHON_BASE_URL%/}/${tarball_name}?cache-buster=${CB}"
		local checksums_url="${ARCHON_BASE_URL%/}/checksums.txt?cache-buster=${CB}"
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

install_archon_binary() {
	local platform="$1" tarball_path="$2"
	mkdir -p "$ARCHON_BIN_DIR"

	local extract_dir="$TMPDIR_REAL/extract"
	mkdir -p "$extract_dir"

	log "extracting ${C_BOLD}archon-audit${C_RESET} to ${C_BOLD}${ARCHON_BIN_DIR}${C_RESET}"
	tar -xzf "$tarball_path" -C "$extract_dir" 2> >(
		grep -vE 'Ignoring unknown extended header keyword .LIBARCHIVE\.xattr' >&2 || true
	)

	local extracted="$extract_dir/archon-audit"
	[[ -f "$extracted" ]] || { err "tarball did not contain 'archon-audit' binary"; exit 1; }

	# Atomic move into place.
	local target="$ARCHON_BIN_DIR/archon-audit"
	if [[ -f "$target" ]]; then
		log "replacing existing ${C_DIM}${target}${C_RESET}"
	fi
	mv -f "$extracted" "$target"
	chmod +x "$target"

	ok "installed ${C_BOLD}${target}${C_RESET}"
}

# ---- main --------------------------------------------------------------------
if [[ -z "$ARCHON_BASE_URL" && -z "$ARCHON_LOCAL_DIST_DIR" ]]; then
	ARCHON_LOCAL_DIST_DIR="$(detect_local_dist_dir || true)"
fi
if [[ -z "$ARCHON_BASE_URL" && -z "$ARCHON_LOCAL_DIST_DIR" ]]; then
	ARCHON_BASE_URL="$DEFAULT_ARCHON_BASE_URL"
fi

CB="$(date +%s)-$$"
TMPDIR_REAL="$(mktemp -d -t archon-install.XXXXXX)"
trap 'rm -rf "$TMPDIR_REAL"' EXIT
mkdir -p "$ARCHON_HOME"

printf "%s%s%s archon installer\n" "$C_BOLD" "▸" "$C_RESET" >&2
if [[ -n "$ARCHON_LOCAL_DIST_DIR" ]]; then
	log "source:  ${C_DIM}local: ${ARCHON_LOCAL_DIST_DIR}${C_RESET}"
else
	log "source:  ${C_DIM}$(host_of "$ARCHON_BASE_URL")${C_RESET}"
fi
log "dest:    ${C_DIM}${ARCHON_BIN_DIR}/archon-audit${C_RESET}"

if ! command -v curl >/dev/null 2>&1 && [[ -z "$ARCHON_LOCAL_DIST_DIR" ]]; then
	err "curl is required to download from ${C_DIM}$(host_of "$ARCHON_BASE_URL")${C_RESET}"
	exit 1
fi
for cmd in uname mktemp tar mv chmod awk sed; do
	command -v "$cmd" >/dev/null 2>&1 || { err "need '$cmd' (command not found)"; exit 1; }
done

PLATFORM="$(detect_platform)"
log "platform: ${C_BOLD}${PLATFORM}${C_RESET}"

resolve_version
TARBALL_PATH="$(download_artifact "$PLATFORM")"
install_archon_binary "$PLATFORM" "$TARBALL_PATH"
configure_archon_path

# Final hint.
echo ""
case ":$PATH:" in
	*":$ARCHON_BIN_DIR:"*)
		ok "done. run: ${C_BOLD}archon-audit --help${C_RESET}"
		;;
	*)
		ok "done."
		warn "${ARCHON_BIN_DIR} is not on PATH for this shell yet."
		log  "run: ${C_BOLD}export PATH=\"${ARCHON_BIN_DIR}:\$PATH\"${C_RESET}"
		;;
esac

if [[ "$ARCHON_PATH_RC_UPDATED" == "1" ]]; then
	log "PATH updated in ${C_BOLD}${ARCHON_PATH_RC_PATH}${C_RESET}; restart your shell or run:"
	log "  ${C_BOLD}source ${ARCHON_PATH_RC_PATH}${C_RESET}"
elif [[ "$ARCHON_PATH_RC_CONFIGURED" == "1" ]]; then
	log "PATH already configured in ${C_BOLD}${ARCHON_PATH_RC_PATH}${C_RESET}"
elif [[ "$SKIP_PATH_SETUP" == "1" ]]; then
	warn "SKIP_PATH_SETUP=1 — shell PATH config was not updated."
fi

log "next: ${C_BOLD}archon-audit verify claude${C_RESET} ${C_DIM}then${C_RESET} ${C_BOLD}archon-audit run --mode lite --target ./your-repo${C_RESET}"
