#!/usr/bin/env bash
set -euo pipefail

# Vigolium CLI Nightly Installation Script
#
# Always pulls artifacts from the Vigolium R2 CDN — no npm, node, or registry
# fallback. The Makefile's `prepare-release-scripts` target stamps BASE_URL
# at upload time so the copy at $BASE_URL/install.sh is self-consistent with
# the artifacts in the same prefix.
#
# Environment overrides:
#   VIGOLIUM_INSTALL_BASE_URL  — override the CDN prefix (default: nightly R2)
#   VIGOLIUM_VERSION           — pin a specific version (e.g. v0.1.8-alpha);
#                                when empty, $BASE_URL/metadata.json is read
#                                to resolve the latest nightly.
#   VIGOLIUM_HOME              — local staging dir (default: ~/.vigolium)

# --- configuration -----------------------------------------------------------

VIGOLIUM_HOME="${VIGOLIUM_HOME:-$HOME/.vigolium}"
BIN_DIR="$HOME/.local/bin"

# Base URL for the nightly artifact prefix on R2. The Makefile target
# `prepare-release-scripts` rewrites this line in place via:
#   perl -0pi -e 's|^BASE_URL="[^"]*"|BASE_URL="$(INSTALL_BASE_URL)"|m'
# so the first line below is the stamp-on-upload anchor. The second line
# layers the runtime env override.
BASE_URL="https://cdn.vigolium.com/vigolium-nightly-release"
BASE_URL="${VIGOLIUM_INSTALL_BASE_URL:-$BASE_URL}"

VERSION="${VIGOLIUM_VERSION:-}"
PLATFORM_TAG=""     # goreleaser-style os_arch (e.g. linux_arm64)
TARBALL_URL=""
TARBALL_FILENAME=""
TARBALL_SHA256=""

# Retry configuration
MAX_RETRIES=6
INITIAL_RETRY_DELAY=2  # seconds

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
LIGHT_GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- output helpers ----------------------------------------------------------

cleanup() {
	echo -e "\n${YELLOW}Installation interrupted...${NC}"
	rm -f "$VIGOLIUM_HOME/vigolium-install-"* 2>/dev/null || true
	exit 1
}

trap cleanup INT TERM

log()     { echo -e "${BLUE}[INFO]${NC} $1" >&2; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1" >&2; }
error()   { echo -e "${RED}[ERROR]${NC} $1" >&2; exit 1; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" >&2; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

need_cmd() {
	if ! command_exists "$1"; then
		error "need '$1' (command not found)"
	fi
}

# --- prerequisites -----------------------------------------------------------

JQ=""
SHA256_CMD=""

check_prereqs() {
	for cmd in uname mktemp chmod mkdir rm mv tar grep awk cut head sed basename touch find; do
		need_cmd "$cmd"
	done

	# goreleaser publishes SHA-256 digests into checksums.txt.
	if command_exists shasum; then
		SHA256_CMD="shasum -a 256"
	elif command_exists sha256sum; then
		SHA256_CMD="sha256sum"
	else
		error "need 'shasum' or 'sha256sum' (command not found)"
	fi

	# jq is optional — metadata.json is small/flat enough for the grep+sed
	# fallback in json_field, but jq gives a more robust parse when present.
	if command_exists jq; then
		JQ="$(command -v jq)"
	fi
}

# --- platform detection ------------------------------------------------------

detect_platform() {
	local platform target
	platform="$(uname -s) $(uname -m)"

	case $platform in
		'Darwin x86_64')
			target=darwin_amd64
			;;
		'Darwin arm64')
			target=darwin_arm64
			;;
		'Linux aarch64' | 'Linux arm64')
			target=linux_arm64
			;;
		'Linux riscv64')
			error 'Not supported on riscv64'
			;;
		MINGW* | MSYS* | CYGWIN* | Windows_NT*)
			error "Windows is not supported yet. Please build from source instead: https://github.com/vigolium/vigolium#build-from-source"
			;;
		'Linux x86_64' | *)
			target=linux_amd64
			;;
	esac

	# Rosetta 2 on macOS — a process forced through translation reports arch
	# x86_64 but is actually running on Apple silicon. Prefer the native build.
	if [[ "$target" == "darwin_amd64" ]]; then
		if [[ $(sysctl -n sysctl.proc_translated 2>/dev/null) = 1 ]]; then
			target=darwin_arm64
			log "Your shell is running in Rosetta 2. Using $target instead"
		fi
	fi

	echo "$target"
}

# --- downloader --------------------------------------------------------------

# Robust downloader that handles snap curl issues with retry logic.
#   $1 = url, $2 = output file, $3 = mode: "hard" (default) | "soft",
#   $4 = progress: 0 (default, silent) | 1 (show progress bar on stderr)
# In "soft" mode exhausted retries return non-zero (fewer, quicker attempts,
# no abort) so callers can fall back; "hard" mode aborts via error().
downloader() {
	local url="$1"
	local output_file="$2"
	local mode="${3:-hard}"
	local progress="${4:-0}"
	local attempt=1
	local delay=$INITIAL_RETRY_DELAY
	local max_retries=$MAX_RETRIES
	if [[ "$mode" == "soft" ]]; then
		max_retries=2
		delay=1
	fi

	# Check if we have a broken snap curl
	local snap_curl=0
	if command_exists curl; then
		local curl_path
		curl_path=$(command -v curl)
		if [[ "$curl_path" == *"/snap/"* ]]; then
			snap_curl=1
		fi
	fi

	while [[ $attempt -le $max_retries ]]; do
		rm -f "$output_file" 2>/dev/null || true

		local download_success=0

		if command_exists curl && [[ $snap_curl -eq 0 ]]; then
			if [[ $progress -eq 1 ]]; then
				# -#: progress bar to stderr; -fL: fail on HTTP errors, follow redirects
				if curl -#fL "$url" -o "$output_file"; then
					download_success=1
				fi
			else
				if curl -fsSL "$url" -o "$output_file" 2>/dev/null; then
					download_success=1
				fi
			fi
		elif command_exists wget; then
			if [[ $progress -eq 1 ]]; then
				# --show-progress: progress bar to stderr (leave stderr open)
				if wget -q --show-progress "$url" -O "$output_file"; then
					download_success=1
				fi
			else
				if wget -q --show-progress "$url" -O "$output_file" 2>/dev/null; then
					download_success=1
				fi
			fi
		elif [[ $snap_curl -eq 1 ]]; then
			error "curl installed with snap cannot download files due to missing permissions. Please uninstall it and reinstall curl with a different package manager (e.g., apt)."
		else
			error "Neither curl nor wget found. Please install one of them."
		fi

		if [[ $download_success -eq 1 ]]; then
			return 0
		fi

		if [[ $attempt -lt $max_retries ]]; then
			if [[ $attempt -ge 3 ]]; then
				warn "Download failed (attempt $attempt/$max_retries). Retrying in ${delay}s..."
			fi
			sleep "$delay"
			delay=$((delay * 2))
			attempt=$((attempt + 1))
		else
			if [[ "$mode" == "soft" ]]; then
				return 1
			fi
			error "Download failed after $max_retries attempts. URL: $url"
		fi
	done
	return 1
}

# --- metadata + version resolution ------------------------------------------

# Extract a single string field from a small flat JSON document.
#   $1 = json file, $2 = jq filter, $3 = fallback flat key name
json_field() {
	local file="$1" filter="$2" key="$3"
	if [[ -n "$JQ" ]]; then
		"$JQ" -r "${filter} // empty" "$file" 2>/dev/null || true
	else
		grep -o "\"${key}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$file" \
			| head -1 \
			| sed 's/.*:[[:space:]]*"\([^"]*\)"/\1/'
	fi
}

# Resolve the latest published nightly version from the CDN's metadata.json
# (written by the Makefile's `generate-metadata` target at release time).
# Sets VERSION to the value as published (typically with a leading `v`).
resolve_latest_version() {
	local manifest_url="${BASE_URL}/metadata.json?t=$(date +%s)"
	local tmp_manifest resolved
	tmp_manifest=$(mktemp)

	log "Resolving latest nightly version from ${BASE_URL}/metadata.json..."
	if ! downloader "$manifest_url" "$tmp_manifest"; then
		rm -f "$tmp_manifest"
		return 1
	fi

	resolved=$(json_field "$tmp_manifest" '.version' 'version')
	rm -f "$tmp_manifest"

	if [[ -z "$resolved" ]]; then
		return 1
	fi

	VERSION="$resolved"
	return 0
}

# --- tarball URL + checksum lookup ------------------------------------------

# Compose the tarball URL + filename for the resolved VERSION + PLATFORM_TAG.
# goreleaser strips the leading `v` from the version, so the filename pattern
# is vigolium_<ver-no-v>_<os>_<arch>.tar.gz (see .goreleaser.yaml).
build_tarball_url() {
	local ver_no_v="${VERSION#v}"
	TARBALL_FILENAME="vigolium_${ver_no_v}_${PLATFORM_TAG}.tar.gz"
	TARBALL_URL="${BASE_URL}/${TARBALL_FILENAME}"
}

# Fetch checksums.txt from the CDN and extract the SHA-256 line for
# TARBALL_FILENAME. A missing checksums.txt or an unlisted file degrades to
# an unverified download (warning printed); a stale CDN with no checksums
# at all should not block install.
fetch_checksum() {
	local checksum_url="${BASE_URL}/checksums.txt?t=$(date +%s)"
	local tmp_checksums
	tmp_checksums=$(mktemp)

	log "Fetching checksums.txt..."
	if ! downloader "$checksum_url" "$tmp_checksums" soft; then
		rm -f "$tmp_checksums"
		warn "Could not fetch checksums.txt; binary download will not be verified"
		return 0
	fi

	# checksums.txt format (goreleaser default): one line per file as
	#   <sha256>  <filename>
	# (two spaces between when produced by sha256sum / shasum -a 256).
	TARBALL_SHA256=$(grep -E "[[:space:]]${TARBALL_FILENAME}\$" "$tmp_checksums" \
		| awk '{print $1}' \
		| head -1)
	rm -f "$tmp_checksums"

	if [[ -z "$TARBALL_SHA256" ]]; then
		warn "Checksum for ${TARBALL_FILENAME} not found in checksums.txt; skipping verification"
	fi
}

# --- download + verify -------------------------------------------------------

download_file() {
	local url="$1"
	local output_file="$2"
	local version="${3:-}"

	if [[ -n "$version" ]]; then
		log "Downloading $(basename "$output_file") (${LIGHT_GREEN}${version}${NC})..."
	else
		log "Downloading $(basename "$output_file")..."
	fi

	local temp_file
	temp_file=$(mktemp "$(dirname "$output_file")/tmp.XXXXXX")
	# Tarball is the large download — show a progress bar so slow links
	# don't look hung. Other callers (metadata.json, checksums.txt) stay
	# silent via the default mode.
	downloader "$url" "$temp_file" hard 1
	mv "$temp_file" "$output_file"
}

verify_checksum() {
	local file="$1"
	local expected_checksum="$2"

	if [[ -z "$expected_checksum" ]]; then
		warn "No checksum available; skipping verification"
		return
	fi

	log "Verifying checksum (SHA-256)..."

	local actual_checksum
	actual_checksum=$($SHA256_CMD "$file" | cut -d' ' -f1)

	if [[ "$actual_checksum" != "$expected_checksum" ]]; then
		error "Checksum verification failed!\nExpected: $expected_checksum\nActual: $actual_checksum"
	fi

	success "Checksum verified"
}

# --- existing install detection ---------------------------------------------

check_existing_installation() {
	local binary_path="$BIN_DIR/vigolium"
	local existing_binary=""

	if [[ -x "$binary_path" ]]; then
		existing_binary="$binary_path"
	elif command_exists vigolium; then
		existing_binary=$(command -v vigolium)
	fi

	if [[ -n "$existing_binary" ]]; then
		warn "Detected existing vigolium installation at $existing_binary"

		local version_output
		version_output=$("$existing_binary" version 2>/dev/null || true)
		if [[ -n "$version_output" ]]; then
			local old_version old_build old_commit
			old_version=$(echo "$version_output" | grep 'Version:' || true)
			old_build=$(echo "$version_output" | grep 'Build:' || true)
			old_commit=$(echo "$version_output" | grep 'Commit:' || true)
			if [[ -n "$old_version" || -n "$old_build" || -n "$old_commit" ]]; then
				log "Existing binary info:"
				[[ -n "$old_version" ]] && echo -e "  ${YELLOW}${old_version}${NC}"
				[[ -n "$old_build" ]] && echo -e "  ${YELLOW}${old_build}${NC}"
				[[ -n "$old_commit" ]] && echo -e "  ${YELLOW}${old_commit}${NC}"
			fi
		fi

		log "Will replace with the new version..."
	fi
}

# --- install -----------------------------------------------------------------

install_vigolium_binary() {
	local binary_name="vigolium"

	check_existing_installation

	build_tarball_url
	fetch_checksum

	log "Installing version: ${LIGHT_GREEN}${VERSION}${NC} (${PLATFORM_TAG})"

	local tarball_path="$VIGOLIUM_HOME/vigolium-install-tarball.tgz"
	local extract_dir="$VIGOLIUM_HOME/vigolium-install-extract"

	mkdir -p "$VIGOLIUM_HOME"
	mkdir -p "$BIN_DIR"
	rm -rf "$extract_dir"
	mkdir -p "$extract_dir"

	download_file "$TARBALL_URL" "$tarball_path" "$VERSION"
	verify_checksum "$tarball_path" "$TARBALL_SHA256"

	log "Extracting tarball..."
	tar -xzf "$tarball_path" -C "$extract_dir"

	# goreleaser tarballs hold the binary at the top level (no nesting,
	# unlike npm's package/vendor/<tag>/vigolium.gz layout). find handles
	# both forms in case a future archive template adds a wrapper dir.
	local binary_path="$BIN_DIR/$binary_name"
	local extracted_binary
	extracted_binary=$(find "$extract_dir" -type f -name "${binary_name}" -print 2>/dev/null | head -1)
	if [[ -z "$extracted_binary" ]]; then
		error "Could not find '${binary_name}' binary in the tarball"
	fi

	# Stage on the same filesystem as the target, then atomic rename.
	# Writing directly to $binary_path would fail with ETXTBSY when
	# `vigolium update` runs this installer — the parent vigolium process
	# still has the executable mapped. rename(2) swaps the directory entry
	# without touching the inode, so the running process is unaffected.
	local staged="${binary_path}.new"
	rm -f "$staged"
	mv "$extracted_binary" "$staged"
	chmod +x "$staged"
	mv "$staged" "$binary_path"

	rm -f "$tarball_path"
	rm -rf "$extract_dir"

	success "Vigolium CLI binary installed to ${LIGHT_GREEN}${binary_path}${NC}"

	local version_output
	version_output=$("$binary_path" version 2>/dev/null || true)
	if [[ -n "$version_output" ]]; then
		local build_info commit_info
		build_info=$(echo "$version_output" | grep 'Build:' || true)
		commit_info=$(echo "$version_output" | grep 'Commit:' || true)
		if [[ -n "$build_info" || -n "$commit_info" ]]; then
			log "Installed binary info:"
			[[ -n "$build_info" ]] && echo -e "  ${LIGHT_GREEN}${build_info}${NC}"
			[[ -n "$commit_info" ]] && echo -e "  ${LIGHT_GREEN}${commit_info}${NC}"
		fi
	fi
}

# --- shell profile -----------------------------------------------------------

update_shell_profile() {
	local default_shell="bash"
	if [[ "$(uname -s)" == "Darwin" ]]; then
		default_shell="zsh"
	fi

	local shell_name
	shell_name=$(basename "${SHELL:-$default_shell}")

	local shell_profiles=()
	local refresh_command=""

	case "$shell_name" in
		zsh)
			shell_profiles=("$HOME/.zshrc")
			refresh_command="exec \$SHELL"
			;;
		bash)
			[[ -f "$HOME/.bashrc" ]] && shell_profiles+=("$HOME/.bashrc")
			[[ -f "$HOME/.bash_profile" ]] && shell_profiles+=("$HOME/.bash_profile")
			[[ ${#shell_profiles[@]} -eq 0 ]] && shell_profiles=("$HOME/.bashrc")
			refresh_command="source ~/.bashrc"
			;;
		fish)
			shell_profiles=("$HOME/.config/fish/config.fish")
			refresh_command="source ~/.config/fish/config.fish"
			;;
		*)
			warn "Unknown shell: $shell_name"
			warn "Please add $BIN_DIR to your PATH manually:"
			echo "  export PATH=\"$BIN_DIR:\$PATH\""
			return
			;;
	esac

	local updated=0
	for shell_profile in "${shell_profiles[@]}"; do
		if [[ -f "$shell_profile" ]] && grep -q "$BIN_DIR" "$shell_profile" 2>/dev/null; then
			log "PATH already configured in $shell_profile"
			continue
		fi

		if [[ ! -f "$shell_profile" ]]; then
			mkdir -p "$(dirname "$shell_profile")"
			touch "$shell_profile"
		fi

		{
			echo ""
			echo "# Vigolium CLI"
			echo "export PATH=\"$BIN_DIR:\$PATH\""
		} >> "$shell_profile"

		success "Added ${LIGHT_GREEN}${BIN_DIR}${NC} to PATH in ${LIGHT_GREEN}${shell_profile}${NC}"
		updated=1
	done

	if [[ $updated -eq 1 ]]; then
		echo ""
		log "To activate the PATH, run:"
		echo -e "  ${LIGHT_GREEN}${refresh_command}${NC}"
	fi
}

# --- main --------------------------------------------------------------------

main() {
	log "Starting Vigolium CLI nightly installation..."
	log "Source: ${LIGHT_GREEN}${BASE_URL}${NC}"

	check_prereqs

	if [[ -n "$VERSION" ]]; then
		log "Using pinned version: ${LIGHT_GREEN}${VERSION}${NC} (VIGOLIUM_VERSION override)"
	else
		if ! resolve_latest_version; then
			error "Failed to resolve latest nightly version from ${BASE_URL}/metadata.json"
		fi
		log "Latest nightly: ${LIGHT_GREEN}${VERSION}${NC}"
	fi

	local platform
	platform=$(detect_platform)
	PLATFORM_TAG="$platform"
	log "Detected platform: ${PLATFORM_TAG}"

	local bin_dir_was_in_path=0
	if echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
		bin_dir_was_in_path=1
	fi

	install_vigolium_binary
	update_shell_profile
	export PATH="$BIN_DIR:$PATH"

	echo ""
	success "Vigolium CLI installed successfully!"
	if [[ $bin_dir_was_in_path -eq 0 ]]; then
		warn "${LIGHT_GREEN}${BIN_DIR}${NC} was not in your PATH before this installation"
		log "Run this to use vigolium immediately without restarting your shell:"
		echo -e "  ${LIGHT_GREEN}export PATH=\"$BIN_DIR:\$PATH\" && vigolium doctor${NC}"
	else
		log "Run ${LIGHT_GREEN}vigolium doctor${NC} to validate your setup"
	fi

	echo ""
	log "Visit ${LIGHT_GREEN}https://docs.vigolium.com${NC} for more details"
	log "Or check out the cloud version at ${LIGHT_GREEN}https://console.vigolium.com${NC}"
}

main "$@"
