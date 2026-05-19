#!/usr/bin/env bash
set -euo pipefail

# Vigolium CLI Nightly Installation Script
# Resolves the latest nightly @vigolium/vigolium release from the npm registry
# and downloads the matching per-platform tarball (no npm/node required).
# Falls back to the `latest` dist-tag when a `nightly` tag is not published.

# Configuration
VIGOLIUM_HOME="${VIGOLIUM_HOME:-$HOME/.vigolium}"
BIN_DIR="$HOME/.local/bin"
NPM_REGISTRY="${VIGOLIUM_NPM_REGISTRY:-https://registry.npmjs.org}"
NPM_PKG="@vigolium/vigolium"
NPM_PKG_ENC="@vigolium%2Fvigolium"   # URL-encoded scoped name
NPM_DIST_TAG="${VIGOLIUM_NPM_TAG:-nightly}"  # which dist-tag to install
NPM_FALLBACK_TAG="latest"            # used if NPM_DIST_TAG does not resolve
VERSION=""        # base version, resolved from the npm dist-tag
PLATFORM_TAG=""   # npm platform tag, e.g. darwin-arm64
TARBALL_URL=""    # resolved per-platform tarball URL
TARBALL_SHA1=""   # dist.shasum (sha1) from the registry

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

# Cleanup on interrupt
cleanup() {
	echo -e "\n${YELLOW}Installation interrupted...${NC}"
	rm -f "$VIGOLIUM_HOME/vigolium-install-"* 2>/dev/null || true
	exit 1
}

trap cleanup INT TERM

log() {
	echo -e "${BLUE}[INFO]${NC} $1" >&2
}

warn() {
	echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

error() {
	echo -e "${RED}[ERROR]${NC} $1" >&2
	exit 1
}

success() {
	echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

# Check if command exists
command_exists() {
	command -v "$1" >/dev/null 2>&1
}

# Require command to exist or exit with error
need_cmd() {
	if ! command_exists "$1"; then
		error "need '$1' (command not found)"
	fi
}

JQ=""

# Check all prerequisite commands upfront
check_prereqs() {
	for cmd in uname mktemp chmod mkdir rm mv tar grep awk cut head sed basename touch find gzip; do
		need_cmd "$cmd"
	done

	# Check for sha1 checksum command (shasum on macOS/BSD, sha1sum on Linux)
	# — npm publishes dist.shasum as a SHA-1 hex digest.
	if command_exists shasum; then
		SHA1_CMD="shasum -a 1"
	elif command_exists sha1sum; then
		SHA1_CMD="sha1sum"
	else
		error "need 'shasum' or 'sha1sum' (command not found)"
	fi

	# jq is optional: used when present for robust JSON parsing, otherwise a
	# grep/sed fallback handles the small flat registry documents we fetch.
	if command_exists jq; then
		JQ="$(command -v jq)"
	fi
}

# Detect target platform for CLI binary
detect_platform() {
	local platform
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

	# Check for Rosetta 2 on macOS
	if [[ "$target" == "darwin_amd64" ]]; then
		if [[ $(sysctl -n sysctl.proc_translated 2>/dev/null) = 1 ]]; then
			target=darwin_arm64
			log "Your shell is running in Rosetta 2. Using $target instead"
		fi
	fi

	echo "$target"
}

# Map the detected goreleaser-style target to the npm platform tag used by
# @vigolium/vigolium per-platform packages.
npm_platform_tag() {
	case "$1" in
		darwin_amd64) echo "darwin-x64" ;;
		darwin_arm64) echo "darwin-arm64" ;;
		linux_amd64)  echo "linux-x64" ;;
		linux_arm64)  echo "linux-arm64" ;;
		*) error "Unsupported platform for npm install: $1" ;;
	esac
}

# Robust downloader that handles snap curl issues with retry logic.
#   $1 = url, $2 = output file, $3 = mode: "hard" (default) | "soft"
# In "soft" mode exhausted retries return non-zero (fewer, quicker attempts,
# no abort) so callers can fall back; "hard" mode aborts via error().
downloader() {
	local url="$1"
	local output_file="$2"
	local mode="${3:-hard}"
	local attempt=1
	local delay=$INITIAL_RETRY_DELAY
	local max_retries=$MAX_RETRIES
	if [[ "$mode" == "soft" ]]; then
		# A missing dist-tag is a deterministic 404 — fail fast and let the
		# caller fall back instead of a ~60s exponential-backoff storm.
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
		# Remove any partial download from previous attempt
		rm -f "$output_file" 2>/dev/null || true

		local download_success=0

		# Check if we have a working (non-snap) curl
		if command_exists curl && [[ $snap_curl -eq 0 ]]; then
			if curl -fsSL "$url" -o "$output_file" 2>/dev/null; then
				download_success=1
			fi
		# Try wget for both no curl and the broken snap curl
		elif command_exists wget; then
			if wget -q --show-progress "$url" -O "$output_file" 2>/dev/null; then
				download_success=1
			fi
		# If we can't fall back from broken snap curl to wget, report the broken snap curl
		elif [[ $snap_curl -eq 1 ]]; then
			error "curl installed with snap cannot download files due to missing permissions. Please uninstall it and reinstall curl with a different package manager (e.g., apt)."
		else
			error "Neither curl nor wget found. Please install one of them."
		fi

		if [[ $download_success -eq 1 ]]; then
			return 0
		fi

		# Download failed
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

# Extract a single string field from a small registry JSON document.
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

# Resolve the base version that a given dist-tag points to (best-effort).
resolve_tag_version() {
	local tag="$1"
	local manifest_url="${NPM_REGISTRY}/${NPM_PKG_ENC}/${tag}?t=$(date +%s)"
	local tmp_manifest resolved
	tmp_manifest=$(mktemp)

	if ! downloader "$manifest_url" "$tmp_manifest" soft; then
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

# Resolve the base version, preferring NPM_DIST_TAG and falling back.
fetch_latest_version() {
	log "Resolving ${NPM_PKG}@${NPM_DIST_TAG} from npm registry..."
	if resolve_tag_version "$NPM_DIST_TAG"; then
		log "Nightly version: ${LIGHT_GREEN}${VERSION}${NC} (tag: ${NPM_DIST_TAG})"
		return 0
	fi

	if [[ "$NPM_DIST_TAG" != "$NPM_FALLBACK_TAG" ]]; then
		warn "dist-tag '${NPM_DIST_TAG}' not found; falling back to '${NPM_FALLBACK_TAG}'"
		if resolve_tag_version "$NPM_FALLBACK_TAG"; then
			log "Resolved version: ${LIGHT_GREEN}${VERSION}${NC} (tag: ${NPM_FALLBACK_TAG})"
			return 0
		fi
	fi

	return 1
}

# Resolve the per-platform tarball URL + sha1 for VERSION/PLATFORM_TAG.
fetch_platform_manifest() {
	local pkg_version="${VERSION}-${PLATFORM_TAG}"
	local manifest_url="${NPM_REGISTRY}/${NPM_PKG_ENC}/${pkg_version}?t=$(date +%s)"
	local tmp_manifest
	tmp_manifest=$(mktemp)

	log "Resolving platform package ${NPM_PKG}@${pkg_version}..."
	downloader "$manifest_url" "$tmp_manifest"

	TARBALL_URL=$(json_field "$tmp_manifest" '.dist.tarball' 'tarball')
	TARBALL_SHA1=$(json_field "$tmp_manifest" '.dist.shasum' 'shasum')
	rm -f "$tmp_manifest"

	if [[ -z "$TARBALL_URL" ]]; then
		error "Could not resolve a tarball for ${NPM_PKG}@${pkg_version}. This platform may not be published for this release."
	fi
}

# Download file with progress
download_file() {
	local url="$1"
	local output_file="$2"
	local version="${3:-}"

	if [[ -n "$version" ]]; then
		log "Downloading $(basename "$output_file") (${LIGHT_GREEN}${version}${NC})..."
	else
		log "Downloading $(basename "$output_file")..."
	fi

	# Use secure temporary file
	local temp_file
	temp_file=$(mktemp "$(dirname "$output_file")/tmp.XXXXXX")

	# Download to temp file first, then atomic move
	downloader "$url" "$temp_file"
	mv "$temp_file" "$output_file"
}

# Verify SHA1 checksum against the registry's dist.shasum
verify_checksum() {
	local file="$1"
	local expected_checksum="$2"

	if [[ -z "$expected_checksum" ]]; then
		warn "Registry did not provide a checksum; skipping verification"
		return
	fi

	log "Verifying checksum..."

	local actual_checksum
	actual_checksum=$($SHA1_CMD "$file" | cut -d' ' -f1)

	if [[ "$actual_checksum" != "$expected_checksum" ]]; then
		error "Checksum verification failed!\nExpected: $expected_checksum\nActual: $actual_checksum"
	fi

	success "Checksum verified"
}

# Check for existing vigolium installation
check_existing_installation() {
	local binary_path="$BIN_DIR/vigolium"
	local existing_binary=""

	# Check in BIN_DIR first
	if [[ -x "$binary_path" ]]; then
		existing_binary="$binary_path"
	# Also check if vigolium is in PATH (might be installed elsewhere)
	elif command_exists vigolium; then
		existing_binary=$(command -v vigolium)
	fi

	if [[ -n "$existing_binary" ]]; then
		warn "Detected existing vigolium installation at $existing_binary"

		# Try to get current version info
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

# Install Vigolium CLI binary from the resolved npm tarball
install_vigolium_binary() {
	local binary_name="vigolium"

	# Check for existing installation before proceeding
	check_existing_installation

	# Resolve the per-platform tarball + checksum from the registry
	fetch_platform_manifest

	log "Installing version: ${LIGHT_GREEN}${VERSION}${NC} (${PLATFORM_TAG})"

	local tarball_path="$VIGOLIUM_HOME/vigolium-install-tarball.tgz"
	local extract_dir="$VIGOLIUM_HOME/vigolium-install-extract"

	# Ensure directories exist
	mkdir -p "$VIGOLIUM_HOME"
	mkdir -p "$BIN_DIR"
	rm -rf "$extract_dir"
	mkdir -p "$extract_dir"

	# Download tarball
	download_file "$TARBALL_URL" "$tarball_path" "$VERSION"

	# Verify checksum against the registry's dist.shasum
	verify_checksum "$tarball_path" "$TARBALL_SHA1"

	# Extract tarball (npm tarballs nest everything under package/)
	log "Extracting tarball..."
	tar -xzf "$tarball_path" -C "$extract_dir"

	# The npm platform package ships the binary gzipped at
	# package/vendor/<tag>/vigolium.gz — decompress it into BIN_DIR.
	local binary_path="$BIN_DIR/$binary_name"
	local gz_path
	gz_path=$(find "$extract_dir" -type f -name "${binary_name}.gz" -print 2>/dev/null | head -1)
	if [[ -z "$gz_path" ]]; then
		error "Could not find '${binary_name}.gz' in the npm tarball"
	fi

	log "Decompressing binary..."
	gzip -dc "$gz_path" > "$binary_path"

	# Make executable
	chmod +x "$binary_path"

	# Clean up
	rm -f "$tarball_path"
	rm -rf "$extract_dir"

	success "Vigolium CLI binary installed to ${LIGHT_GREEN}${binary_path}${NC}"

	# Show build info from the installed binary
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

# Update PATH in shell profile
update_shell_profile() {
	# Detect shell from $SHELL or default
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
			# Add to both .bashrc (interactive) and .bash_profile (login shells)
			[[ -f "$HOME/.bashrc" ]] && shell_profiles+=("$HOME/.bashrc")
			[[ -f "$HOME/.bash_profile" ]] && shell_profiles+=("$HOME/.bash_profile")
			# If neither exists, create .bashrc
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
		# Check if PATH is already updated
		if [[ -f "$shell_profile" ]] && grep -q "$BIN_DIR" "$shell_profile" 2>/dev/null; then
			log "PATH already configured in $shell_profile"
			continue
		fi

		# Create config file if it doesn't exist
		if [[ ! -f "$shell_profile" ]]; then
			mkdir -p "$(dirname "$shell_profile")"
			touch "$shell_profile"
		fi

		# Add to PATH
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

# Main installation
main() {
	log "Starting Vigolium CLI nightly installation..."

	# Check prerequisites
	check_prereqs

	# Resolve the base version from the requested npm dist-tag (with fallback)
	if ! fetch_latest_version; then
		error "Failed to resolve ${NPM_PKG} from the npm registry"
	fi

	# Detect platform and map to the npm platform tag
	local platform
	platform=$(detect_platform)
	PLATFORM_TAG=$(npm_platform_tag "$platform")
	log "Detected platform: $platform (npm: $PLATFORM_TAG)"

	# Check if BIN_DIR was already in PATH before installation
	local bin_dir_was_in_path=0
	if echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
		bin_dir_was_in_path=1
	fi

	# Install binary
	install_vigolium_binary

	# Update shell profile
	update_shell_profile

	# Make binary available immediately in this shell session
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
