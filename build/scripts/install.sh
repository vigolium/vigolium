#!/usr/bin/env bash
set -euo pipefail

# Vigolium CLI Installation Script
# Downloads pre-compiled Vigolium CLI binary from R2 bucket

# Configuration
VIGOLIUM_HOME="${VIGOLIUM_HOME:-$HOME/.vigolium}"
BIN_DIR="$HOME/.local/bin"
BASE_URL="https://cdn.vigolium.com/6813d66ecb9a55ab58d674accc4fd07c"
VERSION="v0.0.1-alpha"

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

# Check all prerequisite commands upfront
check_prereqs() {
	for cmd in uname mktemp chmod mkdir rm mv tar grep awk cut head sed basename touch; do
		need_cmd "$cmd"
	done

	# Check for sha256 checksum command (shasum on macOS/BSD, sha256sum on Linux)
	if command_exists shasum; then
		SHA256_CMD="shasum -a 256"
	elif command_exists sha256sum; then
		SHA256_CMD="sha256sum"
	else
		error "need 'shasum' or 'sha256sum' (command not found)"
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

# Robust downloader that handles snap curl issues with retry logic
downloader() {
	local url="$1"
	local output_file="$2"
	local attempt=1
	local delay=$INITIAL_RETRY_DELAY

	# Check if we have a broken snap curl
	local snap_curl=0
	if command_exists curl; then
		local curl_path
		curl_path=$(command -v curl)
		if [[ "$curl_path" == *"/snap/"* ]]; then
			snap_curl=1
		fi
	fi

	while [[ $attempt -le $MAX_RETRIES ]]; do
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
		if [[ $attempt -lt $MAX_RETRIES ]]; then
			if [[ $attempt -ge 3 ]]; then
				warn "Download failed (attempt $attempt/$MAX_RETRIES). Retrying in ${delay}s..."
			fi
			sleep "$delay"
			delay=$((delay * 2))
			attempt=$((attempt + 1))
		else
			error "Download failed after $MAX_RETRIES attempts. URL: $url"
		fi
	done
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

# Verify SHA256 checksum
verify_checksum() {
	local file="$1"
	local expected_checksum="$2"

	log "Verifying checksum..."

	local actual_checksum
	actual_checksum=$($SHA256_CMD "$file" | cut -d' ' -f1)

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
		local old_version=""
		local old_build=""
		# Try to get the current version
		old_version=$("$existing_binary" version 2>/dev/null | grep 'Version:' || echo "")
		old_build=$("$existing_binary" version 2>/dev/null | grep 'Build:' || echo "")

		if [[ -n "$old_version" && -n "$old_build" ]]; then
			warn "Detected existing vigolium installation at $existing_binary (${old_version} - ${old_build})"
		else
			warn "Detected existing vigolium installation at $existing_binary"
		fi
		log "Will replace with the new version..."
	fi
}

# Install Vigolium CLI binary
install_vigolium_binary() {
	local platform="$1"
	local binary_name="vigolium"

	# Check for existing installation before proceeding
	check_existing_installation

	log "Installing version: ${LIGHT_GREEN}${VERSION}${NC}"

	# Strip 'v' prefix for tarball filename (e.g., v1.0.0 -> 1.0.0)
	local version_no_v="${VERSION#v}"
	local tarball_name="vigolium_${version_no_v}_${platform}.tar.gz"
	# Append cache-busting query param to bypass CDN cache
	local cache_bust="?t=$(date +%s)"
	local tarball_url="${BASE_URL}/${tarball_name}${cache_bust}"
	local checksum_url="${BASE_URL}/checksums.txt${cache_bust}"

	local tarball_path="$VIGOLIUM_HOME/vigolium-install-tarball.tar.gz"
	local checksum_path="$VIGOLIUM_HOME/vigolium-install-checksums.txt"
	local extract_dir="$VIGOLIUM_HOME/vigolium-install-extract"

	# Ensure directories exist
	mkdir -p "$VIGOLIUM_HOME"
	mkdir -p "$BIN_DIR"
	mkdir -p "$extract_dir"

	# Download checksum first
	download_file "$checksum_url" "$checksum_path" "$VERSION"

	# Extract expected checksum for our tarball
	local expected_checksum
	expected_checksum=$(grep "$tarball_name" "$checksum_path" | awk '{print $1}')

	if [[ -z "$expected_checksum" ]]; then
		error "Could not find checksum for $tarball_name in checksums file"
	fi

	# Download tarball
	download_file "$tarball_url" "$tarball_path" "$VERSION"

	# Verify checksum
	verify_checksum "$tarball_path" "$expected_checksum"

	# Extract tarball
	log "Extracting tarball..."
	tar -xzf "$tarball_path" -C "$extract_dir"

	# Move binary to BIN_DIR
	local binary_path="$BIN_DIR/$binary_name"
	mv "$extract_dir/$binary_name" "$binary_path"

	# Make executable
	chmod +x "$binary_path"

	# Clean up
	rm -f "$tarball_path" "$checksum_path"
	rm -rf "$extract_dir"

	success "Vigolium CLI binary installed to ${LIGHT_GREEN}${binary_path}${NC}"
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
	log "Starting Vigolium CLI installation..."

	# Check prerequisites
	check_prereqs

	# Detect platform
	local platform
	platform=$(detect_platform)
	log "Detected platform: $platform"

	# Check if BIN_DIR was already in PATH before installation
	local bin_dir_was_in_path=0
	if echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
		bin_dir_was_in_path=1
	fi

	# Install binary
	install_vigolium_binary "$platform"

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
}

main "$@"
