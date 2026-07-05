#!/usr/bin/env bash
set -euo pipefail

# Publish the already-built public artifacts to a GitHub release.
#
# Invoked by `make github-release` AFTER `make public-release` has produced the
# cross-platform tarballs in build/dist-public/. This script does the GitHub
# half: it creates (and pushes) the git tag if missing, pulls the release notes
# from CHANGELOG.md, and creates — or, for an unchanged version, edits in place —
# the GitHub release, uploading every artifact.
#
# Usage (normally via `make github-release`):
#   github-release.sh
#
# Env / make vars:
#   VERSION          = release tag/title (default: parsed from pkg/cli/version.go)
#   PUBLIC_DIST_DIR  = artifact dir (default: build/dist-public)
#   CHANGELOG        = changelog path (default: CHANGELOG.md)
#   TAG_TARGET       = commit-ish the new tag points at (default: HEAD)
#
# Re-running for a version whose release already exists edits that release —
# refreshing the notes and re-uploading (clobbering) every artifact — instead of
# failing on the duplicate tag.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION_FILE="$ROOT/pkg/cli/version.go"
PUBLIC_DIST_DIR="${PUBLIC_DIST_DIR:-build/dist-public}"
CHANGELOG="${CHANGELOG:-CHANGELOG.md}"
TAG_TARGET="${TAG_TARGET:-HEAD}"

die()  { printf '\033[31m[!] %s\033[0m\n' "$*" >&2; exit 1; }
info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }

command -v gh  >/dev/null 2>&1 || die "gh CLI not found — install GitHub CLI (https://cli.github.com/)."
command -v git >/dev/null 2>&1 || die "git not found."

VERSION="${VERSION:-}"
if [ -z "$VERSION" ]; then
  [ -f "$VERSION_FILE" ] || die "version file not found: $VERSION_FILE"
  VERSION="$(grep -E '^[[:space:]]*Version[[:space:]]*=' "$VERSION_FILE" | head -1 | cut -d '"' -f 2)"
fi
[ -n "$VERSION" ] || die "could not determine VERSION"

# --- Release notes from CHANGELOG.md -----------------------------------------
# Grab the block from the `## [<version>]` header up to (not including) the next
# `## [` section header.
[ -f "$CHANGELOG" ] || die "changelog not found: $CHANGELOG"
notes_file="$(mktemp)"
trap 'rm -f "$notes_file"' EXIT
awk -v ver="$VERSION" '
  index($0, "## [" ver "]") == 1 { grab=1; next }
  grab && /^## \[/ { exit }
  grab { print }
' "$CHANGELOG" > "$notes_file"
[ -s "$notes_file" ] || die "no CHANGELOG.md section found for $VERSION"

# --- Artifacts ----------------------------------------------------------------
artifacts=()
while IFS= read -r f; do artifacts+=("$f"); done < <(
  ls "$PUBLIC_DIST_DIR"/*.tar.gz "$PUBLIC_DIST_DIR"/checksums.txt "$PUBLIC_DIST_DIR"/metadata.json 2>/dev/null
)
[ "${#artifacts[@]}" -gt 0 ] || die "no artifacts in $PUBLIC_DIST_DIR/ — run 'make public-release' first"

# --- Git tag (create + push if missing) --------------------------------------
if git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
  info "git tag $VERSION already exists locally"
else
  info "creating annotated git tag $VERSION at $TAG_TARGET..."
  git tag -a "$VERSION" -m "Release $VERSION" "$TAG_TARGET"
fi

if git ls-remote --exit-code --tags origin "refs/tags/$VERSION" >/dev/null 2>&1; then
  info "git tag $VERSION already present on origin"
else
  info "pushing tag $VERSION to origin..."
  git push origin "refs/tags/$VERSION"
fi

# --- GitHub release (create or edit in place) --------------------------------
if gh release view "$VERSION" >/dev/null 2>&1; then
  info "release $VERSION exists — updating notes and re-uploading artifacts..."
  # --draft=false promotes a leftover draft to a published, tag-associated
  # release (a no-op when it is already published).
  gh release edit   "$VERSION" --title "$VERSION" --notes-file "$notes_file" --draft=false
  gh release upload "$VERSION" "${artifacts[@]}" --clobber
else
  info "creating GitHub release $VERSION..."
  gh release create "$VERSION" "${artifacts[@]}" --title "$VERSION" --notes-file "$notes_file"
fi

info "GitHub release $VERSION published (${#artifacts[@]} artifacts)."
