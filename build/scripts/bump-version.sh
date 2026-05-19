#!/usr/bin/env bash
set -euo pipefail

# Bump the single source-of-truth version in pkg/cli/version.go.
#
# That `Version` constant drives everything downstream: goreleaser builds, the
# @vigolium/vigolium npm package + its per-platform sub-packages, and the
# install scripts. npm versions are immutable, so every release needs a new,
# unique number here before `make npm-publish`.
#
# Usage (normally via `make bump-version`):
#   bump-version.sh [part]
#
# Env / make vars:
#   PART    = patch (default) | minor | major | pre | release
#   LABEL   = override the prerelease label (e.g. LABEL=beta -> -beta)
#   SET     = set an explicit version (e.g. SET=v0.4.0-rc.1); skips computation
#   DRY_RUN = 1 to preview the change without writing the file
#
# Examples (current -> new):
#   v0.1.3-alpha   PART=patch    ->  v0.1.4-alpha   (default)
#   v0.1.3-alpha   PART=minor    ->  v0.2.0-alpha
#   v0.1.3-alpha   PART=major    ->  v1.0.0-alpha
#   v0.1.3-alpha   PART=pre      ->  v0.1.3-alpha.1
#   v0.1.3-alpha.1 PART=pre      ->  v0.1.3-alpha.2
#   v0.1.3-alpha   PART=release  ->  v0.1.3          (drop prerelease)
#   v0.1.3-alpha   LABEL=beta    ->  v0.1.4-beta     (default patch + relabel)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION_FILE="$ROOT/pkg/cli/version.go"

PART="${PART:-${1:-patch}}"
LABEL="${LABEL:-}"
SET="${SET:-}"
DRY_RUN="${DRY_RUN:-}"

die()  { printf '\033[31m[!] %s\033[0m\n' "$*" >&2; exit 1; }
info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }

[ -f "$VERSION_FILE" ] || die "version file not found: $VERSION_FILE"

current="$(grep -E '^[[:space:]]*Version[[:space:]]*=' "$VERSION_FILE" | head -1 | cut -d '"' -f 2)"
[ -n "$current" ] || die "could not parse Version from $VERSION_FILE"

# Optionally v-prefixed semver with an optional prerelease label.
semver_re='^v?([0-9]+)\.([0-9]+)\.([0-9]+)(-[0-9A-Za-z][0-9A-Za-z.-]*)?$'

if [ -n "$SET" ]; then
  new="$SET"
  [[ "$new" =~ $semver_re ]] || die "SET='$new' is not a valid (optionally v-prefixed) semver"
else
  [[ "$current" =~ $semver_re ]] || die "current version '$current' is not parseable semver"
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  patch="${BASH_REMATCH[3]}"
  label="${BASH_REMATCH[4]#-}"   # prerelease without the leading '-' ('' if none)

  case "$PART" in
    major)   major=$((major + 1)); minor=0; patch=0 ;;
    minor)   minor=$((minor + 1)); patch=0 ;;
    patch)   patch=$((patch + 1)) ;;
    release) label="" ;;          # promote to a stable (non-prerelease) version
    pre)
      [ -n "$label" ] || die "PART=pre needs an existing prerelease label; set one with LABEL=alpha"
      if [[ "$label" =~ ^(.*[^0-9.])\.?([0-9]+)$ ]]; then
        label="${BASH_REMATCH[1]}.$((BASH_REMATCH[2] + 1))"
      else
        label="${label}.1"
      fi
      ;;
    *) die "unknown PART='$PART' (use: patch|minor|major|pre|release)" ;;
  esac

  # LABEL overrides the prerelease label (ignored when PART=release clears it).
  if [ -n "$LABEL" ] && [ "$PART" != "release" ]; then
    label="$LABEL"
  fi

  new="v${major}.${minor}.${patch}"
  [ -n "$label" ] && new="${new}-${label}"
fi

# version.go keeps a leading 'v' — normalize so SET= without it still matches.
case "$new" in v*) ;; *) new="v$new" ;; esac
[[ "$new" =~ $semver_re ]] || die "computed version '$new' failed validation"
[ "$new" != "$current" ] || die "version unchanged ($current) — nothing to bump (PART=$PART)"

info "version: $current  ->  $new"

if [ "$DRY_RUN" = "1" ]; then
  info "DRY_RUN=1 — $VERSION_FILE left unchanged"
  exit 0
fi

# Rewrite only the `Version = "..."` line (perl -0pi matches the in-place
# substitutions used elsewhere in the Makefile). The new value is passed as
# ARGV[0] and shifted off in BEGIN so perl does not treat it as a file.
perl -0pi -e 'BEGIN{$n=shift @ARGV} s/^(\s*Version\s*=\s*)"[^"]*"/$1"$n"/m' "$new" "$VERSION_FILE"

after="$(grep -E '^[[:space:]]*Version[[:space:]]*=' "$VERSION_FILE" | head -1 | cut -d '"' -f 2)"
[ "$after" = "$new" ] || die "rewrite failed (file still shows '$after')"

info "updated $VERSION_FILE"
info "next: review the diff & commit, then 'make npm-publish' (auto-rebuilds binaries for $new)"
