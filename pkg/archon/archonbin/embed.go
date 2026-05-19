// Package archonbin embeds the archon-audit host binary into vigolium and
// extracts it to a per-user cache directory on first use.
//
// The binary is built from platform/archon-audit/ by `make update-archon`,
// which
// runs `bun run build` and copies the host-platform output to _bin/archon.
// Cross-compiling vigolium requires staging the matching archon-<os>-<arch>
// blob at _bin/archon before `go build`.
package archonbin

import (
	"embed"
)

// binFS holds whatever lives under _bin at compile time. `all:` lets the
// embed directive match an empty _bin (only the tracked .gitkeep) on
// fresh clones — missing-binary surfaces as a runtime extract error
// rather than a build failure.
//
//go:embed all:_bin
var binFS embed.FS

const embeddedName = "_bin/archon"
