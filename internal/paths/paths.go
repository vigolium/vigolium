// Package paths holds the process-wide "stateless home" switch.
//
// `-S/--stateless` on a scan-driving command promises that the run leaves no
// config or state in $HOME: it may READ caches (an already-extracted browser or
// jstangle, installed nuclei templates), but every file it would otherwise write
// under ~/.vigolium (bootstrap config, profiles, database, init marker,
// update-check cache, native-sessions liveness, materialized wordlists) goes to
// a per-process scratch directory instead, and a download that would land in
// HOME (template clone, Chrome for Testing) fails closed with a clear error.
//
// The CLI enables it in PersistentPreRunE; packages that write state consult
// Stateless/StateDir. The embedded nuclei/uncover libraries create their
// config directories at package init, before any flag is parsed; only
// VIGOLIUM_STATE_DIR moves them (state_dir.go, earlyenv).
package paths

import (
	"os"
	"path/filepath"
	"sync/atomic"
)

var statelessRoot atomic.Pointer[string]

// EnableStateless switches the process to the stateless home rooted at root
// (a scratch directory the caller owns). An empty root disables it.
func EnableStateless(root string) {
	if root == "" {
		statelessRoot.Store(nil)
		return
	}
	statelessRoot.Store(&root)
}

// Stateless reports whether the stateless home is on.
func Stateless() bool { return statelessRoot.Load() != nil }

// Root returns the stateless scratch root ("" when off).
func Root() string {
	if p := statelessRoot.Load(); p != nil {
		return *p
	}
	return ""
}

// StateDir returns def normally, and <root>/<name> under the stateless home.
func StateDir(name, def string) string {
	if root := Root(); root != "" {
		return filepath.Join(root, name)
	}
	return def
}

// Writable reports whether dir exists (or can be created) and accepts a file.
// Used to decide whether a cache under HOME can be used in stateless mode.
func Writable(dir string) bool {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false
	}
	f, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}
