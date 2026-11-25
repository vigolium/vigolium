// Package earlyenv points the embedded libraries' config directories at
// VIGOLIUM_STATE_DIR before their package init runs.
//
// The nuclei library (pkg/catalog/config) and uncover (sources) create their
// config directories and write a default file from package init, under
// os.UserConfigDir(); golang.org/x/tools (pulled in by nuclei) creates its
// goimports cache under os.UserCacheDir(). That happens before main, so no flag
// and no later code can move it. This package's init runs first: it imports
// only the standard library and internal/paths, and Go initializes a package
// whose imports are done in import-path order, so it lands ahead of those
// libraries, whose own dependency trees are not yet initialized
// (TestStateDirKeepsHomeEmpty in test/e2e-expect pins the outcome).
//
// With VIGOLIUM_STATE_DIR set it sets NUCLEI_CONFIG_DIR for the life of the
// process, and for the init window only it points HOME, XDG_CONFIG_HOME and
// XDG_CACHE_HOME at $VIGOLIUM_STATE_DIR/lib/home (os.UserConfigDir reads HOME on
// macOS and XDG_CONFIG_HOME on Linux). main calls Restore first thing, so the
// operator's real HOME is what vigolium itself and its child processes see.
//
// Only cmd/vigolium imports it: a test binary or another tool importing
// internal/paths gets no environment changes.
package earlyenv

import (
	"os"

	"github.com/vigolium/vigolium/internal/paths"
)

// nucleiConfigDirEnv is the nuclei library's own override of its config dir
// (config.NucleiConfigDirEnv), named here to keep this package free of the
// library it has to run ahead of.
const nucleiConfigDirEnv = "NUCLEI_CONFIG_DIR"

// initWindowVars are the variables swapped for the init window.
var initWindowVars = []string{"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"}

// saved holds each swapped variable's value before init (nil: unset).
var saved map[string]*string

func init() {
	if !paths.StateDirSet() {
		return
	}
	_ = os.Setenv(nucleiConfigDirEnv, paths.LibDir("nuclei"))
	home := paths.LibDir("home")
	saved = make(map[string]*string, len(initWindowVars))
	for _, name := range initWindowVars {
		if v, ok := os.LookupEnv(name); ok {
			saved[name] = &v
		} else {
			saved[name] = nil
		}
	}
	_ = os.Setenv("HOME", home)
	_ = os.Setenv("XDG_CONFIG_HOME", home+"/.config")
	_ = os.Setenv("XDG_CACHE_HOME", home+"/.cache")
}

// Restore puts back the variables init swapped. Call it first thing in main;
// it is a no-op when VIGOLIUM_STATE_DIR was unset or on a second call.
func Restore() {
	for name, v := range saved {
		if v == nil {
			_ = os.Unsetenv(name)
		} else {
			_ = os.Setenv(name, *v)
		}
	}
	saved = nil
}
