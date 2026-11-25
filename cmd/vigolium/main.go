package main

import (
	"github.com/vigolium/vigolium/internal/paths/earlyenv"
	"github.com/vigolium/vigolium/pkg/cli"
)

// main does nothing but hand off. It used to print the startup banner here,
// before cobra had parsed anything, by scanning os.Args for "--json"/"-j" and
// comparing os.Args[1] against a hand-written command list. That decided stdout
// framing from raw argv, so `--json=true`, an alias, or a global placed before
// the command all defeated it — and any command whose stdout is data but which
// was missing from the list (completion, js, storage download) got a mascot
// glued to the front of its output.
//
// The banner is presentation and now lives on stderr, emitted from the root
// PersistentPreRunE once the command and its flags are actually known. See
// pkg/cli/banner.go.
//
// earlyenv.Restore runs first: under VIGOLIUM_STATE_DIR the package's init
// pointed HOME at the state tree for the embedded libraries' init, and
// everything from here on sees the operator's real HOME again.
func main() {
	earlyenv.Restore()
	cli.Execute()
}
