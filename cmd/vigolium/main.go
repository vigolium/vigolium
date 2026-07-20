package main

import (
	"fmt"
	"os"

	"github.com/vigolium/vigolium/pkg/cli"
)

func main() {
	// The startup banner goes to stdout, so suppress it whenever stdout is data
	// the caller consumes: --json/-j output, --silent runs ("all output except
	// findings"), and the read/scan commands that stream results to stdout. The
	// scanning commands (scan/run and the lightweight scan-url/scan-request) print
	// their own config summary to stderr instead, keeping stdout clean for
	// --print-finding's Markdown and file/JSON output.
	if !hasFlag("--json", "-j") && !hasFlag("--silent") && !isSubcommand(
		"version", "config", "agent", "traffic", "finding", "findings", "db",
		"export", "scan", "scan-url", "scan-request", "run", "r", "replay",
		"fuzz", "import", "log", "olium", "ol", "skills", "skill",
	) {
		fmt.Print(cli.GetBanner())
	}
	cli.Execute()
}

// hasFlag returns true if any of the given flags appear in os.Args.
func hasFlag(flags ...string) bool {
	for _, arg := range os.Args[1:] {
		for _, f := range flags {
			if arg == f {
				return true
			}
		}
	}
	return false
}

// isSubcommand returns true if the first argument matches any of the given
// command names.
func isSubcommand(names ...string) bool {
	if len(os.Args) < 2 {
		return false
	}
	for _, name := range names {
		if os.Args[1] == name {
			return true
		}
	}
	return false
}
