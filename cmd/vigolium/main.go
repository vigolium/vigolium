package main

import (
	"fmt"
	"os"

	"github.com/vigolium/vigolium/pkg/cli"
)

func main() {
	if !hasFlag("--json", "-j") && (len(os.Args) < 2 || os.Args[1] != "version") && !isSubcommand("config") && !isSubcommand("agent") && !isSubcommand("traffic") && !isSubcommand("finding") && !isSubcommand("findings") && !isSubcommand("db") {
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

// isSubcommand returns true if the first argument matches the given command name.
func isSubcommand(name string) bool {
	return len(os.Args) >= 2 && os.Args[1] == name
}
