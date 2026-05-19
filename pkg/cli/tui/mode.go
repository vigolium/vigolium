package tui

import (
	"fmt"
	"os"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

// AddFlags registers the standard --tui and --no-tui flags on a command.
// Both flags default to false. Pass pointers to command-local bool vars.
func AddFlags(cmd *cobra.Command, tui, noTUI *bool) {
	cmd.Flags().BoolVar(tui, "tui", false, "Open interactive TUI (arrow keys to navigate, enter to view details, c to copy id)")
	cmd.Flags().BoolVar(noTUI, "no-tui", false, "Force TUI off (escape hatch if TUI ever becomes default)")
}

// Active returns true when a TUI should be launched given the flag state.
// Rules:
//   - jsonOutput=true → false (JSON always wins)
//   - noTUI=true → false
//   - tui=true → true (but returns an error if stdout is not a TTY)
//   - otherwise → false (default off; user must opt in)
func Active(forceTUI, noTUI, jsonOutput bool) (bool, error) {
	if jsonOutput || noTUI {
		return false, nil
	}
	if !forceTUI {
		return false, nil
	}
	if !isatty.IsTerminal(os.Stdout.Fd()) && !isatty.IsTerminal(os.Stderr.Fd()) {
		return false, fmt.Errorf("--tui requires a terminal, but neither stdout nor stderr is a TTY")
	}
	return true, nil
}
