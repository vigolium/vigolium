package cli

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/terminal"
)

func TestHighlightTipCommands(t *testing.T) {
	const tip = "install with `sudo apt install chromium` (or run `vigolium doctor --fix --only chrome` to download Chrome for Testing)"

	t.Run("color disabled keeps backticks unchanged", func(t *testing.T) {
		restore := terminal.IsColorEnabled()
		terminal.SetColorEnabled(false)
		defer terminal.SetColorEnabled(restore)

		if got := highlightTipCommands(tip); got != tip {
			t.Fatalf("expected tip unchanged when color disabled\n got: %q\nwant: %q", got, tip)
		}
	})

	t.Run("color enabled wraps commands in bold cyan", func(t *testing.T) {
		restore := terminal.IsColorEnabled()
		terminal.SetColorEnabled(true)
		defer terminal.SetColorEnabled(restore)

		got := highlightTipCommands(tip)

		// Both backtick-wrapped commands must be emitted in bold cyan.
		for _, cmd := range []string{"sudo apt install chromium", "vigolium doctor --fix --only chrome"} {
			if !strings.Contains(got, terminal.BoldCyan(cmd)) {
				t.Errorf("expected bold-cyan %q in output, got %q", cmd, got)
			}
		}
		// Backticks are dropped once the command is colorized.
		if strings.Contains(terminal.StripANSI(got), "`") {
			t.Errorf("expected backticks removed in colored output, got %q", terminal.StripANSI(got))
		}
		// Surrounding prose survives intact (sans backticks).
		plain := terminal.StripANSI(got)
		if !strings.Contains(plain, "install with ") || !strings.Contains(plain, " to download Chrome for Testing)") {
			t.Errorf("surrounding prose lost: %q", plain)
		}
	})
}
