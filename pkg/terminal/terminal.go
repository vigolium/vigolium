package terminal

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// Notice prints a normal, prefixed console line to stderr (not a structured
// log). Format: "  ◆ [prefix] message". Color honors NO_COLOR / CI detection
// via the shared color helpers.
func Notice(prefix, message string) {
	fmt.Fprintf(os.Stderr, "  %s %s %s\n",
		Purple(SymbolInfo), BoldCyan("["+prefix+"]"), message)
}

// Global state for terminal capabilities
var (
	colorEnabled = true
	ciMode       = false
)

func init() {
	// Auto-detect terminal capabilities and NO_COLOR environment variable
	// https://no-color.org/
	if !term.IsTerminal(int(os.Stdout.Fd())) || os.Getenv("NO_COLOR") != "" {
		colorEnabled = false
	}
}

// TerminalWidth returns the current terminal width in columns.
// Falls back to 120 if detection fails (e.g. not a TTY, piped output).
func TerminalWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 {
		return 120
	}
	return w
}

// IsColorEnabled returns whether color output is enabled
func IsColorEnabled() bool {
	return colorEnabled
}

// SetColorEnabled enables or disables color output
func SetColorEnabled(enabled bool) {
	colorEnabled = enabled
}

// SetCIMode enables CI mode (suppresses decorative output)
func SetCIMode(enabled bool) {
	ciMode = enabled
}

// IsCIMode returns whether CI mode is enabled
func IsCIMode() bool {
	return ciMode
}

// ShortenHome replaces the user's home directory prefix with "~" in a path.
func ShortenHome(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	if strings.HasPrefix(path, home) {
		return "~" + path[len(home):]
	}
	return path
}

// Truncate truncates a string to maxWidth characters, appending "…" if truncated.
func Truncate(s string, maxWidth int) string {
	if len(s) <= maxWidth {
		return s
	}
	if maxWidth <= 1 {
		return "…"
	}
	return s[:maxWidth-1] + "…"
}
