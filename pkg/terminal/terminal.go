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

// AgentNotice prints a prefixed console line to stderr like Notice but with the
// join / relation glyph (⋈). Used for autonomous engine decisions
// (e.g. discovery confirming an extension and queuing it for fuzzing).
func AgentNotice(prefix, message string) {
	fmt.Fprintf(os.Stderr, "  %s %s %s\n",
		Purple(SymbolBowtie), BoldCyan("["+prefix+"]"), message)
}

// Global state for terminal capabilities
var (
	colorEnabled     = true
	ciMode           = false
	stdoutIsTerminal = false
)

func init() {
	stdoutIsTerminal = term.IsTerminal(int(os.Stdout.Fd()))
	// Auto-detect terminal capabilities and NO_COLOR environment variable
	// https://no-color.org/
	if !stdoutIsTerminal || os.Getenv("NO_COLOR") != "" {
		colorEnabled = false
	}
}

// IsTerminal reports whether stdout is an interactive terminal (TTY). It is
// false when stdout is redirected to a file or pipe — including the per-target
// .console.log capture used by `-P` parallel scans. Width-based truncation of
// live console lines keys off this so file/pipe output stays full-length and
// greppable instead of being clipped to the 150-column TerminalWidth fallback.
func IsTerminal() bool {
	return stdoutIsTerminal
}

// SetIsTerminal overrides the detected TTY state. Intended for tests and any
// caller that needs to force truncation behavior explicitly.
func SetIsTerminal(enabled bool) {
	stdoutIsTerminal = enabled
}

// TerminalWidth returns the current terminal width in columns.
// Falls back to 150 if detection fails (e.g. not a TTY, piped output).
func TerminalWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 {
		return 150
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

// EnableCLIColor turns color on for interactive CLI use, overriding the non-TTY
// auto-disable from init() so redirected or piped output — e.g. the -P/--parallel
// fan-out's per-host <output>.console.log — stays colored and reads like a live
// console scan. The explicit opt-outs win: the --no-color flag, CI output mode,
// and the NO_COLOR env var (https://no-color.org/) all force color off. NO_COLOR
// is re-checked here (not just in init()) because this unconditionally resets the
// color state, so it must re-apply that opt-out rather than assume init() stuck.
func EnableCLIColor(noColor, ciOutput bool) {
	SetColorEnabled(!(noColor || ciOutput || os.Getenv("NO_COLOR") != ""))
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
