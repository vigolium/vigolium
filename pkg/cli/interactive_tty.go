package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// ttyProbe reports whether an interactive terminal is available: /dev/tty
// opens and stdout is a terminal. A variable so tests can stand in for a
// headless run.
var ttyProbe = func() bool {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return terminal.IsTerminal()
}

// requireInteractiveTTY refuses to start a terminal UI where there is no
// terminal, as a usage error naming the non-interactive form (alt), instead
// of the UI library's raw "could not open a new TTY" failure. Under -j the
// terminal is never the caller's, so it is refused there too.
func requireInteractiveTTY(what, alt string) error {
	if !globalJSON && ttyProbe() {
		return nil
	}
	return clicommon.CLIError{
		Err:  fmt.Errorf("%s needs an interactive terminal, and this process has none", what),
		Hint: "run it non-interactively: " + alt,
	}
}

// readNonEmptyStdin reads the prompt piped on stdin, refusing an empty one
// (whitespace only) as a usage error: an empty prompt would still be sent to
// the provider.
func readNonEmptyStdin(flag string) (string, error) {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return "", usageErrorf("%s: stdin was empty; pipe a prompt in, or pass it with -p", flag)
	}
	return text, nil
}
