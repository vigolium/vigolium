package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
)

// stdinIsPiped returns true if stdin is a pipe (not a terminal).
func stdinIsPiped() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}

// readStdinIfPiped reads all data from stdin if it's a pipe.
// Returns the data and true if stdin was piped, or empty string and false otherwise.
func readStdinIfPiped() (string, bool) {
	if !stdinIsPiped() {
		return "", false
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil || len(data) == 0 {
		return "", false
	}
	return strings.TrimRight(string(data), "\n\r"), true
}

// resolveTargetFromInput normalizes a raw input string (curl, raw HTTP, Burp XML, URL)
// and extracts the target URL. Used by autopilot and pipeline commands to derive --target
// from --input or piped stdin.
func resolveTargetFromInput(ctx context.Context, input string, repo *database.Repository) (string, error) {
	targetURL, err := agent.TargetURLFromInput(ctx, input, "", repo)
	if err != nil {
		return "", fmt.Errorf("failed to extract target URL from input: %w", err)
	}
	return targetURL, nil
}
