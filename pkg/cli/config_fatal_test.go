package cli

import (
	"strings"
	"testing"
)

// TestDiscoveredConfigFatal_ExemptsRepairCommands: a broken
// discovered config stops every command except the ones used to repair it.
func TestDiscoveredConfigFatal_ExemptsRepairCommands(t *testing.T) {
	for path, want := range map[string]bool{
		"scan":            true,
		"config set":      true,
		"traffic":         true,
		"doctor":          false,
		"config validate": false,
		"config clean":    false,
		"config ls":       false,
		"version":         false,
	} {
		cmd, _, err := rootCmd.Find(strings.Fields(path))
		if err != nil || cmd == rootCmd {
			t.Fatalf("%q: no such command (%v)", path, err)
		}
		if got := discoveredConfigFatal(cmd); got != want {
			t.Errorf("discoveredConfigFatal(%q) = %v, want %v", path, got, want)
		}
	}
}
