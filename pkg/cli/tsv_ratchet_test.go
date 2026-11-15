package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// tsvReadCommands render --format tsv. Every command that registers
// --no-header is listed, and every listed command rejects a format it cannot
// render instead of printing its table.
var tsvReadCommands = []string{
	"db list", "db stats", "dns", "endpoints", "finding", "hosts", "log ls",
	"match-not-found", "params", "scan diff", "scan ls", "traffic",
}

func TestTSVReadCommandsRatchet(t *testing.T) {
	var got []string
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Flags().Lookup("no-header") != nil {
			got = append(got, strings.TrimPrefix(c.CommandPath(), rootCmd.Name()+" "))
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
	slices.Sort(got)
	require.Equal(t, tsvReadCommands, got, "a read command with --no-header must be listed here, and every listed one must register it")
}

func TestTSVReadCommandsRejectOtherFormats(t *testing.T) {
	e := newB5Env(t)
	code, _, stderr := e.run(t, nil, "db", "seed", "-j")
	require.Equal(t, 0, code, stderr)
	for _, name := range []string{"db list", "db stats", "log ls", "scan diff"} {
		args := append(strings.Fields(name), "--format", "html")
		code, _, stderr := e.run(t, nil, args...)
		require.Equal(t, 2, code, "%s --format html: %s", name, stderr)
	}
	code, stdout, stderr := e.run(t, nil, "db", "stats", "--format", "tsv")
	require.Equal(t, 0, code, stderr)
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	require.Len(t, lines, 2, "a header and the one stats row: %s", stdout)
	require.Contains(t, lines[0], "\tfindings.total\t", "nested objects flatten to dotted columns")
	code, stdout, stderr = e.run(t, nil, "log", "ls", "--format", "tsv", "--no-header")
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, "\tscan-0001-aaaa-bbbb-cccc-ddddeeee0001\t")
	code, stdout, stderr = e.run(t, nil, "db", "ls", "--format", "tsv", "--fields", "uuid")
	require.Equal(t, 0, code, stderr)
	require.True(t, strings.HasPrefix(stdout, "uuid\n"), stdout)
}

// Reading a JSONL export without -S names the file and the -S remedy rather
// than the driver's "file is not a database".
func TestReadingJSONLWithoutStatelessHintsS(t *testing.T) {
	e := newB5Env(t)
	src := writeImportJSONL(t, e.home)
	code, stdout, stderr := e.run(t, nil, "--db", src, "traffic", "-j")
	require.Equal(t, 1, code, stderr)
	require.Contains(t, stdout, "source_unreadable")
	require.Contains(t, stdout, "-S --db")
}

func TestDBResetDryRunAndStatsScope(t *testing.T) {
	e := newB5Env(t)
	code, _, stderr := e.run(t, nil, "db", "seed", "-j")
	require.Equal(t, 0, code, stderr)

	code, stdout, stderr := e.run(t, nil, "db", "reset", "--dry-run", "-j")
	require.Equal(t, 0, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	require.Equal(t, false, doc["changed"])
	item := doc["items"].([]any)[0].(map[string]any)
	require.Equal(t, true, item["dry_run"])
	require.Contains(t, item["files"], e.db)
	require.FileExists(t, e.db, "a dry run deletes nothing")

	code, stdout, stderr = e.run(t, nil, "db", "stats", "-j")
	require.Equal(t, 0, code, stderr)
	require.Contains(t, oneDoc(t, stdout, stderr), "project_uuid", "db stats reports the project it counted")
}
