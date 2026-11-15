package cli

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
)

// TestDBIntentCoverage: every runnable command declares what it does with the
// store. An undeclared command would silently open the read-write store (the
// safe default) — but a new read command left undeclared would also silently
// take the write lock on every open, which is the bug intents exist to fix, so
// the declaration is required rather than defaulted.
func TestDBIntentCoverage(t *testing.T) {
	prepareCommandTree(rootCmd)

	seen := map[string]bool{}
	walkTree(rootCmd, func(c *cobra.Command) {
		path := commandPathWithoutRoot(c)
		seen[path] = true
		if !c.Runnable() {
			return
		}
		tr, ok := commandTraits[path]
		if !ok {
			t.Errorf("command %q is not in commandTraits (command_traits.go): add it with DB dbRead, dbWrite or dbNone", path)
			return
		}
		if tr.DB == dbUndeclared {
			t.Errorf("command %q declares no DB intent; want dbRead, dbWrite or dbNone", path)
		}
	})

	for path := range commandTraits {
		if seen[path] || path == "help" || strings.HasPrefix(path, "completion") {
			continue // cobra adds help/completion at Execute time
		}
		t.Errorf("commandTraits names %q, which is not a command: remove the stale entry", path)
	}
}

// TestReadOnlyCommandsOpenTheReadPool: a ReadOnly command never writes, so it
// opens the read pool — except a network command, which records what it sends.
func TestReadOnlyCommandsOpenTheReadPool(t *testing.T) {
	for path, tr := range commandTraits {
		if tr.ReadOnly && tr.DB != dbRead && !tr.SendsTraffic {
			t.Errorf("%q accepts --read-only but declares DB %s", path, tr.DB)
		}
	}
}

// TestResolveDBIntent_WriteFlagsFlip: an invocation, not a command, is a reader
// or a writer. --save-to-vigolium-db turns a traffic read into a write.
func TestResolveDBIntent_WriteFlagsFlip(t *testing.T) {
	prepareCommandTree(rootCmd)

	traffic, _, err := rootCmd.Find([]string{"traffic"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = traffic.Flags().Set("save-to-vigolium-db", "false") })

	if got := resolveDBIntent(traffic); got != clicommon.IntentRead {
		t.Fatalf("traffic intent = %v, want read", got)
	}
	if err := traffic.Flags().Set("save-to-vigolium-db", "true"); err != nil {
		t.Fatal(err)
	}
	if got := resolveDBIntent(traffic); got != clicommon.IntentWrite {
		t.Fatalf("traffic --save-to-vigolium-db intent = %v, want write", got)
	}

	// "none" and undeclared commands open as write, the legacy behaviour.
	version, _, _ := rootCmd.Find([]string{"version"})
	if got := resolveDBIntent(version); got != clicommon.IntentWrite {
		t.Errorf("version intent = %v, want write (none → legacy default)", got)
	}
	if !slices.Contains(dbWriteFlags, "in-replace") {
		t.Error("dbWriteFlags lost in-replace")
	}
}

// The database layer's own conditions reach error.code through Code(), and the
// evidence-mode sentinel through errors.Is.
func TestClassifyDatabaseCodedErrors(t *testing.T) {
	cases := map[apicontract.ErrorCode]error{
		apicontract.CodeDatabaseLocked: fmt.Errorf("list: %w", &database.LockedError{Attempts: 3, Err: errors.New("database is locked")}),
		apicontract.CodeSchemaTooNew:   &database.SchemaTooNewError{DBVersion: 9, Binary: 2, Write: true},
		apicontract.CodeSchemaOutdated: fmt.Errorf("%w and --read-only cannot migrate it", database.ErrSchemaOutdated),
	}
	for want, err := range cases {
		if got := classifyErrorCode(err, classifyExitCode(err)); got != want {
			t.Errorf("classifyErrorCode(%v) = %q, want %q", err, got, want)
		}
	}
}
