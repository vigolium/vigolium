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
	applyDBIntentAnnotations(rootCmd)

	seen := map[string]bool{}
	walkCommandTree(rootCmd, func(c *cobra.Command) {
		path := commandPathWithoutRoot(c)
		seen[path] = true
		if !c.Runnable() {
			return
		}
		v, ok := c.Annotations[dbIntentAnnotation]
		if !ok {
			t.Errorf("command %q has no %s annotation: add it to commandTraits (command_traits.go) with DB read, write or none",
				path, dbIntentAnnotation)
			return
		}
		if _, valid := clicommon.ParseOpenIntent(v); !valid && v != dbIntentNone {
			t.Errorf("command %q declares db intent %q; want read, write or none", path, v)
		}
	})

	for path := range dbIntents {
		if seen[path] || path == "help" || strings.HasPrefix(path, "completion") {
			continue // cobra adds help/completion at Execute time
		}
		t.Errorf("dbIntents names %q, which is not a command: remove the stale entry", path)
	}
}

// TestDBIntentReadCommandsAgreeWithReadOnlyList: the read-only-capable commands
// are, by their own contract, the ones that never write — so each must open the
// read pool, except the two network commands that declare write on purpose.
func TestDBIntentReadCommandsAgreeWithReadOnlyList(t *testing.T) {
	for _, path := range readOnlyCapableCommands {
		want := "read"
		if path == "replay" || path == "fuzz" {
			want = "write"
		}
		if got := dbIntents[path]; got != want {
			t.Errorf("dbIntents[%q] = %q, want %q", path, got, want)
		}
	}
}

// TestResolveDBIntent_WriteFlagsFlip: an invocation, not a command, is a reader
// or a writer. --save-to-vigolium-db turns a traffic read into a write.
func TestResolveDBIntent_WriteFlagsFlip(t *testing.T) {
	prepareCommandTree(rootCmd)
	applyDBIntentAnnotations(rootCmd)

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
