package cli

import (
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

// globalReadOnly backs the persistent --read-only flag.
var globalReadOnly bool

// Opening a database was always a write. openSQLite creates the parent
// directory, sets the journal_mode PRAGMA (which rewrites the file header) and
// runs an unconditional wal_checkpoint(TRUNCATE) — so a plain
// `traffic -S --db evidence.sqlite -j` changed that file's SHA-256, flipped it
// from `delete` to `wal`, and dropped -shm/-wal siblings beside it. A file marked
// `chmod 444` could not be read at all.
//
// That is fine for the working project database, which vigolium owns. It is not
// fine for a `.sqlite` handed over as evidence, a per-run export being read after
// the fact, or anything under chain of custody, where the artifact must survive
// the read byte-identical.
//
// --read-only is a separate axis from -S/--stateless, which is a *scoping* mode
// ("ignore project boundaries in this file") and never implied immutability
// despite reading like it might.

// The commands that accept --read-only are the ones commandTraits marks
// ReadOnly, by exact cobra path: "finding load" imports findings INTO the
// database, the one thing this flag exists to prevent, so a group's row never
// covers its subcommands.

// registerReadOnlyFlag adds the persistent --read-only flag to the root command.
func registerReadOnlyFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(&globalReadOnly, "read-only", false,
		"Open the database without modifying it (no directory creation, no journal-mode change, no WAL checkpoint). Read commands only; use it when the source file is evidence")
}

// applyReadOnlyMode validates --read-only against the running command and, when
// accepted, arms the shared opener before any database is opened.
//
// It also arms the opener with the command's declared database intent
// (resolveDBIntent): both decide how the one shared connection is opened, and
// both must be settled before anything opens it.
func applyReadOnlyMode(cmd *cobra.Command) error {
	applyDBIntent(cmd)
	if !globalReadOnly {
		return nil
	}
	if t, _ := traitOf(cmd); !t.ReadOnly {
		return usageErrorf(
			"--read-only is not supported on %q: it is a read-command guarantee, and this command writes.\n\nsupported: %s",
			commandPathWithoutRoot(cmd), strings.Join(readOnlyCapableCommands(), ", "))
	}
	// A command is not a reader or a writer — an INVOCATION is. These flags turn
	// an admitted read command into one that writes, and would otherwise be
	// accepted here only to fail (or half-succeed) against the read-only handle.
	//
	// flagOn, not Changed: `--save-to-vigolium-db=false` writes nothing, so
	// rejecting it was a conflict that did not exist — and the operator who spells
	// out the safe value is exactly the one least deserving of a usage error.
	for _, w := range dbWriteFlags {
		if flagOn(cmd, w) {
			return usageErrorf("--read-only cannot be combined with --%s: that flag writes to the database", w)
		}
	}
	clicommon.Policy.ReadOnly = true
	return nil
}

// commandPathWithoutRoot renders "vigolium db ls" as "db ls".
func commandPathWithoutRoot(cmd *cobra.Command) string {
	if cmd == nil {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(cmd.CommandPath(), cmd.Root().Name()))
}

// readOnlyCapableCommands lists the commands that accept --read-only, sorted.
func readOnlyCapableCommands() []string {
	var out []string
	for path, t := range commandTraits {
		if t.ReadOnly {
			out = append(out, path)
		}
	}
	slices.Sort(out)
	return out
}
