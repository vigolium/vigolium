package cli

import (
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
)

// A read command pointed at a database path that does not exist used to CREATE
// it and then report success against the empty store it had just made:
//
//	$ vigolium traffic --db ./typo.sqlite -j
//	{"total": 0, "items": [], "db_path": "./typo.sqlite", …}     # exit 0
//	$ ls -la typo.sqlite  →  344064 bytes, created by that read
//
// For anything driving vigolium — an agent, a script, a CI step — "the path is
// wrong" and "nothing was captured here" are then the same answer, and the wrong
// one is the one that looks like a finished task. It also leaves a stray
// 300-plus-KB file next to whatever the caller meant to read.
//
// Both halves are fixed by refusing: an explicitly pinned source that is not
// there is a typo, and a typo deserves apicontract.CodeSourceMissing (exit 1), which -S
// and --read-only have always returned for the same input. The guarantee already
// existed; it just was not the default.
//
// Only an EXPLICIT pin is covered — --db, or $VIGOLIUM_DB_PATH which
// applyDBPathEnv folds into the same global. The built-in default database is
// still created on first use, because a fresh install's first `vigolium traffic`
// legitimately has nothing to read yet and erroring there would be a regression
// with no upside.

// applySourceMustExist arms the shared opener when the running command is a pure
// read against an explicitly pinned source. Called from the root
// PersistentPreRunE after applyDBPathEnv, so $VIGOLIUM_DB_PATH has already been
// folded into globalDB and both pins are covered by the one check.
func applySourceMustExist(cmd *cobra.Command) {
	if globalDB == "" {
		return
	}
	// The read-only-capable pure reads. replay and fuzz accept --read-only too,
	// but they record what they send, so a fresh store is a legitimate outcome
	// for them (they declare DB write).
	if t, _ := traitOf(cmd); !t.ReadOnly || t.DB != dbRead {
		return
	}
	// database.ExpandPath, not config.ExpandPath: the guard must resolve the path
	// the same way the opener will. The two differ — config's form also expands
	// ${VAR:-default} — so using the wrong one would stat one file and create
	// another, which is the precise outcome this check exists to prevent.
	clicommon.Policy.MustExist = database.ExpandPath(globalDB)
}
