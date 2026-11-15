package cli

import (
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
)

// dbWriteFlags turn an invocation of a read command into one that writes. A
// command is not a reader or a writer — an invocation is. Shared with
// applyReadOnlyMode, which refuses them under --read-only for the same reason
// they flip intent here.
var dbWriteFlags = []string{"save-to-vigolium-db", "in-replace", "reap"}

// resolveDBIntent is the intent this invocation opens the store with: the
// declared one, flipped to write by a dbWriteFlags flag, and write for
// anything undeclared or dbNone.
func resolveDBIntent(cmd *cobra.Command) clicommon.OpenIntent {
	t, _ := traitOf(cmd)
	intent := t.DB.openIntent()
	if intent == clicommon.IntentRead {
		for _, f := range dbWriteFlags {
			if flagOn(cmd, f) {
				return clicommon.IntentWrite
			}
		}
	}
	return intent
}

// applyDBIntent arms the shared opener with the running command's intent.
// Called before anything can open a database.
func applyDBIntent(cmd *cobra.Command) {
	clicommon.Policy.Intent = resolveDBIntent(cmd)
}

// getDBFor opens (or reuses) the shared connection for an explicit intent,
// overriding the command's declared one — for a code path that knows it will
// write regardless of which command reached it.
func getDBFor(intent clicommon.OpenIntent) (*database.DB, error) {
	return clicommon.GetDBFor(intent, globalConfig, globalDB)
}
