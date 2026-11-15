package cli

import (
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
)

// dbIntentAnnotation carries a command's declared database intent on its cobra
// node: "read", "write" or "none". Stamped from commandTraits by prepareCommandTree.
const dbIntentAnnotation = "vigolium.io/db-intent"

// dbIntentNone marks a command that has no reason to open the store. If one
// does anyway (a --project-name lookup, say) it gets write intent, which is
// what every opener did before intents existed — so "none" can never make an
// open stricter than it was.
const dbIntentNone = "none"

// dbWriteFlags turn an invocation of a read command into one that writes. A
// command is not a reader or a writer — an invocation is. Shared with
// applyReadOnlyMode, which refuses them under --read-only for the same reason
// they flip intent here.
var dbWriteFlags = []string{"save-to-vigolium-db", "in-replace", "reap"}

// applyDBIntentAnnotations stamps every command's declared intent from
// dbIntents. Called from prepareCommandTree, once the tree is complete.
func applyDBIntentAnnotations(root *cobra.Command) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if v, ok := dbIntents[commandPathWithoutRoot(c)]; ok {
			if c.Annotations == nil {
				c.Annotations = map[string]string{}
			}
			c.Annotations[dbIntentAnnotation] = v
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}

// declaredDBIntent returns cmd's declared intent: the annotation when the tree
// was prepared, the central table otherwise, "" when undeclared.
func declaredDBIntent(cmd *cobra.Command) string {
	if cmd == nil {
		return ""
	}
	if v, ok := cmd.Annotations[dbIntentAnnotation]; ok {
		return v
	}
	return dbIntents[commandPathWithoutRoot(cmd)]
}

// resolveDBIntent is the intent this invocation opens the store with: the
// declared one, flipped to write by a dbWriteFlags flag, and write for
// anything undeclared or "none".
func resolveDBIntent(cmd *cobra.Command) clicommon.OpenIntent {
	intent, ok := clicommon.ParseOpenIntent(declaredDBIntent(cmd))
	if !ok {
		return clicommon.IntentWrite
	}
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
