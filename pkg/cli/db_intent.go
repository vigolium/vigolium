package cli

import (
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
)

// dbIntentAnnotation carries a command's declared database intent on its cobra
// node: "read", "write" or "none". Stamped from dbIntents by prepareCommandTree.
const dbIntentAnnotation = "vigolium.io/db-intent"

// dbIntentNone marks a command that has no reason to open the store. If one
// does anyway (a --project-name lookup, say) it gets write intent, which is
// what every opener did before intents existed — so "none" can never make an
// open stricter than it was.
const dbIntentNone = "none"

// dbIntents declares, for every runnable command, what it does with the store.
// Keyed by cobra path without the root name; "" is the root itself.
//
// "read" opens the read pool (query_only, no journal-mode change, no
// checkpointing), so the command never waits on a scan writing the same file.
// Only commands that provably never write belong there: a write through the
// read pool fails loudly ("attempt to write a readonly database"), which is the
// right failure for a mis-declared command but still a failure. When in doubt,
// "write" — it is the behaviour every command had before.
//
// One table, like machineKinds, so an added command that nobody classified
// fails db_intent_test.go instead of silently inheriting a default.
var dbIntents = map[string]string{
	// Help-only groups, cobra's own commands, passthrough shims (they re-enter
	// the tree as the translated command, which declares its own intent).
	"":                      dbIntentNone,
	"help":                  dbIntentNone,
	"completion bash":       dbIntentNone,
	"completion fish":       dbIntentNone,
	"completion powershell": dbIntentNone,
	"completion zsh":        dbIntentNone,
	"kit":                   dbIntentNone,
	"kit oast":              dbIntentNone,
	"auth":                  dbIntentNone,
	"completion":            dbIntentNone,
	"config":                dbIntentNone,
	"db":                    dbIntentNone,
	"project":               dbIntentNone,
	"server ca":             dbIntentNone,
	"storage":               dbIntentNone,
	"oast":                  dbIntentNone,
	"arjun":                 dbIntentNone,
	"dig":                   dbIntentNone,
	"host":                  dbIntentNone,
	"ffuf":                  dbIntentNone,
	"gau":                   dbIntentNone,
	"katana":                dbIntentNone,
	"nuclei":                dbIntentNone,
	"skills gen-flags":      dbIntentNone,

	// Scans and agent runs write findings, records and scan rows.
	"scan":            "write",
	"scan diff":       "read",
	"scan status":     "read",
	"scan ls":         "read",
	"scan stop":       "write",
	"agent cancel":    "write",
	"status":          "read",
	"config get":      dbIntentNone,
	"config unset":    dbIntentNone,
	"scope add":       dbIntentNone,
	"scope rm":        dbIntentNone,
	"scope check":     dbIntentNone,
	"auth show":       "read",
	"auth rm":         "write",
	"project current": "read",
	"project rename":  "write",
	"module show":     dbIntentNone,
	"finding show":    "read",
	"scan wait":       "read", // polls during a scan: must never take the write lock
	"run":             "write",
	"scan-url":        "write",
	"scan-request":    "write",
	"server":          "write",
	"agent autopilot": "write",
	"agent swarm":     "write",
	"agent audit":     "write",
	"agent triage":    "write",
	"agent query":     "write",
	"agent olium":     "write",
	"olium":           "write",
	"audit":           "write",
	"agent":           dbIntentNone, // --list-agents / --list-templates
	"agent session":   "read",

	// server ca: the MITM CA lives on disk, outside the store.
	"server ca install":   dbIntentNone,
	"server ca path":      dbIntentNone,
	"server ca print":     dbIntentNone,
	"server ca uninstall": dbIntentNone,

	// Auth.
	"auth check": "read",
	"auth lint":  dbIntentNone,
	"auth list":  "read",
	"auth load":  "write",
	"auth totp":  dbIntentNone,

	// Config files, not the store.
	"config clean": dbIntentNone,
	"config ls":    dbIntentNone,
	"config set":   dbIntentNone,
	// validate reads recent scan targets for one rule; a missing store skips it.
	"config validate": "read",

	// Database.
	"db clean":   "write",
	"db compact": "write",
	"db export":  "read",
	"db list":    "read",
	"db migrate": "write",
	"db reset":   "write",
	"db seed":    "write",
	"db stats":   "read",

	"doctor": "read",
	"export": "read",

	// Extensions. eval/js run scripts that may call vigolium.ingest.
	"extensions":         dbIntentNone,
	"extensions docs":    dbIntentNone,
	"extensions eval":    "write",
	"extensions example": dbIntentNone,
	"extensions lint":    dbIntentNone,
	"extensions ls":      dbIntentNone,
	"extensions preset":  dbIntentNone,
	"extensions run":     "read", // also `extensions eval --record-uuid`, which opens the read pool itself
	"extensions test":    dbIntentNone,
	"extensions types":   dbIntentNone,
	"js":                 "write",

	// Findings and traffic. replay/fuzz stay "write": they read a stored
	// request, but replay --in-replace rewrites it and both are network
	// commands whose DB touch is incidental, so the read pool buys nothing.
	"finding":         "read",
	"finding load":    "write",
	"finding mark":    "write",
	"finding verify":  "write",
	"traffic":         "read",
	"endpoints":       "read",
	"params":          "read",
	"traffic body":    "read",
	"traffic headers": "read",
	"fuzz":            "write",
	"replay":          "write",

	// Input.
	"import": "write",
	"ingest": "write",
	"init":   "write",

	// Ingested callbacks become findings of the scan that planted them.
	"oast ingest": "write",
	"oast poll":   "write",

	// Kit utilities are offline tools.
	"kit harvest":     dbIntentNone,
	"kit js-beautify": dbIntentNone,
	"kit jwt-crack":   dbIntentNone,
	"kit oast new":    dbIntentNone,
	"kit oast poll":   dbIntentNone,
	"kit param-mine":  dbIntentNone,
	"kit payload":     dbIntentNone,
	"kit secret-scan": dbIntentNone,
	"kit tmp-clean":   dbIntentNone,
	"kit wordlist":    dbIntentNone,

	// Logs.
	"log":    "read",
	"log ls": "read",

	// Modules and scope live in config.
	"module":         dbIntentNone,
	"module ls":      dbIntentNone,
	"module enable":  dbIntentNone,
	"module disable": dbIntentNone,
	"scope":          dbIntentNone,
	"scope set":      dbIntentNone,
	"scope view":     dbIntentNone,

	// Projects.
	"project config": "write",
	"project create": "write",
	"project delete": "write",
	"project list":   "read",
	"project use":    "write",

	// Skills, storage (object store, not the DB), misc.
	"schema":           dbIntentNone,
	"schema list":      dbIntentNone,
	"schema command":   dbIntentNone,
	"schema event":     dbIntentNone,
	"schema error":     dbIntentNone,
	"schema plan":      dbIntentNone,
	"schema all":       dbIntentNone,
	"schema storage":   "read",
	"schema flags":     dbIntentNone,
	"hosts":            "read",
	"match-not-found":  "read",
	"dns":              "write",
	"fingerprint":      "write",
	"skills":           dbIntentNone,
	"skills get":       dbIntentNone,
	"skills install":   dbIntentNone,
	"skills list":      dbIntentNone,
	"storage download": dbIntentNone,
	"storage ls":       dbIntentNone,
	"storage presign":  dbIntentNone,
	"storage results":  dbIntentNone,
	"storage rm":       dbIntentNone,
	"storage upload":   dbIntentNone,
	"strategy":         dbIntentNone,
	"update":           dbIntentNone,
	"version":          dbIntentNone,
}

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
