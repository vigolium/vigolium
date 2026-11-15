package cli

import (
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// Every -j read attaches a ready-to-run follow-up command:
//
//	"query": "vigolium finding --id 5 --json --with-records"
//
// and every one of them was generated without the context that made the read
// reachable. Finding IDs are per-database autoincrement integers and traffic
// UUIDs are per-store, so following that string from a session pinned to
// `--db /engagements/acme.sqlite -S` opens the DEFAULT database instead and
// returns a different row with the same id, or nothing. The envelope already
// reports db_path and project_scoped; the follow-up it printed contradicted
// both.
//
// A glob merge is worse: `--glob-db '*.sqlite'` reads through a temporary
// database that is deleted when the process exits, so a follow-up naming it
// cannot be reopened by anyone, ever.
//
// readContextArgs generates the flags that reproduce the current read, and
// followUpQuery composes them with a command. The display string stays a
// display string — correctly quoted, but nobody should have to eval it.

// readContextArgs returns the flags that pin a follow-up read to the same store
// and scope as the read that produced it.
//
// Returns nil when the read cannot be reproduced (a glob merge), so the caller
// suppresses the follow-up rather than printing one that leads somewhere else.
func readContextArgs() ([]string, bool) {
	// A glob merge reads through a scratch database that does not survive the
	// process. There is no argument list that reopens it, and the honest answer
	// is no follow-up rather than a plausible one that fails or, worse, silently
	// resolves the same id in a different store.
	if strings.TrimSpace(globalGlobDB) != "" {
		return nil, false
	}

	var args []string
	if db := followUpDBFlag(); db != "" {
		args = append(args, "--db", db)
	}
	// Scope is carried explicitly rather than left to the active-project file:
	// that file is global process state a parallel caller may have changed
	// between the two reads.
	stateless := statelessReadRequested()
	if stateless {
		args = append(args, "--stateless")
	}
	args = append(args, followUpScopeFlags(stateless)...)
	if globalReadOnly {
		args = append(args, "--read-only")
	}
	if cfg := strings.TrimSpace(globalConfig); cfg != "" {
		// Absolute, for the same reason --db is: the follow-up may be run from
		// another directory, and a relative --config that resolves to a
		// different file there is worse than no --config at all.
		args = append(args, "--config", absOrRaw(cfg))
	}
	return args, true
}

// followUpDBFlag renders the --db value that reopens this read's store, or ""
// when the store cannot be named on a command line.
//
// Two rules, both learned from follow-ups that resolved somewhere else:
//
//   - A stateless read's store is the SOURCE the operator named (a .jsonl
//     export, a standalone .sqlite), not the scratch database it was loaded
//     into. OpenedDBPath reports the scratch file, which is deleted on exit.
//   - A non-SQLite driver has no path. OpenedDBPath returns the driver name
//     there, and "--db postgres" means "a file called postgres in the cwd" —
//     so the connection details stay where they are, in the config.
func followUpDBFlag() string {
	// The first rule is readSourcePath's — shared with the --tree root label, so
	// the two cannot disagree about which store a read is about.
	src := readSourcePath()
	if !statelessReadRequested() {
		if driver := clicommon.OpenedDBDriver(); driver != "" && driver != "sqlite" {
			return ""
		}
	}
	// A command that opened its store directly (ingest, and others that do not
	// go through the recorded opener) leaves nothing recorded; the --db the
	// caller passed is still the store it used.
	if src == "" {
		src = strings.TrimSpace(globalDB)
	}
	if src == "" {
		return ""
	}
	return absOrRaw(database.ExpandPath(src))
}

// followUpScopeFlags pins the project the read was scoped to.
//
// The resolved UUID is preferred over the operator's own --project-name or the
// implicit active project: a name is looked up at run time in whichever store
// the follow-up opens, and the active-project file can be changed by `project
// use` between the two commands. Pinning the UUID makes the follow-up name the
// same rows this read returned.
//
// A stateless read is unscoped by default (the file carries whatever
// project_uuid it was exported under), so a scope flag is emitted only when the
// operator asked for one.
func followUpScopeFlags(stateless bool) []string {
	if stateless && !explicitProjectSelected() {
		return nil
	}
	if uuid, ok := clicommon.ResolvedProjectUUID(); ok {
		return []string{"--project-uuid", uuid}
	}
	if uuid := strings.TrimSpace(globalProjectUUID); uuid != "" {
		return []string{"--project-uuid", uuid}
	}
	if name := strings.TrimSpace(globalProjectName); name != "" {
		return []string{"--project-name", name}
	}
	return nil
}

// absOrRaw makes path absolute, falling back to the original when the working
// directory cannot be read. A best-effort absolute path beats refusing to
// describe the read.
func absOrRaw(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// followUpQuery renders a runnable follow-up command string, pinned to the read
// context. tail is the command and its own flags, e.g.
// []string{"finding", "--id", "5", "--json", "--with-records"}.
//
// Returns "" when the read cannot be reproduced, which the envelope renders as
// an absent `query` field rather than a wrong one.
func followUpQuery(tail ...string) string {
	parts := followUpArgv(tail...)
	if parts == nil {
		return ""
	}
	return quoteArgv(parts)
}

// quoteArgv renders argv as one pasteable POSIX shell line (httpmsg.ShellQuote
// per word). The one quoter for every command line the CLI prints — follow-up
// queries, resume and shim lines, the scan document — so a database path with a
// space in it is escaped by the same rule everywhere.
func quoteArgv(argv []string) string {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = httpmsg.ShellQuote(a)
	}
	return strings.Join(quoted, " ")
}

// followUpArgv is followUpQuery's unquoted form: the same command as an argv
// vector, ready for exec.Command without a shell in the middle.
//
// Returns nil when the read cannot be reproduced, so both forms are absent
// together and a consumer cannot find one but not the other.
func followUpArgv(tail ...string) []string {
	ctx, ok := readContextArgs()
	if !ok {
		return nil
	}
	parts := make([]string, 0, len(ctx)+len(tail)+1)
	parts = append(parts, "vigolium")
	parts = append(parts, ctx...)
	parts = append(parts, tail...)
	return parts
}
