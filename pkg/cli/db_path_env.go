package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// dbPathEnvVar supplies a default for the --db flag, so a shell can be pinned to
// one database for a whole session (`export VIGOLIUM_DB_PATH=~/scans/acme.sqlite`)
// instead of repeating --db on every command. An explicit --db always wins.
//
// The value goes through config.ExpandPath, so `~` and nested env references
// resolve the same way the config file's database.sqlite.path does.
const dbPathEnvVar = "VIGOLIUM_DB_PATH"

// dbPathEnvAutoStateless records that dbPathEnvVar named a usable database, so
// reads should treat it as a standalone source with project scoping off. It is
// consumed by statelessReadRequested — the one predicate every read path already
// consults — rather than by a list of command names here.
var dbPathEnvAutoStateless bool

// dbPathEnvPinned records that dbPathEnvVar was honored as this invocation's
// --db, whether or not the file exists yet. dbPathEnvAutoStateless is gated on
// existence (a read of a missing file must not fail), so it cannot answer "is
// this shell pinned to a session database" consistently from the first scan of
// a session to the second; overlayProjectUUID needs exactly that answer.
var dbPathEnvPinned bool

// statelessWriteRequested reports whether the user explicitly asked cmd for the
// throwaway-database flavor of -S. It reads the flag rather than globalStateless
// because that variable is only one of the bindings behind the name: `audit -S`
// sets auditStateless, and on server/ingest -S is the retired --scan-on-receive
// tombstone (a usage error), not a stateless flag at all.
// flagOn, not Changed: `scan --stateless=false VIGOLIUM_DB_PATH=…` means "I know
// about -S and I do not want it", and reading Changed as enabled dropped the pin
// and sent the scan's writes to the default database instead.
func statelessWriteRequested(cmd *cobra.Command) bool {
	if t, _ := traitOf(cmd); !t.Runtime.has(rtStatelessWrite) {
		return false
	}
	return flagOn(cmd, "stateless")
}

// applyDBPathEnv resolves dbPathEnvVar into the --db global (and, for reads, the
// stateless-source flag) and prints a one-line notice describing what it did. It
// is a no-op when the var is unset, and never overrides an explicit flag.
//
// The stateless half is deliberately gated on the file already existing: a
// stateless read stats its source and fails when it is missing, so a session
// whose database has not been written yet would otherwise error on the first
// `vigolium finding` instead of printing an empty table.
//
// Returns an error when the pinned path is set but unusable. A pin that cannot
// be honored must NOT silently fall through to the built-in default: that
// default is one shared file under one default project, so the fall-through
// quietly redirects an engagement's reads and writes into a store holding every
// other target that ever landed there. Failing is the only safe answer.
func applyDBPathEnv(cmd *cobra.Command) error {
	applyConfigEnv()
	if handled, err := applyDBEnv(cmd); handled || err != nil {
		return err
	}
	raw := strings.TrimSpace(os.Getenv(dbPathEnvVar))
	if raw == "" {
		return nil
	}

	// An explicit --db wins. Say so when the two disagree — silently preferring
	// one path over another is exactly the kind of thing that gets debugged for
	// ten minutes.
	if explicit := strings.TrimSpace(globalDB); explicit != "" {
		if explicit != raw && config.ExpandPath(explicit) != config.ExpandPath(raw) {
			dbPathEnvNotice(fmt.Sprintf("--db overrides %s (using %s)",
				terminal.BoldCyan(dbPathEnvVar), terminal.BoldYellow(terminal.ShortenHome(explicit))))
		}
		return nil
	}

	if statelessWriteRequested(cmd) {
		dbPathEnvNotice(fmt.Sprintf("%s: ignoring %s (results go to a temporary database)",
			terminal.BoldCyan("--stateless"), terminal.BoldCyan(dbPathEnvVar)))
		return nil
	}

	path := config.ExpandPath(raw)
	if err := dbPathEnvUsable(path); err != nil {
		return fmt.Errorf("%s=%s is unusable (%w).\n"+
			"Refusing to fall back to the default database: it is one shared file holding every target that has ever been scanned into it, "+
			"so a silent redirect there would mix this session with unrelated work. Fix the path or unset %s",
			dbPathEnvVar, raw, err, dbPathEnvVar)
	}
	globalDB = path
	dbPathEnvPinned = true

	notice := fmt.Sprintf("%s → %s",
		terminal.BoldCyan(dbPathEnvVar), terminal.BoldYellow(terminal.ShortenHome(path)))
	if !statelessReadRequested() && statelessSourceUsable(path) {
		dbPathEnvAutoStateless = true
		notice += terminal.Gray(" (reads: project scoping off)")
	}
	dbPathEnvNotice(notice)
	return nil
}

// applyConfigEnv is the env fallback for --config: VIGOLIUM_CONFIG names the
// config file when the flag was not given. An agent's bash tool exports it so
// the `vigolium` commands the agent runs load the parent's config.
func applyConfigEnv() {
	if strings.TrimSpace(globalConfig) != "" {
		return
	}
	if v := strings.TrimSpace(os.Getenv(configEnvVar)); v != "" {
		globalConfig = config.ExpandPath(v)
	}
}

// applyDBEnv is the env fallback for --db: VIGOLIUM_DB is exactly "--db from
// the environment". Unlike VIGOLIUM_DB_PATH it does NOT turn project scoping
// off for reads, which is why an agent's bash tool exports it for a scoped
// parent (a child of `--db X --project-uuid P` must read P, not every project
// in X). Precedence: --db, then VIGOLIUM_DB, then VIGOLIUM_DB_PATH, then the
// config's database, then the default.
//
// handled reports that VIGOLIUM_DB was set (and so VIGOLIUM_DB_PATH is not
// consulted). Like VIGOLIUM_DB_PATH, a pin that cannot be honored is an
// error, never a silent fall-through to the shared default database.
func applyDBEnv(cmd *cobra.Command) (handled bool, err error) {
	raw := strings.TrimSpace(os.Getenv(dbEnvVar))
	if raw == "" {
		return false, nil
	}
	if strings.TrimSpace(globalDB) != "" {
		return true, nil
	}
	if statelessWriteRequested(cmd) {
		dbPathEnvNotice(fmt.Sprintf("%s: ignoring %s (results go to a temporary database)",
			terminal.BoldCyan("--stateless"), terminal.BoldCyan(dbEnvVar)))
		return true, nil
	}
	path := config.ExpandPath(raw)
	if err := dbPathEnvUsable(path); err != nil {
		return true, fmt.Errorf("%s=%s is unusable (%w).\n"+
			"Refusing to fall back to the default database. Fix the path or unset %s",
			dbEnvVar, raw, err, dbEnvVar)
	}
	globalDB = path
	dbPathEnvNotice(fmt.Sprintf("%s → %s", terminal.BoldCyan(dbEnvVar), terminal.BoldYellow(terminal.ShortenHome(path))))
	return true, nil
}

// dbPathEnvUsable reports why the pinned path cannot back a database, or nil.
//
// A path that does not exist yet is FINE — the first scan of a session creates
// it, and refusing there would make the pin unusable for its main purpose. What
// is not fine is a path whose parent directory cannot be created or written:
// that one can never become a database, so honoring the pin is impossible and
// the fall-through is exactly what must not happen.
func dbPathEnvUsable(path string) error {
	if info, err := os.Stat(path); err == nil {
		if info.IsDir() {
			return fmt.Errorf("path is a directory")
		}
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("cannot create parent directory %s: %w", dir, err)
	}
	probe, err := os.OpenFile(filepath.Join(dir, ".vigolium-write-probe"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("parent directory %s is not writable: %w", dir, err)
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return nil
}

// dbPathEnvNotice prints one informational line to stderr, staying quiet in the
// output modes that promise a clean stream (--silent, -j/--json, CI).
func dbPathEnvNotice(msg string) {
	if machineOutputMode() {
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), msg)
}
