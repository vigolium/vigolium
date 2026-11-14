package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// "No implicit work": a scan only touches what it was pointed at.
//
// `vigolium scan` (and `vigolium run <phase>`, which delegates to it) with no
// -t, -T, -i or piped stdin used to fall through to runDBScan and attack every
// HTTP record already stored in the project. `</dev/null` is a character device,
// so an agent that forgot its target — or whose variable expanded to nothing —
// silently re-scanned the whole database and exited 0. That workflow is now
// opt-in with --all-records (the spelling `agent swarm` already uses).
//
// The bare form stays working for one release on an interactive terminal, with
// a deprecation warning, so a human's muscle memory is not broken without
// notice. Anywhere a machine is likely on the other end (-j, --events,
// --ci-output, or stdout/stderr not a terminal) it is a usage error now.

// globalAllRecords is --all-records on scan and run.
var globalAllRecords bool

// allRecordsFlag is the flag name, shared by registration and the messages that
// tell the operator to pass it.
const allRecordsFlag = "all-records"

// registerAllRecordsFlag declares --all-records. Only scan and run take it:
// they are the two commands whose no-target path scans the database, and both
// share runScanCmd. ingest also registers the input-source set but has no DB
// fallback, so the flag is not part of registerInputSourceFlags.
func registerAllRecordsFlag(flags *pflag.FlagSet) {
	flags.BoolVar(&globalAllRecords, allRecordsFlag, false,
		"Scan every HTTP record already stored in the active project (the database rescan). Required when no -t/-T/-i/stdin target is given; cannot be combined with them")
}

// runDBScanFn is the database-rescan entry point executeNativeScan calls. A var
// so the target-contract tests can prove `--all-records` reaches it without
// running a scan.
var runDBScanFn = runDBScan

// scanStdinExplicit records why runScanCmd chose stdin: true for a typed `-i -`
// (full --input-read-timeout), false for the implicit guess (first-byte window).
var scanStdinExplicit bool

// scanStdinPrefetched holds stdin drained by prefetchScanStdin, so the
// no-data/empty verdict is reached before the database opens and the banner
// prints. executeNativeScan consumes it through takeScanStdin.
var (
	scanStdinPrefetched      []byte
	scanStdinPrefetchedReady bool
)

// describeScanStore names the store and project a database rescan would touch,
// so the "no targets" error tells the caller exactly what --all-records means
// for THIS invocation rather than "the database" in the abstract.
func describeScanStore(settings *config.Settings, projectUUID string) string {
	store := "default database"
	if settings != nil {
		switch {
		case settings.Database.Driver != "" && settings.Database.Driver != "sqlite":
			store = settings.Database.Driver + " database"
		case strings.TrimSpace(settings.Database.SQLite.Path) != "":
			store = "database " + terminal.ShortenHome(config.ExpandPath(settings.Database.SQLite.Path))
		}
	}
	var project string
	switch {
	case projectUUID == "" || projectUUID == database.DefaultProjectUUID:
		project = "default project"
	case strings.TrimSpace(globalProjectName) != "":
		project = fmt.Sprintf("project %s (%s)", globalProjectName, projectUUID)
	default:
		project = "project " + projectUUID
	}
	return store + ", " + project
}

// resolveScanTargetSource enforces the target contract for scan/run once
// settings are loaded (so the store can be named):
//
//   - --all-records with -t/-T/-i is a usage error: the two must not be silently
//     unioned, and the operator has to say which one they meant.
//   - --all-records with --stateless is a usage error: a stateless run starts
//     from an empty temporary database, so there is nothing to rescan.
//   - no target source at all, without --all-records, is a usage error in any
//     machine context and a deprecation warning (still rescanning) on a TTY.
func resolveScanTargetSource(cmd *cobra.Command, settings *config.Settings) error {
	hasTargets := len(scanOpts.Targets) > 0
	hasTargetFile := len(scanOpts.TargetsFilePaths) > 0
	inputTyped := cmd.Flags().Changed("input")
	hasInputFile := globalInput != "" && globalInput != "-"
	store := describeScanStore(settings, scanOpts.ProjectUUID)

	if globalAllRecords {
		var conflicts []string
		if hasTargets {
			conflicts = append(conflicts, "-t/--target (or a positional URL)")
		}
		if hasTargetFile {
			conflicts = append(conflicts, "-T/--target-file")
		}
		if inputTyped {
			conflicts = append(conflicts, "-i/--input")
		}
		if len(conflicts) > 0 {
			return usageErrorf("--%s rescans the HTTP records already in the %s and cannot be combined with %s; drop one",
				allRecordsFlag, store, strings.Join(conflicts, ", "))
		}
		if scanOpts.Stateless {
			return usageErrorf("--%s needs a persistent database: --stateless starts from an empty temporary one, so there is nothing to rescan",
				allRecordsFlag)
		}
		return nil
	}

	if hasTargets || hasTargetFile || hasInputFile || scanOpts.Stdin {
		return nil
	}

	// No target is a usage error everywhere, terminal or not: the old TTY
	// fallback rescanned every stored record after a warning, which turned a
	// forgotten -t into a scan of a whole project.
	return usageErrorf("no targets: pass -t <url>, -T <file>, -i <file>, pipe URLs on stdin, "+
		"or --%s to scan every HTTP record already in the %s", allRecordsFlag, store)
}

// prefetchScanStdin drains stdin for the URL-list path before any database or
// network work, so "nothing arrived" and "stdin was empty" fail as usage errors
// in milliseconds instead of after the banner, the scan row and scan.started.
// Formats other than a target list keep streaming through StdinSource.
func prefetchScanStdin() error {
	scanStdinPrefetched, scanStdinPrefetchedReady = nil, false
	if !scanOpts.Stdin || !source.IsTargetListFormat(scanOpts.InputFileMode) {
		return nil
	}
	raw, err := readScanStdin(scanStdinExplicit)
	if err != nil {
		if errors.Is(err, clicommon.ErrStdinNoData) {
			return usageErrorf("no targets: nothing arrived on stdin within %s; pass -t <url>, -T <file>, -i <file>, "+
				"or pipe URLs (use -i - to wait for a slow producer)", implicitStdinWait)
		}
		return fmt.Errorf("failed to read stdin: %w", err)
	}
	if strings.TrimSpace(string(raw)) == "" && len(scanOpts.Targets) == 0 && len(scanOpts.TargetsFilePaths) == 0 {
		return usageErrorf("no targets: stdin was empty; pass -t <url>, -T <file>, -i <file>, or pipe URLs")
	}
	scanStdinPrefetched, scanStdinPrefetchedReady = raw, true
	return nil
}

// takeScanStdin returns the prefetched stdin once, falling back to a read for a
// caller that reached executeNativeScan without going through runScanCmd.
func takeScanStdin() ([]byte, error) {
	if scanStdinPrefetchedReady {
		raw := scanStdinPrefetched
		scanStdinPrefetched, scanStdinPrefetchedReady = nil, false
		return raw, nil
	}
	return readScanStdin(scanStdinExplicit)
}
