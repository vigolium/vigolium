package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `scan --only-new-since <scan>`: an incremental assessment of the stored
// records.
//
// The cursor is a scan reference (full uuid, 8+ character prefix, `latest` or
// `previous`), resolved in the project, and it means "records added after that
// scan finished": the scan's finished_at becomes this run's start cursor
// (scans.start_cursor_at, scan_mode incremental) — the incremental cursor mode
// scan-on-receive already runs in — and the dynamic assessment reads only the
// records whose created_at is at or after it. The comparison is the cursor
// keyset every stored-record reader uses: (created_at, uuid) at one-second
// precision, so a record stored in the second the scan finished counts as new
// (re-assessing one is cheaper than missing one).
//
// created_at is when a record entered the store it was written to. A SQLite
// import (`vigolium import other.sqlite`) copies rows verbatim, created_at
// included, so a merged record counts as new only if it was captured after the
// cursor; label imports with `import --tag` to select them by origin instead.
//
// The flag names the input outright, as --all-records does: the stored records
// of the project, narrowed to the new ones. Without --only/--skip it runs the
// dynamic assessment alone, the phase that reads stored records.

// scanOnlyNewSince is `scan --only-new-since`.
var scanOnlyNewSince string

const onlyNewSinceFlag = "only-new-since"

func registerOnlyNewSinceFlag(flags *pflag.FlagSet) {
	flags.StringVar(&scanOnlyNewSince, onlyNewSinceFlag, "",
		"Assess only the stored records added after this scan finished (scan uuid, 8+ char prefix, latest or previous): an incremental --all-records. Runs the dynamic assessment alone unless --only/--skip pick phases. Cannot be combined with -t/-T/-i, --record-uuid, -S or --db-isolate")
}

// validateOnlyNewSinceSource enforces the flag's contract: it names the stored
// records as the input, so another input source or a scratch database (which
// holds none of them) is a usage error. --all-records is the same input and is
// accepted alongside it.
func validateOnlyNewSinceSource(cmd *cobra.Command) error {
	if strings.TrimSpace(scanOnlyNewSince) == "" {
		return usageErrorf("--%s was given no scan", onlyNewSinceFlag)
	}
	var conflicts []string
	if len(scanOpts.Targets) > 0 {
		conflicts = append(conflicts, "-t/--target (or a positional URL)")
	}
	if len(scanOpts.TargetsFilePaths) > 0 {
		conflicts = append(conflicts, "-T/--target-file")
	}
	if cmd.Flags().Changed("input") || scanStdinExplicit {
		conflicts = append(conflicts, "-i/--input")
	}
	if len(scanRecordUUIDs) > 0 {
		conflicts = append(conflicts, "--"+recordUUIDFlag)
	}
	if globalStateless {
		conflicts = append(conflicts, "-S/--stateless (its temporary database holds no stored records)")
	}
	if globalDBIsolate {
		conflicts = append(conflicts, "--db-isolate (its scratch database holds no stored records)")
	}
	if len(conflicts) > 0 {
		return usageErrorf("--%s assesses records already in the database and cannot be combined with %s",
			onlyNewSinceFlag, strings.Join(conflicts, ", "))
	}
	return nil
}

// onlyNewSinceDefaults runs the dynamic assessment alone when the flag is given
// without a phase selection, and leaves an inherited stdin pipe unread (a typed
// -i - is still seen and refused as a conflict).
func onlyNewSinceDefaults() {
	if scanOnlyNewSince == "" {
		return
	}
	if !scanStdinExplicit {
		scanOpts.Stdin = false
	}
	if scanOpts.OnlyPhase == "" && len(scanOpts.SkipPhases) == 0 {
		scanOpts.OnlyPhase = string(runner.PhaseDynamicAssessment)
	}
}

// onlyNewSinceCursor resolves ref to the cursor floor: the referenced scan's
// finished_at. A scan that has not finished has no such point yet.
func onlyNewSinceCursor(ctx context.Context, repo *database.Repository, projectUUID, ref string) (*database.Scan, time.Time, error) {
	scan, err := repo.ResolveScanRef(ctx, projectUUID, ref)
	if errors.Is(err, database.ErrScanNotFound) {
		return nil, time.Time{}, clicommon.NewCodedError(apicontract.CodeScanNotFound,
			fmt.Errorf("--%s: %w", onlyNewSinceFlag, err))
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	if scan.FinishedAt.IsZero() {
		return nil, time.Time{}, usageErrorf("--%s %s: that scan has not finished (status %q), so no record is yet \"added after it finished\"; wait for it or name a finished scan",
			onlyNewSinceFlag, scan.UUID, scan.Status)
	}
	return scan, scan.FinishedAt, nil
}

// applyOnlyNewSince resolves --only-new-since into scanOpts.OnlyNewSinceAt,
// once the project is known and before anything is sent.
func applyOnlyNewSince(ctx context.Context) error {
	if scanOnlyNewSince == "" {
		return nil
	}
	db, err := getDB()
	if err != nil {
		return fmt.Errorf("open the database to resolve --%s: %w", onlyNewSinceFlag, err)
	}
	repo := database.NewRepository(db)
	scan, at, err := onlyNewSinceCursor(ctx, repo, scanOpts.ProjectUUID, scanOnlyNewSince)
	if err != nil {
		return err
	}
	scanOpts.OnlyNewSinceAt = at
	if !globalJSON && !globalSilent {
		n, cerr := repo.CountRecordsAfterCursor(ctx, scanOpts.ProjectUUID, at, "")
		count := "?"
		if cerr == nil {
			count = fmt.Sprint(n)
		}
		fmt.Fprintf(os.Stderr, "%s Incremental: %s stored record(s) added since scan %s finished at %s\n",
			terminal.InfoSymbol(), count, scan.UUID, at.UTC().Format(time.RFC3339))
	}
	return nil
}
