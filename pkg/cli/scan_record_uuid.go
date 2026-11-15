package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
)

// scanRecordUUIDs is `scan --record-uuid`, repeatable: the stored records to
// run the modules against (full UUIDs or unique 8+ character prefixes).
var scanRecordUUIDs []string

const recordUUIDFlag = "record-uuid"

func registerScanRecordUUIDFlag(flags *pflag.FlagSet) {
	flags.StringArrayVar(&scanRecordUUIDs, recordUUIDFlag, nil,
		"Scan only this stored HTTP record (UUID or unique 8+ char prefix); repeatable. Runs the dynamic assessment over exactly these records unless --only/--skip pick phases. Cannot be combined with -t/-T/-i, --all-records, -S or --db-isolate")
}

// validateRecordUUIDSource enforces --record-uuid's contract: it names the
// input outright, so another input source, a stateless or isolated scratch
// database (which holds none of the stored records) is a usage error.
func validateRecordUUIDSource(cmd *cobra.Command) error {
	if len(scanRecordUUIDs) == 0 {
		return nil
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
	if globalAllRecords {
		conflicts = append(conflicts, "--"+allRecordsFlag)
	}
	if globalStateless {
		conflicts = append(conflicts, "-S/--stateless (its temporary database holds no stored records)")
	}
	if globalDBIsolate {
		conflicts = append(conflicts, "--db-isolate (its scratch database holds no stored records)")
	}
	if len(conflicts) > 0 {
		return usageErrorf("--%s scans records already in the database and cannot be combined with %s",
			recordUUIDFlag, strings.Join(conflicts, ", "))
	}
	return nil
}

// recordUUIDDefaultPhase runs the dynamic assessment alone when --record-uuid
// is given without a phase selection: the records are the input, and the
// target-driven phases (discovery, spidering) have no target to start from.
//
// Like --all-records it names the input outright, so an inherited stdin pipe
// is not read; a typed -i - is still seen and rejected as a conflict.
func recordUUIDDefaultPhase() {
	if len(scanRecordUUIDs) == 0 {
		return
	}
	if !scanStdinExplicit {
		scanOpts.Stdin = false
	}
	if scanOpts.OnlyPhase == "" && len(scanOpts.SkipPhases) == 0 {
		scanOpts.OnlyPhase = string(runner.PhaseDynamicAssessment)
	}
}

// resolveScanRecordRefs expands --record-uuid values to full UUIDs of
// records in the project, refusing unknown, ambiguous and evidence records
// (a finding's attached exchange is never re-attacked).
func resolveScanRecordRefs(ctx context.Context, repo *database.Repository, projectUUID string, refs []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range refs {
		for _, ref := range strings.Split(raw, ",") {
			ref = strings.ToLower(strings.TrimSpace(ref))
			if ref == "" {
				continue
			}
			full := ref
			if !scanUUIDShape.MatchString(ref) {
				if len(ref) < database.MinRecordUUIDPrefix {
					return nil, usageErrorf("--%s %q: a prefix needs at least %d characters", recordUUIDFlag, ref, database.MinRecordUUIDPrefix)
				}
				uuid, candidates, err := repo.ResolveRecordUUIDInProject(ctx, ref, projectUUID)
				switch {
				case errors.Is(err, sql.ErrNoRows):
					return nil, codedErrorf(apicontract.CodeRecordNotFound, "--%s %q: no stored record in this project matches", recordUUIDFlag, ref)
				case err != nil:
					return nil, err
				case len(candidates) > 1:
					ids := make([]string, len(candidates))
					for i, c := range candidates {
						ids[i] = c.UUID
					}
					return nil, codedErrorf(apicontract.CodeAmbiguousID, "--%s %q matches %d records (%s); use more characters",
						recordUUIDFlag, ref, len(ids), strings.Join(ids, ", "))
				}
				full = uuid
			}
			rec, err := repo.GetRecordByUUID(ctx, full)
			if err != nil || rec == nil || (projectUUID != "" && rec.ProjectUUID != projectUUID) {
				return nil, codedErrorf(apicontract.CodeRecordNotFound, "--%s %s: no stored record in this project has this UUID", recordUUIDFlag, full)
			}
			for _, ev := range database.EvidenceRecordSources {
				if rec.Source == ev {
					return nil, usageErrorf("--%s %s is scan evidence (source %q): evidence records are never re-scanned; scan the request it came from instead",
						recordUUIDFlag, full, rec.Source)
				}
			}
			if !seen[full] {
				seen[full] = true
				out = append(out, full)
			}
		}
	}
	if len(out) == 0 {
		return nil, usageErrorf("--%s was given no record", recordUUIDFlag)
	}
	return out, nil
}

// applyScanRecordRefs resolves --record-uuid into scanOpts.RecordUUIDs, once
// the project is known and before anything is printed or sent.
func applyScanRecordRefs(ctx context.Context) error {
	if len(scanRecordUUIDs) == 0 {
		return nil
	}
	db, err := getDB()
	if err != nil {
		return fmt.Errorf("open the database to resolve --%s: %w", recordUUIDFlag, err)
	}
	uuids, err := resolveScanRecordRefs(ctx, database.NewRepository(db), scanOpts.ProjectUUID, scanRecordUUIDs)
	if err != nil {
		return err
	}
	scanOpts.RecordUUIDs = uuids
	return nil
}

// scanContext is cmd's context, or Background for a RunE called directly.
func scanContext(cmd *cobra.Command) context.Context {
	if cmd != nil && cmd.Context() != nil {
		return cmd.Context()
	}
	return context.Background()
}
