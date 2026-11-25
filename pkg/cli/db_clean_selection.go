package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
)

// `db clean` used to branch into its orphan, findings-only, table, and all-table
// handlers BEFORE resolving the project and the filters, and each of those
// handlers then built its own query from scratch. Three of the four ignored
// every selector on the command line:
//
//	vigolium db clean --findings-only --host staging.example --force
//
// read as "delete findings for that host" and deleted every finding in the
// store, across every project, because cleanFindingsOnly applied severity and
// nothing else. --orphans and --table constructed an empty QueryFilters, so
// they too swept the whole file regardless of the selected project.
//
// The shape of the bug is that --findings-only LOOKS like a narrowing modifier
// and is actually a mode switch. So the fix is not only to apply the filters: it
// is to resolve ONE selection up front that states its own scope, apply it
// identically to the preview, the count, and the delete, and reject a selector
// the chosen mode cannot honor instead of silently dropping it.

// cleanMode is the operation `db clean` was asked to perform. Exactly one is
// selected per invocation.
type cleanMode string

const (
	// cleanModeRecords deletes HTTP records (and their findings) matching the
	// filters. This is the default when no mode flag is given.
	cleanModeRecords cleanMode = "records"
	// cleanModeFindings deletes findings only, leaving HTTP records in place.
	cleanModeFindings cleanMode = "findings"
	// cleanModeOrphans deletes findings with no surviving HTTP record.
	cleanModeOrphans cleanMode = "orphans"
	// cleanModeTable truncates one table. Store-wide by definition: several
	// cleanable tables (finding_records) carry no project column at all.
	cleanModeTable cleanMode = "table"
	// cleanModeAll truncates every data table. Store-wide.
	cleanModeAll cleanMode = "all"
)

// cleanSelection is the validated description of what will be deleted. Preview,
// count, and execution all read this one value, so the number shown to the
// operator and the rows actually removed cannot diverge.
type cleanSelection struct {
	Mode cleanMode

	// Filters is applied by every scoped mode. ProjectUUID is always populated
	// for a scoped mode and always empty for a store-wide one.
	Filters database.QueryFilters

	// Table names the target of cleanModeTable.
	Table string

	// StoreWide records that this selection deliberately addresses the entire
	// database rather than one project. It is stated rather than inferred so the
	// preview can say so out loud.
	StoreWide bool
}

// resolveCleanSelection validates the flag combination and builds the selection.
// It performs no I/O: it runs before a writable database is opened, so an
// invalid combination cannot reach a delete path or leave a connection behind.
func resolveCleanSelection(projectUUID string) (*cleanSelection, error) {
	modes := []struct {
		flag string
		on   bool
		mode cleanMode
	}{
		{"--orphans", cleanOrphans, cleanModeOrphans},
		{"--findings-only", cleanFindings, cleanModeFindings},
		{"--table", cleanTable != "", cleanModeTable},
		{"--all", cleanAll, cleanModeAll},
	}

	var chosen []string
	mode := cleanModeRecords
	for _, m := range modes {
		if m.on {
			chosen = append(chosen, m.flag)
			mode = m.mode
		}
	}
	// --severity names findings, so on its own it deletes findings: as a
	// record filter it removed every HTTP record carrying a finding of that
	// severity, and with them every other finding those records proved.
	if len(chosen) == 0 && cleanSeverity != "" {
		mode = cleanModeFindings
	}
	if len(chosen) > 1 {
		return nil, usageErrorf(
			"%s select different sets of rows and cannot be combined; run one mode at a time",
			strings.Join(chosen, " and "))
	}

	// The flags the operator actually supplied, in a fixed order so a rejection
	// message lists them the way they were typed rather than map-random.
	var supplied []string
	for _, sel := range []struct {
		flag string
		set  bool
	}{
		{"--host", cleanHost != ""},
		{"--scan-uuid", cleanScanUUID != ""},
		{"--before", cleanBefore != ""},
		{"--status", len(cleanStatus) > 0},
		{"--severity", cleanSeverity != ""},
		{"--search", dbSearch != ""},
		{"--tag", len(cleanTags) > 0},
	} {
		if sel.set {
			supplied = append(supplied, sel.flag)
		}
	}

	if mode == cleanModeTable || mode == cleanModeAll {
		return resolveStoreWideSelection(mode, supplied)
	}
	return resolveScopedSelection(mode, projectUUID, supplied)
}

// resolveStoreWideSelection builds a --table / --all selection. These truncate;
// they cannot narrow. A selector supplied alongside one was previously accepted
// and dropped, which made the command line read narrower than the delete was.
func resolveStoreWideSelection(mode cleanMode, supplied []string) (*cleanSelection, error) {
	if len(supplied) > 0 {
		modeFlag := "--all"
		if mode == cleanModeTable {
			modeFlag = "--table"
		}
		return nil, usageErrorf(
			"%s deletes every matching row in the database and cannot be narrowed by %s; "+
				"drop %s to delete the whole table, or drop %s and use the filters to delete a subset",
			modeFlag, strings.Join(supplied, ", "), strings.Join(supplied, ", "), modeFlag)
	}

	sel := &cleanSelection{Mode: mode, StoreWide: true}
	if mode == cleanModeTable {
		if _, ok := database.AllowedCleanTables[cleanTable]; !ok {
			allowed := make([]string, 0, len(database.AllowedCleanTables))
			for k := range database.AllowedCleanTables {
				allowed = append(allowed, k)
			}
			sort.Strings(allowed)
			return nil, usageErrorf("table %q is not allowed for cleaning. Allowed tables: %s",
				cleanTable, strings.Join(allowed, ", "))
		}
		sel.Table = cleanTable
	}
	// A dry run deletes nothing, so it needs no confirmation.
	if mode == cleanModeAll && !globalForce && !cleanDryRun {
		return nil, usageErrorf("--all deletes every row in the database and requires --force (or --dry-run to preview)")
	}
	return sel, nil
}

// resolveScopedSelection builds a records / findings-only / orphans selection.
// Every one of these is confined to the resolved project.
func resolveScopedSelection(mode cleanMode, projectUUID string, supplied []string) (*cleanSelection, error) {
	// An orphan is a finding with no surviving HTTP record, so every selector
	// that reaches through a record (--host, --status) can only ever match zero
	// rows, and the rest describe a subset the sweep does not compute. Accepting
	// them would restate the original bug in a quieter form.
	if mode == cleanModeOrphans {
		if len(supplied) > 0 {
			return nil, usageErrorf(
				"--orphans sweeps findings whose HTTP records are already gone and cannot be narrowed by %s "+
					"(a filter that reaches through a record can never match an orphan); "+
					"it is confined to the active project",
				strings.Join(supplied, ", "))
		}
		return &cleanSelection{
			Mode:    mode,
			Filters: database.QueryFilters{ProjectUUID: projectUUID},
		}, nil
	}

	// --before is deliberately resolved with ParseSince, not the upper-bound
	// ParseUntil: "before 2026-08-01" excludes the 1st, and the end-of-day snap
	// an upper bound applies would silently widen a DELETE by a full day.
	var dateTo *time.Time
	if cleanBefore != "" {
		t, err := clicommon.ParseSince(cleanBefore)
		if err != nil {
			return nil, usageErrorf("invalid --before date: %v", err)
		}
		dateTo = &t
	}

	severities := clicommon.SplitCSV(cleanSeverity)

	// A tag labels records; the findings modes select findings, which carry
	// none. Accepting it there would delete findings the tag never named.
	tags, err := parseTagFilterFlag(cleanTags)
	if err != nil {
		return nil, err
	}
	if len(tags) > 0 && mode == cleanModeFindings {
		return nil, usageErrorf("--tag selects records and cannot narrow a findings delete (--findings-only or --severity alone); " +
			"drop --tag, or drop the findings selector to delete the tagged records with the findings only they evidence")
	}

	return &cleanSelection{
		Mode: mode,
		Filters: database.QueryFilters{
			ProjectUUID: projectUUID,
			HostPattern: cleanHost,
			StatusCodes: cleanStatus,
			ScanUUID:    cleanScanUUID,
			DateTo:      dateTo,
			Severity:    severities,
			SearchTerm:  dbSearch,
			Tags:        tags,
		},
	}, nil
}

// describeScope renders the scope line shown above every preview. A store-wide
// delete says so explicitly; a scoped one names the project it is confined to.
func (s *cleanSelection) describeScope() string {
	if s.StoreWide {
		return "the ENTIRE database (all projects)"
	}
	if s.Filters.ProjectUUID == "" {
		return "the entire database (no project scope resolved)"
	}
	return fmt.Sprintf("project %s", s.Filters.ProjectUUID)
}

// describeAction renders the short phrase the confirmation prompt asks about.
func (s *cleanSelection) describeAction(count int64) string {
	// The noun is pluralized where the noun IS, not by appending to the end of
	// the whole phrase: "row from every data table" pluralized by suffix reads
	// "row from every data tables".
	noun := func(one, many string) string {
		if count == 1 {
			return one
		}
		return many
	}

	var unit string
	switch s.Mode {
	case cleanModeFindings, cleanModeOrphans:
		unit = noun("finding", "findings")
	case cleanModeTable:
		unit = fmt.Sprintf("%s from %q", noun("row", "rows"), s.Table)
	case cleanModeAll:
		unit = noun("row", "rows") + " from every data table"
	default:
		unit = noun("record", "records")
	}
	return fmt.Sprintf("deleting %d %s in %s", count, unit, s.describeScope())
}
