package cli

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	scanDiffTarget           string
	scanDiffLast             int
	scanDiffFailOnNew        string
	scanDiffIncludeDismissed bool
)

var scanDiffCmd = &cobra.Command{
	Use:   "diff <base-scan> <head-scan>",
	Short: "Compare two scans' findings: new, fixed, not re-observed, unchanged",
	Long: `Compare the findings two scans observed.

  new             observed by the head scan, not by the base scan
  unchanged       observed by both
  fixed           observed by the base scan and not by the head scan, when the
                  head scan is comparable: it completed, covered every base
                  target, and completed every phase that ran in the base scan
  not_reobserved  the same, when the head scan is NOT comparable (curtailed,
                  narrower, still running): absence is not evidence of a fix

The base may also be a previous run's export (a .jsonl file or a .sqlite
store, e.g. from a CI artifact): its findings are compared with the head scan
by finding hash.

Hashes listed in --ignore-file (default .vigolium-ignore.yaml when present)
are left out of new and counted as ignored.

A scan is a full UUID, a UUID prefix (8+ characters), or a keyword: "latest"
(the most recently started scan that is not running) and "previous" (the one
before it). --target <url> --last N compares the N-th most recent scan of that
target against its most recent one instead.

Findings marked false_positive or accepted_risk are left out unless
--include-dismissed. "history": "partial" means a scan predates the store's
per-scan observation history, so a finding re-detected by it may be missing.

--fail-on-new <severity> exits 4 when a new finding is at or above the
severity (after the result is written).`,
	Example: `  vigolium scan diff previous latest
  vigolium scan diff 3f2a9c1d 8b7e0f42 -j
  vigolium scan diff --target https://app.example.com --last 2 --fail-on-new high`,
	Args: cobra.MaximumNArgs(2),
	RunE: runScanDiff,
}

func init() {
	scanCmd.AddCommand(scanDiffCmd)
	f := scanDiffCmd.Flags()
	registerTSVFlags(f)
	registerInMemoryOffsetFlag(f)
	f.StringVar(&scanDiffTarget, "target", "", "Compare the scans of this target (with --last) instead of naming two scans")
	f.IntVar(&scanDiffLast, "last", 2, "With --target: compare the N-th most recent scan of the target against the most recent (N >= 2)")
	f.StringVar(&scanDiffFailOnNew, "fail-on-new", "", "Exit 4 when a NEW finding is at or above this severity ("+strings.Join(severityOrder, "|")+")")
	f.BoolVar(&scanDiffIncludeDismissed, "include-dismissed", false, "Keep findings marked false_positive or accepted_risk")
	f.StringVar(&scanIgnoreFile, "ignore-file", "", "YAML list of finding hashes to leave out of `new` ({hash, reason, expires}); default "+defaultIgnoreFile+" when present")
	f.BoolVarP(&globalStateless, "stateless", "S", false, "Read from --db (a .jsonl export or standalone .sqlite) with project scoping off; never writes to your project DB")
	f.StringVar(&globalGlobDB, "glob-db", "", "Read across a glob of result files merged into one temporary DB; implies -S")
	registerAgentJSONFlags(f)
	registerJSONOutputFlag(scanDiffCmd)
}

// scanDiffViewFields is the --fields vocabulary of a diff item: the finding view
// plus the diff's own keys.
var scanDiffViewFields = append(append([]string{}, findingViewFields...), "change", "first_seen_scan")

func runScanDiff(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	if err := validateAgentViewFlags(agentViewOptionsFromFlags(), scanDiffViewFields); err != nil {
		return err
	}
	if err := validateJSONOutputFlag(cmd); err != nil {
		return err
	}
	if _, err := enableReadTSV(cmd); err != nil {
		return err
	}
	if scanDiffFailOnNew != "" {
		scanDiffFailOnNew = normalizeSeverity(scanDiffFailOnNew)
		if severityRank(scanDiffFailOnNew) == 0 {
			return usageErrorf("invalid --fail-on-new %q (want one of: %s)", scanDiffFailOnNew, strings.Join(severityOrder, ", "))
		}
	}
	byTarget := strings.TrimSpace(scanDiffTarget) != ""
	switch {
	case byTarget && len(args) > 0:
		return usageErrorf("scan diff takes either two scans or --target <url>, not both")
	case byTarget && scanDiffLast < 2:
		return usageErrorf("--last must be at least 2 (got %d): it counts back from the most recent scan", scanDiffLast)
	case !byTarget && cmd.Flags().Changed("last"):
		return usageErrorf("--last needs --target <url>")
	case !byTarget && len(args) != 2:
		return usageErrorf("scan diff needs two scans (e.g. `vigolium scan diff previous latest`) or --target <url> --last 2")
	}

	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return err
	}
	db, err := openReadDB(globDBSkipSet{Records: true, RecordFileMap: true})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	repo := database.NewRepository(db)
	ctx := context.Background()

	var diff *database.ScanDiff
	if len(args) == 2 && isBaselineFileRef(args[0]) {
		head, rerr := repo.ResolveScanRef(ctx, projectUUID, args[1])
		if errors.Is(rerr, database.ErrScanNotFound) {
			return clicommon.NewCodedError(apicontract.CodeScanNotFound, rerr)
		}
		if rerr != nil {
			return rerr
		}
		if diff, err = diffAgainstBaselineFile(ctx, repo, projectUUID, args[0], head); err != nil {
			return err
		}
	} else {
		base, head, rerr := resolveDiffScans(ctx, repo, projectUUID, args)
		if rerr != nil {
			return rerr
		}
		if base.UUID == head.UUID {
			return usageErrorf("scan diff compares two different scans; both resolved to %s", base.UUID)
		}
		diff, err = repo.DiffScans(ctx, database.ScanDiffOptions{
			ProjectUUID:      projectUUID,
			Base:             base,
			Head:             head,
			IncludeDismissed: scanDiffIncludeDismissed,
		})
		if err != nil {
			return fmt.Errorf("scan diff: %w", err)
		}
	}
	ignore, err := loadIgnoreFile(scanIgnoreFile, time.Now())
	if err != nil {
		return asUsageError(err)
	}
	applyIgnoreToDiff(diff, ignore)

	if globalJSON || readTSV {
		err = writeScanDiffJSON(cmd, diff, projectUUID)
	} else {
		printScanDiff(diff)
	}
	if err != nil {
		return err
	}
	return scanDiffGate(diff)
}

// resolveDiffScans turns the positional scan references (or --target/--last)
// into the base and head scan rows, both inside the project.
func resolveDiffScans(ctx context.Context, repo *database.Repository, projectUUID string, args []string) (*database.Scan, *database.Scan, error) {
	if target := strings.TrimSpace(scanDiffTarget); target != "" {
		scans, err := repo.ScansForTarget(ctx, projectUUID, target, scanDiffLast)
		if err != nil {
			return nil, nil, err
		}
		if len(scans) < scanDiffLast {
			return nil, nil, codedErrorf(apicontract.CodeScanNotFound,
				"--target %s --last %d: found %d finished scan(s) of that target in scope, need %d", target, scanDiffLast, len(scans), scanDiffLast)
		}
		return scans[scanDiffLast-1], scans[0], nil
	}
	resolve := func(ref string) (*database.Scan, error) {
		s, err := repo.ResolveScanRef(ctx, projectUUID, ref)
		if errors.Is(err, database.ErrScanNotFound) {
			return nil, clicommon.NewCodedError(apicontract.CodeScanNotFound, err)
		}
		return s, err
	}
	base, err := resolve(args[0])
	if err != nil {
		return nil, nil, err
	}
	head, err := resolve(args[1])
	if err != nil {
		return nil, nil, err
	}
	return base, head, nil
}

// scanDiffGate trips --fail-on-new: a gate result (exit 4), returned only after
// the diff was written.
func scanDiffGate(diff *database.ScanDiff) error {
	if scanDiffFailOnNew == "" {
		return nil
	}
	threshold := severityRank(scanDiffFailOnNew)
	n := 0
	for _, e := range diff.Entries {
		if e.Change == database.DiffNew && severityRank(e.Finding.Severity) >= threshold {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	//vigolium:not-usage gate result (exit 4), not a usage error
	return gateError{err: fmt.Errorf("--fail-on-new %s: %d new finding(s) at or above it", scanDiffFailOnNew, n)}
}

// scanDiffSideView is the summary of one side of the diff (base, head).
type scanDiffSideView struct {
	UUID         string `json:"uuid"`
	Status       string `json:"status"`
	Target       string `json:"target"`
	StartedAt    string `json:"started_at"`
	Completeness string `json:"completeness,omitempty"`
	FinishedAt   string `json:"finished_at,omitempty"`
}

// scanDiffScanView is the summary of one side of the diff.
func scanDiffScanView(s *database.Scan) scanDiffSideView {
	v := scanDiffSideView{
		UUID:         s.UUID,
		Status:       s.Status,
		Target:       s.Target,
		StartedAt:    agentTimestamp(s.StartedAt),
		Completeness: s.Completeness,
	}
	if !s.FinishedAt.IsZero() {
		v.FinishedAt = agentTimestamp(s.FinishedAt)
	}
	return v
}

func writeScanDiffJSON(cmd *cobra.Command, diff *database.ScanDiff, projectUUID string) error {
	opts := agentViewOptionsFromFlags()
	items := make([]map[string]any, 0, len(diff.Entries))
	for _, e := range diff.Entries {
		v := compactFindingView(e.Finding, nil, opts)
		// change is the point of the row; a --fields projection never drops it.
		v["change"] = e.Change
		if e.FirstSeenScan != "" && (len(opts.fields) == 0 || slices.Contains(opts.fields, "first_seen_scan")) {
			v["first_seen_scan"] = e.FirstSeenScan
		}
		items = append(items, v)
	}
	reasons := diff.ComparabilityReasons
	if reasons == nil {
		reasons = []string{}
	}
	page, err := pageFromOffset(items, inMemoryOffset)
	if err != nil {
		return err
	}
	return emitRead(cmd, "", page, int64(len(items)), inMemoryOffset, len(page),
		withExtra("base", scanDiffScanView(diff.Base)),
		withExtra("head", scanDiffScanView(diff.Head)),
		withExtra("comparable", diff.Comparable),
		withExtra("comparability_reasons", reasons),
		withExtra("history", diff.History),
		withExtra("counts", diff.Counts),
		withExtra("include_dismissed", scanDiffIncludeDismissed),
		withProjectScope(projectUUID),
		withDBPath(resolvedReadDBPath()),
	)
}

func printScanDiff(diff *database.ScanDiff) {
	side := func(label string, s *database.Scan) {
		state := s.Status
		if s.Completeness != "" {
			state += ", " + s.Completeness
		}
		fmt.Printf("  %s %s  %s  %s (%s)\n", terminal.Gray(label), terminal.Cyan(s.UUID),
			s.StartedAt.Local().Format("2006-01-02 15:04"), clicommon.Truncate(s.Target, 60), state)
	}
	fmt.Printf("%s Scan diff\n", terminal.InfoSymbol())
	side("base", diff.Base)
	side("head", diff.Head)
	if diff.Comparable {
		fmt.Printf("  %s comparable: absent findings are reported as fixed\n", terminal.Gray("·"))
	} else {
		fmt.Printf("  %s not comparable (%s): absent findings are reported as not_reobserved\n",
			terminal.WarningSymbol(), strings.Join(diff.ComparabilityReasons, ", "))
	}
	if diff.History == database.DiffHistoryPartial {
		fmt.Printf("  %s history partial: a scan predates per-scan observation history; re-detections before it may be missing\n", terminal.WarningSymbol())
	}
	var counts []string
	for _, c := range database.DiffChanges {
		counts = append(counts, fmt.Sprintf("%s:%d", c, diff.Counts[c]))
	}
	fmt.Printf("  %s %s\n\n", terminal.Gray("·"), strings.Join(counts, "  "))
	if len(diff.Entries) == 0 {
		fmt.Printf("%s Neither scan observed a finding in scope.\n", terminal.InfoSymbol())
		return
	}

	headers := []string{"CHANGE", "ID", "SEVERITY", "MODULE", "URL", "STATUS"}
	weights := []int{14, 6, 10, 30, 60, 14}
	tbl := terminal.NewTableFullWidthWeighted(terminal.TerminalWidth(), weights, headers...)
	for _, e := range diff.Entries {
		f := e.Finding
		status := f.Status
		if status == "" {
			status = database.StatusTriaged
		}
		tbl.AddRow(colorDiffChange(e.Change), fmt.Sprintf("%d", f.ID), clicommon.ColorSeverity(f.Severity),
			clicommon.Truncate(f.ModuleName, 30), clicommon.Truncate(findingURLValue(f), 60), status)
	}
	tbl.Print()
	fmt.Println()
}

func colorDiffChange(c string) string {
	switch c {
	case database.DiffNew:
		return terminal.BoldRed(c)
	case database.DiffFixed:
		return terminal.Green(c)
	case database.DiffNotReobserved:
		return terminal.BoldYellow(c)
	}
	return terminal.Gray(c)
}

// scanUUIDShape matches a full scan/record UUID.
var scanUUIDShape = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// rejectUUIDScanTargets refuses a UUID-shaped positional target on `scan`.
//
// `scan` takes target URLs positionally and also has subcommands, so a typo in
// the subcommand name (`scan staus <uuid>`) would otherwise start a scan of two
// hosts named "staus" and "<uuid>". Only the UUID is rejected — a bare word
// like `scan intranet` is a legitimate host — because no one scans a host
// whose name is a UUID, while everyone who types one meant a subcommand.
func rejectUUIDScanTargets(cmd *cobra.Command, args []string) error {
	for _, a := range args {
		if !scanUUIDShape.MatchString(strings.TrimSpace(a)) {
			continue
		}
		return clicommon.CLIError{
			Err:       fmt.Errorf("%q looks like a scan UUID, not a target URL", a),
			Hint:      scanUUIDVerbsHint,
			UsageArgv: clicommon.UsageArgvFor("scan"),
		}
	}
	return nil
}

// scanUUIDVerbsHint names what can be done with a scan UUID.
const scanUUIDVerbsHint = "Read it: vigolium scan status <uuid>; wait for it: vigolium scan wait <uuid>; " +
	"compare two: vigolium scan diff <a> <b>; its log: vigolium log <uuid>; stop it: vigolium scan stop <uuid>."

// scanVerbTargets maps a bare word that is a verb, typed where `scan` expects a
// target, to the command the caller meant. `vigolium scan ls` used to start a
// real scan of http://ls.
var scanVerbTargets = map[string]string{
	"ls":     "vigolium scan ls",
	"list":   "vigolium scan ls",
	"ps":     "vigolium scan ls",
	"show":   "vigolium scan status <uuid>",
	"logs":   "vigolium log <uuid>",
	"stop":   "vigolium scan stop <uuid>",
	"cancel": "vigolium scan stop <uuid>",
	"kill":   "vigolium scan stop <uuid>",
	"pause":  "POST /api/scans/<uuid>/pause on the server that runs the scan (pause is server-only)",
	"resume": "POST /api/scans/<uuid>/resume on the server that runs the scan (resume is server-only)",
	"rm":     "vigolium db clean --scan-uuid <uuid>",
}

// rejectVerbScanTargets refuses a bare word that is a verb, where `scan`
// expects a target. A URL (`http://ls`) or a host with a dot or port is still a
// target; so is any other bare word (`scan intranet`). A near miss of a scan
// subcommand is caught by the command tree's group hook.
func rejectVerbScanTargets(args []string) error {
	for _, a := range args {
		meant, ok := scanVerbTargets[strings.ToLower(strings.TrimSpace(a))]
		if !ok {
			continue
		}
		return clicommon.CLIError{
			Err:       fmt.Errorf("%q is a verb, not a scan target; scan has no %q subcommand", a, strings.ToLower(a)),
			Hint:      "Use: " + meant + ". To scan a host with that name, pass it as a URL (http://" + a + ")",
			UsageArgv: clicommon.UsageArgvFor("scan"),
		}
	}
	return nil
}
