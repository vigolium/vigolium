package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/scanplan"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// printScanSummary prints a human-readable scan configuration overview to stderr.
// progressFile, when non-empty, is the resume progress manifest written by the
// stateless parallel fan-out; it is appended to the Output line so the operator
// can see (and resume from) it. Empty for every other scan mode.
func printScanSummary(opts *types.Options, settings *config.Settings, strategyName string, repo *database.Repository, progressFile string) {
	if opts.Silent || globalJSON || globalCIOutput {
		return
	}

	// Credit the discovery co-authors when the run is discovery/spidering-only
	// (e.g. `vigolium run discover` or `vigolium scan --only discovery`).
	// Through emitBanner, so the once-guard covers this and the root hook
	// together: whichever runs first wins and the other is a no-op, with no
	// annotation or command list keeping them apart.
	if isDiscoveryOnlyPhases(opts.OnlyPhase) {
		emitBanner(GetDiscoveryBanner())
	} else {
		emitBanner(GetBanner())
	}

	// The banner renders from the scan plan — the same object scan --dry-run
	// prints and the runner emits as scan.plan — so its phases, targets and
	// module counts are the ones the run uses (the module counts include the
	// tier, risk and hygiene gates, which an ad-hoc count here used to miss).
	plan, planErr := resolveCLIScanPlan(nil, opts, settings, strategyName, repo, false)
	if planErr != nil {
		plan = nil
	}
	phaseOn := func(id runner.NativePhase, fallback bool) bool {
		if plan == nil {
			return fallback
		}
		ph := plan.Phase(string(id))
		return ph != nil && ph.Enabled
	}
	discoveryEnabled := phaseOn(runner.PhaseDiscovery, opts.DiscoverEnabled)
	spideringEnabled := phaseOn(runner.PhaseSpidering, opts.SpideringEnabled)
	knownIssueScanEnabled := phaseOn(runner.PhaseKnownIssueScan, opts.KnownIssueScanEnabled)
	daEnabled := phaseOn(runner.PhaseDynamicAssessment, !opts.SkipDynamicAssessment)
	ehEnabled := phaseOn(runner.PhaseExternalHarvest, opts.ExternalHarvestEnabled)

	// Strategy name
	strategy := strategyName
	if strategy == "" {
		strategy = "default"
	}

	// Scope origin mode
	scopeOrigin := config.ResolveCLIOriginMode(settings.Scope.CLIOriginMode)

	fmt.Fprintf(os.Stderr, "\n  %s %s %s %s %s %s\n",
		terminal.TipPrefix(), terminal.Gray("run"), terminal.HiCyan("vigolium traffic list"), terminal.Gray("and"), terminal.HiCyan("vigolium findings list"), terminal.Gray("to view ingested data and vulnerabilities"))
	fmt.Fprintf(os.Stderr, "  %s %s %s %s\n",
		terminal.TipPrefix(), terminal.Gray("run each phase separately via"), terminal.HiCyan("vigolium run <phase>"), terminal.Gray("(e.g. vigolium run dynamic-assessment)"))
	fmt.Fprintf(os.Stderr, "  %s %s %s %s\n\n",
		terminal.TipPrefix(), terminal.Gray("skip phases you don't need via"), terminal.HiCyan("--skip <phase>"), terminal.Gray("(e.g. --skip discovery,known-issue-scan)"))
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.Green(terminal.SymbolStart), terminal.BoldHiBlue("Native Scan Configuration"))
	// In stateless mode the scan lives in a throwaway database, so the UUID
	// can't be used to query results later — printing it is just noise.
	if opts.ScanUUID != "" && !opts.Stateless {
		fmt.Fprintf(os.Stderr, "  %s Scan ID: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(opts.ScanUUID))
	}
	if opts.Stateless {
		statelessLine := "Stateless mode: using temporary database"
		if globalVerbose && settings.Database.SQLite.Path != "" {
			statelessLine += " " + terminal.Gray("("+settings.Database.SQLite.Path+")")
		}
		fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), statelessLine)
	}
	if opts.DBIsolate {
		dest := dbIsolateDestPath
		if dest == "" {
			dest = "--db"
		}
		isolateLine := "DB isolation: scanning into a private temporary database, merged into " +
			terminal.HiTeal(dest) + " at the end"
		if globalVerbose && settings != nil && settings.Database.SQLite.Path != "" {
			isolateLine += " " + terminal.Gray("(scratch: "+settings.Database.SQLite.Path+")")
		}
		fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), isolateLine)
	}
	// Only surface the project when it's a real, operator-chosen one. The
	// auto-created default project is implementation noise, and in stateless
	// mode the project lives in a throwaway database anyway.
	if opts.ProjectUUID != "" && opts.ProjectUUID != database.DefaultProjectUUID && !opts.Stateless {
		fmt.Fprintf(os.Stderr, "  %s Project: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(opts.ProjectUUID))
	}
	fmt.Fprintf(os.Stderr, "  %s Strategy: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(strategy))
	if opts.ScanningProfile != "" {
		fmt.Fprintf(os.Stderr, "  %s Profile: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(opts.ScanningProfile))
	}
	// The headline count is every target the scan will actually seed, CLI and
	// -T file alike. Counting only the CLI ones reported "Targets: 0" for a run
	// driven entirely by a target file, which reads as though nothing was found.
	fileTargets := countTargetFileTargets(opts.TargetsFilePaths)
	seededTargets := len(opts.Targets) + fileTargets
	if plan != nil && plan.Targets.Seeded > 0 {
		seededTargets, fileTargets = plan.Targets.Seeded, plan.Targets.FromFiles
	}
	targetsLine := fmt.Sprintf("Targets: %s", terminal.Orange(fmt.Sprintf("%d", seededTargets)))
	if len(opts.Targets) > 0 {
		targetsLine += fmt.Sprintf(" (CLI: %s)", terminal.HiBlue(summarizeTargetList(opts.Targets, 3)))
	}
	if len(opts.TargetsFilePaths) > 0 {
		label := "file"
		if len(opts.TargetsFilePaths) > 1 {
			label = "files"
		}
		targetsLine += fmt.Sprintf(" (+%d from %s: %s)", fileTargets, label, terminal.HiTeal(strings.Join(opts.TargetsFilePaths, ", ")))
	}
	if repo != nil {
		ctx := context.Background()
		// Scoped to this run's project. Unscoped, this counted every project in
		// the store and printed the total on the Targets line, which reads as
		// "these records are input for this scan" — they are not, and a
		// project-scoped scan cannot even see them.
		dbCount, err := repo.CountRecordsAfterCursor(ctx, opts.ProjectUUID, time.Time{}, "")
		switch {
		case err == nil && globalAllRecords:
			// Under --all-records the stored records ARE the input, so say so
			// instead of "Targets: 0".
			targetsLine = fmt.Sprintf("All records: %s HTTP records in the %s",
				terminal.Orange(fmt.Sprintf("%d", dbCount)), describeScanStore(settings, opts.ProjectUUID))
		case err == nil && dbCount > 0:
			targetsLine += fmt.Sprintf(" | %s (HTTP Records)", terminal.Orange(fmt.Sprintf("%d", dbCount)))
		}
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolTarget), targetsLine)
	printTargetAdmission(os.Stderr, opts.TargetAdmission)
	fmt.Fprintf(os.Stderr, "  %s Phases: %s | %s | %s\n",
		terminal.Purple(terminal.SymbolInfo),
		runner.PhaseLabel(settings, "ExternalHarvest", "external_harvester", ehEnabled, 0),
		runner.PhaseLabel(settings, "Spidering", "spidering", spideringEnabled, runner.SpideringBudget(settings, opts)),
		runner.PhaseLabel(settings, "Discovery", "discovery", discoveryEnabled, runner.DiscoveryBudget(settings, opts)))
	fmt.Fprintf(os.Stderr, "           %s | %s\n",
		runner.PhaseLabel(settings, "KnownIssueScan", "known-issue-scan", knownIssueScanEnabled, 0),
		runner.PhaseLabel(settings, "DynamicAssessment", "dynamic-assessment", daEnabled, 0))
	// Total scan-duration budget (from --scanning-max-duration). The per-phase
	// durations above are factor-scaled slices of this cap and share it — the
	// whole scan is bounded by it. Under a parallel fan-out (-P > 1) each target
	// is an isolated child process with its own budget, so the cap applies per
	// target line, not across the whole batch.
	if opts.ScanMaxDuration > 0 {
		budgetLine := "Max scan duration: " + terminal.HiBlue(opts.ScanMaxDuration.String())
		if opts.Parallel > 1 {
			budgetLine += " " + terminal.Gray("per target line (each -P child runs its own budget)")
		} else {
			budgetLine += " " + terminal.Gray("(whole scan, all phases share this budget)")
		}
		fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), budgetLine)
	}
	heuristicsDesc := map[string]string{
		"basic":    "probe target root pages to detect content type (HTML, JSON, blank) and skip spidering for non-HTML targets",
		"advanced": "basic checks + deep HTML analysis to detect SPA frameworks and optimize phase selection",
		"none":     "skip all heuristic probes, run all enabled phases unconditionally",
	}
	if desc, ok := heuristicsDesc[opts.HeuristicsCheck]; ok {
		fmt.Fprintf(os.Stderr, "  %s Heuristics: %s %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(opts.HeuristicsCheck),
			terminal.Gray(desc))
	} else {
		fmt.Fprintf(os.Stderr, "  %s Heuristics: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(opts.HeuristicsCheck))
	}
	fmt.Fprintf(os.Stderr, "  %s Speed: concurrency=%s | rate-limit=%s | max-per-host=%s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiBlue(fmt.Sprintf("%d", opts.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", opts.RateLimit)),
		terminal.HiBlue(fmt.Sprintf("%d", opts.MaxPerHost)))
	// Under a parallel fan-out (-P > 1), surface the per-process heap ceiling the
	// isolated child scans inherit. A single scan omits it — the ceiling is rarely
	// worth a line when only one process runs.
	if opts.Parallel > 1 {
		if line := heapCeilingConfigLine(scanHeapCeiling); line != "" {
			fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), line)
		}
	}
	originDesc := map[string]string{
		"relaxed":  "host must contain the target's keyword (e.g. \"example\")",
		"all":      "no origin restriction, all hosts are in scope",
		"balanced": "host must share the target's eTLD+1 (e.g. *.example.com)",
		"strict":   "host must exactly match the target host",
	}
	originDescStr := ""
	if desc, ok := originDesc[scopeOrigin]; ok {
		originDescStr = " " + terminal.Gray(desc)
	}
	fmt.Fprintf(os.Stderr, "  %s Scope: origin=%s | ignore-static=%s%s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiPurple(scopeOrigin),
		terminal.HiPurple(fmt.Sprintf("%v", settings.Scope.IgnoreStaticFile)),
		originDescStr)
	fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), modulesBannerLine(plan, opts, settings))
	if plan != nil {
		fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), estimateBannerLine(plan))
	}
	// Output destination & format(s) — shown when -o or a non-default --format
	// is in play so it's clear where (and in what shape) results land.
	formats := opts.OutputFormats
	if len(formats) == 0 {
		formats = []string{"console"}
	}
	isDefaultFormat := len(formats) == 1 && formats[0] == "console"
	if opts.Output != "" || !isDefaultFormat {
		formatStr := strings.Join(formats, ", ")
		dest := "stdout"
		if opts.Output != "" {
			base := types.StripFormatExtension(opts.Output)
			seen := make(map[string]struct{}, len(formats))
			paths := make([]string, 0, len(formats))
			for _, f := range formats {
				p := types.FormatOutputPath(base, f)
				if p == "" {
					continue
				}
				if _, dup := seen[p]; dup {
					continue
				}
				seen[p] = struct{}{}
				paths = append(paths, p)
			}
			if len(paths) > 0 {
				dest = strings.Join(paths, ", ")
			}
		}
		// Surface the resume progress manifest (stateless parallel fan-out) on the
		// same line so the operator can see where progress is checkpointed and what
		// --resume reads. Appended after the per-host output files.
		if progressFile != "" {
			if dest == "stdout" {
				dest = progressFile
			} else {
				dest += ", " + progressFile
			}
		}
		fmt.Fprintf(os.Stderr, "  %s Output: %s %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(dest),
			terminal.Gray("(format: "+formatStr+")"))
	}
	// The spidering fan-out hint. Placed with the tips rather than beside the
	// Phases line because it is advice, not configuration — and printed before
	// the verbose-only block so it lands whether or not -v is on.
	printSpiderFanOutTip(opts, seededTargets)
	if globalVerbose {
		fmt.Fprintf(os.Stderr, "\n  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("view scope details via"), terminal.HiCyan("vigolium config ls scope"))
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("view scanning pace via"), terminal.HiCyan("vigolium config ls scanning_pace"))
		if knownIssueScanEnabled && !settings.KnownIssueScan.EnrichTargets {
			fmt.Fprintf(os.Stderr, "  %s %s %s\n",
				terminal.TipPrefix(), terminal.Gray("enrich KnownIssueScan targets with discovered paths via"), terminal.HiCyan("vigolium config set known_issue_scan.enrich_targets true"))
		}
	}
	fmt.Fprintln(os.Stderr)
}

// modulesBannerLine renders the banner's module line from the plan: the
// modules that run, the extensions, and what the hardening-advisory, tier and
// risk gates hold back. Without a plan it falls back to the hygiene-adjusted
// selection count.
func modulesBannerLine(plan *scanplan.Plan, opts *types.Options, settings *config.Settings) string {
	if plan == nil {
		var activeMods []modules.ActiveModule
		if len(opts.Modules) > 0 && opts.Modules[0] == "all" {
			activeMods = modules.GetActiveModules()
		} else {
			activeMods = modules.GetActiveModulesByIDs(opts.Modules)
		}
		a, p, note := runner.HygieneBannerCounts(opts, settings, activeMods, modules.GetPassiveModules())
		line := fmt.Sprintf("Modules: %s active, %s passive", terminal.Orange(fmt.Sprintf("%d", a)), terminal.Orange(fmt.Sprintf("%d", p)))
		if note != "" {
			line += " " + note
		}
		return line
	}
	m := plan.Modules
	line := fmt.Sprintf("Modules: %s active, %s passive",
		terminal.Orange(fmt.Sprintf("%d", m.Active)),
		terminal.Orange(fmt.Sprintf("%d", m.Passive)))
	if settings != nil && settings.DynamicAssessment.Extensions.Enabled {
		line += fmt.Sprintf(" + %s extensions", terminal.HiTeal(fmt.Sprintf("%d", m.Extensions)))
	}
	if m.HygieneSuppressed > 0 {
		// Point at the knob that is actually holding them back: --intensity
		// deep does nothing when the config already forced them off.
		hint := "--intensity deep or --module-tag hygiene to include"
		if settings != nil && settings.DynamicAssessment.HygieneModules != nil {
			hint = "off via dynamic-assessment.hygiene_modules"
		}
		line += " " + terminal.Gray(fmt.Sprintf("(%d hardening advisories off; %s)", m.HygieneSuppressed, hint))
	}
	var held []string
	if m.TierFiltered > 0 {
		held = append(held, fmt.Sprintf("%d above the %s tier", m.TierFiltered, m.TierCeiling))
	}
	if m.RiskGated > 0 {
		held = append(held, fmt.Sprintf("%d risk:high withheld", m.RiskGated))
	}
	if len(held) > 0 {
		line += " " + terminal.Gray("("+strings.Join(held, ", ")+")")
	}
	return line
}

// estimateBannerLine renders the plan's rough request estimate.
func estimateBannerLine(plan *scanplan.Plan) string {
	e := plan.Estimate
	line := fmt.Sprintf("Estimate: %s requests %s", terminal.Orange(formatRange(e.Low, e.High)), terminal.Gray("("+e.Confidence+"; vigolium scan --dry-run for the breakdown)"))
	if e.CeilingByPace != nil {
		line = fmt.Sprintf("Estimate: at most %s requests by pace, %s expected %s",
			terminal.Orange(fmt.Sprintf("%d", *e.CeilingByPace)), terminal.Orange(formatRange(e.Low, e.High)),
			terminal.Gray("("+e.Confidence+"; vigolium scan --dry-run for the breakdown)"))
	}
	if d := e.DurationMS; d != nil && d.High > 0 {
		line += fmt.Sprintf(", %s %s", terminal.Orange("~"+formatDurationRange(d.Low, d.High)), terminal.Gray("("+d.Confidence+")"))
	}
	return line
}

// formatDurationRange renders a rough millisecond range as "2m-15m".
func formatDurationRange(lowMS, highMS int64) string {
	round := func(ms int64) string {
		sec := (ms + 500) / 1000
		switch {
		case sec < 60:
			return fmt.Sprintf("%ds", sec)
		case sec < 3600:
			return fmt.Sprintf("%dm", (sec+30)/60)
		default:
			m := (sec + 30) / 60
			return fmt.Sprintf("%dh%02dm", m/60, m%60)
		}
	}
	lo, hi := round(lowMS), round(highMS)
	if lo == hi {
		return hi
	}
	return lo + "-" + hi
}

// countExtensionFiles counts JS/TS/YAML extension files from the configured directories without loading them.
func countExtensionFiles(cfg *config.ExtensionsConfig) int {
	count := len(cfg.CustomDir)

	if cfg.ExtensionDir != "" {
		dir := config.ExpandPath(cfg.ExtensionDir)
		if entries, err := os.ReadDir(dir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				name := entry.Name()
				if strings.HasSuffix(name, ".d.ts") {
					continue
				}
				if strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".ts") || strings.HasSuffix(name, ".vgm.yaml") {
					count++
				}
			}
		}
	}

	return count
}

// summaryScopeHosts returns the in-scope (scheme, hostname, port) origins present in the
// project's DB for the given CLI targets, delegating to Repository.InScopeHosts (the same
// scoping the runner phases use). With no targets (or no settings/repo) it returns nil —
// meaning "no filter", a project-wide pass. The scan-completion summary uses this so its
// counts cover only the origins actually scanned, not leftovers from prior scans of other
// origins in the project.
func summaryScopeHosts(ctx context.Context, repo *database.Repository, settings *config.Settings, targets []string, projectUUID, scanUUID string) []database.HostTarget {
	if repo == nil || settings == nil {
		return nil
	}
	return repo.InScopeHosts(ctx, settings.Scope, targets, projectUUID, scanUUID)
}

// printScanCompletionSummary prints a compact summary of ingested records,
// findings, and total wall-clock duration after scan completion. The record count is
// scoped to the in-scope origins (scheme/host/port), so it reflects the current
// scan's targets rather than the whole project.
//
// The finding count is THIS scan's (repository.ScanFindingTotal), the same figure
// the runner's "Scan finished … findings: N" banner prints and the --fail-on gate
// judges. It used to be a project-wide count over the in-scope hostnames, which
// disagreed with the banner a line above it on any project with earlier scans.
// Without a scan id it falls back to that host-scoped count.
func printScanCompletionSummary(repo *database.Repository, projectUUID, scanUUID string, hosts []database.HostTarget, elapsed time.Duration) {
	// Header line carries the total wall-clock duration, so it prints first and
	// unconditionally: even if the count queries below fail, the operator still
	// sees the completion banner and how long the run took.
	headline := "Native scan completed"
	if scanWasInterrupted() {
		headline = "Native scan interrupted"
	}
	fmt.Fprintf(os.Stderr, "\n%s %s %s%s\n",
		terminal.Aqua(terminal.SymbolSparkle),
		terminal.BoldAqua(headline),
		terminal.Gray("in "),
		terminal.Magenta(elapsed.Round(time.Second).String()))

	if repo == nil {
		return
	}

	ctx := context.Background()

	// Records line, with the status-class breakdown (2xx/3xx/4xx/5xx…) appended
	// inline, both scoped to this project and the in-scope origins — the same
	// scope as the findings count below, so every line of the summary describes
	// one population.
	//
	// The total comes from summing the breakdown rather than from a second query.
	// The classes cover exactly the rows the count would, so they sum to it by
	// construction, and one grouped scan is cheaper than a scan plus a count
	// (measured at 200k records: 22.9ms versus 28.2ms). CountRecordsAfterCursor
	// is the fallback for when the group-by fails, since the total is the part
	// the operator needs and the breakdown is decoration.
	var recordCount int64
	byCode, err := repo.CountRecordsByStatusCode(ctx, projectUUID, hosts...)
	classes := ""
	if err == nil {
		for _, n := range byCode {
			recordCount += n
		}
		classes = formatStatusClassLine(bucketStatusCounts(byCode))
	} else if recordCount, err = repo.CountRecordsAfterCursor(ctx, projectUUID, time.Time{}, "", hosts...); err != nil {
		return
	}

	recordsLine := fmt.Sprintf("  %s Records: %s http records ingested",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Cyan(fmt.Sprintf("%d", recordCount)))
	if classes != "" {
		recordsLine += terminal.Gray(" — ") + classes
	}
	fmt.Fprintln(os.Stderr, recordsLine)

	totalFindings, counts, err := summaryFindingCounts(ctx, repo, projectUUID, scanUUID, hosts)
	if err != nil {
		return
	}

	defer printSummaryTail(scanUUID, resolvedSummaryDBPath(), totalFindings, !globalStateless)
	if totalFindings == 0 {
		fmt.Fprintf(os.Stderr, "  %s Findings: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.Gray("no issues found"))
		return
	}
	defer printSummaryFindingsTable(ctx, repo, projectUUID, scanUUID, totalFindings)

	// Build severity breakdown
	var parts []string
	for _, s := range []struct {
		key string
		fn  func(string) string
		sym func() string
	}{
		{"critical", terminal.BoldMagenta, terminal.CriticalSymbol},
		{"high", terminal.BoldRed, terminal.HighSymbol},
		{"medium", terminal.BoldYellow, terminal.MediumSymbol},
		{"low", terminal.BoldGreen, terminal.LowSymbol},
		{"suspect", terminal.BoldCyan, terminal.SuspectSymbol},
		{"info", terminal.BoldBlue, terminal.InfoSeveritySymbol},
	} {
		if c, ok := counts[s.key]; ok && c > 0 {
			parts = append(parts, fmt.Sprintf("%s %s %s", s.sym(), s.fn(fmt.Sprintf("%d", c)), s.key))
		}
	}

	fmt.Fprintf(os.Stderr, "  %s Findings: %s issues found — %s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Orange(fmt.Sprintf("%d", totalFindings)),
		strings.Join(parts, ", "))
}

// summaryFindingCounts is the completion summary's finding total and severity
// breakdown: the scan's own (shared with the runner's banner) when there is a
// scan id, else the project's findings on the in-scope hostnames.
func summaryFindingCounts(ctx context.Context, repo *database.Repository, projectUUID, scanUUID string, hosts []database.HostTarget) (int64, map[string]int64, error) {
	if scanUUID != "" {
		total, tally, err := repo.ScanFindingTotal(ctx, scanUUID)
		if err != nil {
			return 0, nil, err
		}
		counts := make(map[string]int64, len(tally))
		for k, v := range tally {
			counts[k] = int64(v)
		}
		return int64(total), counts, nil
	}
	counts, err := database.CountFindingsBySeverity(ctx, repo.DB(), projectUUID, database.HostnamesOf(hosts)...)
	if err != nil {
		return 0, nil, err
	}
	var total int64
	for _, c := range counts {
		total += c
	}
	return total, counts, nil
}

// resolvedSummaryDBPath is the store the completion summary names under
// "Stored:" ("" when it cannot be named, e.g. a non-SQLite driver).
func resolvedSummaryDBPath() string {
	return resolvedReadDBPath()
}
