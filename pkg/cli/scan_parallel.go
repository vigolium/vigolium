package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// parallelSocketWarnThreshold is the rough number of simultaneous in-flight
// requests (Parallel × per-target Concurrency) above which we warn the operator
// that the fan-out may open a lot of sockets at once.
const parallelSocketWarnThreshold = 200

// childExitGrace is how long a child gets to shut down gracefully after the
// parent forwards SIGINT (e.g. on Ctrl-C) before the OS hard-kills it. Children
// remove their temporary stateless database on a clean SIGINT, so the grace
// window lets that cleanup run.
const childExitGrace = 10 * time.Second

// validateParallelScan rejects -P/--parallel values that the fan-out can't
// honor. Parallel fan-out needs each concurrent child fully isolated — sharing a
// DB writer or an output file across processes would corrupt them — so it is
// gated to one of the two combinations that guarantee isolation:
//
//   - stateless  (-S -T --split-by-host): each target gets its own throwaway DB
//     and its own per-host output file; nothing is shared.
//   - db-isolate (--db-isolate -T): each target scans into its own private
//     scratch DB and merges into the shared --db under a cross-process lock, and
//     the parent exports a single unified output from that merged DB at the end
//     (so no --split-by-host is needed — there are no per-host files to collide).
//
// Anything else would share a DB or an output file across concurrent scans, so
// it is rejected up front rather than silently serialized.
func validateParallelScan(opts *types.Options) error {
	if opts.Parallel < 1 {
		return fmt.Errorf("--parallel must be >= 1 (got %d)", opts.Parallel)
	}
	if opts.Parallel <= 1 {
		return nil
	}
	statelessOK := opts.Stateless && opts.TargetsFilePath != "" && opts.SplitByHost
	isolateOK := opts.DBIsolate && opts.TargetsFilePath != ""
	if !statelessOK && !isolateOK {
		return fmt.Errorf("--parallel > 1 requires either --stateless (-S) -T --split-by-host, or --db-isolate -T (results merge into --db)")
	}
	return nil
}

// targetResult records the outcome of one child scan in the fan-out.
type targetResult struct {
	target   string
	output   string
	console  string
	err      error
	duration time.Duration
	stats    childStats
	statsOK  bool
}

// childStats are the per-target counts the parent recovers from a child's JSONL
// output once it finishes: HTTP records ingested, findings, and a severity
// breakdown. Only populated when jsonl is among the requested formats.
type childStats struct {
	records  int
	findings int
	sev      map[string]int
}

// readChildStats counts a child's HTTP records and findings (by severity) from
// its per-target JSONL output. The unified export writes one {"type":...} JSON
// object per line, so consecutive json.Decode calls recover the counts without a
// line-length limit (response bodies can make individual lines large). Returns
// ok=false when jsonl wasn't requested or the file is missing/unreadable, so the
// caller simply omits the stats segment rather than guessing.
func readChildStats(output string, formats []string) (childStats, bool) {
	hasJSONL := false
	for _, f := range formats {
		if f == "jsonl" {
			hasJSONL = true
			break
		}
	}
	if !hasJSONL {
		return childStats{}, false
	}

	f, err := os.Open(types.StripFormatExtension(output) + ".jsonl")
	if err != nil {
		return childStats{}, false
	}
	defer func() { _ = f.Close() }()

	st := childStats{sev: make(map[string]int)}
	dec := json.NewDecoder(f)
	for {
		var env struct {
			Type string `json:"type"`
			Data struct {
				Severity string `json:"severity"`
			} `json:"data"`
		}
		if err := dec.Decode(&env); err != nil {
			break // EOF or a malformed tail — stop with what we have.
		}
		switch env.Type {
		case "http_record":
			st.records++
		case "finding":
			st.findings++
			if env.Data.Severity != "" {
				st.sev[strings.ToLower(env.Data.Severity)]++
			}
		}
	}
	return st, true
}

// runStatelessTargetsParallel scans every target in targets concurrently, up to
// scanOpts.Parallel at a time, by spawning one isolated child `vigolium scan`
// process per target. This is only reached from the -S -T --split-by-host path,
// where each target already gets its own throwaway database and its own per-host
// output file — so the children share no state, no database, and no output file,
// and the global-state hazards of in-process concurrency never arise.
//
// Each child's verbose console is captured to a per-target <output>.console.log
// so N interleaved scans do not garble the terminal; the parent prints compact
// start/done/failed lines plus a final roll-up. The batch exits non-zero only
// when every target failed (a partial success is still a success); --soft-fail
// overrides that to exit 0 for CI wrappers, just as it does for a single scan.
func runStatelessTargetsParallel(cmd *cobra.Command, settings *config.Settings, strategyName string, targets []string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate the vigolium binary for parallel fan-out: %w", err)
	}

	parallel := scanOpts.Parallel
	if parallel > len(targets) {
		parallel = len(targets)
	}

	// Print the shared scan-configuration banner once at the top — every child
	// inherits the same strategy/phases/speed/scope/modules, so showing it here
	// (instead of burying one copy per child in the per-target console logs)
	// tells the operator exactly how the whole batch will run. Targets is
	// briefly pointed at the file list so the banner's count reflects the batch,
	// and Output at the per-host pattern so it reads "roche-vig-<host>.jsonl"
	// (what children actually write) instead of the literal "roche-vig.jsonl"
	// that no file ever uses under --split-by-host.
	if !scanOpts.Silent {
		origBannerTargets := scanOpts.Targets
		origBannerOutput := scanOpts.Output
		scanOpts.Targets = targets
		scanOpts.Output = perHostOutputPattern(scanOpts.Output)
		printScanSummary(scanOpts, settings, strategyName, nil)
		scanOpts.Targets = origBannerTargets
		scanOpts.Output = origBannerOutput
		scanOpts.ScanConfigPrinted = true
	}

	// Resolve a unique output path per target up front. perTargetOutputPath
	// already inserts the sanitized host before the extension, but two target
	// lines that resolve to the same host (e.g. two paths on one origin) would
	// collide — harmless when scanning sequentially (the later one overwrites),
	// but two concurrent writers to one file corrupt it. Disambiguate any
	// collision with the target index so every child owns a distinct file.
	outputs := make([]string, len(targets))
	seen := make(map[string]int, len(targets))
	collisions := 0
	for i, target := range targets {
		path := perTargetOutputPath(scanOpts.Output, target, i)
		if seen[path] > 0 {
			path = withIndexSuffix(path, i)
			collisions++
		}
		seen[path]++
		outputs[i] = path
	}

	// The shared child flags are derived once from the command's changed flags;
	// only the per-target -t/-o differ between children.
	baseChildArgs := childScanArgs(cmd)

	if !scanOpts.Silent {
		budget := parallel * scanOpts.Concurrency
		fmt.Fprintf(os.Stderr, "\n%s %s scanning %s targets, %s at a time\n",
			terminal.Purple(terminal.SymbolTarget),
			terminal.BoldHiBlue("Parallel"),
			terminal.HiCyan(fmt.Sprintf("%d", len(targets))),
			terminal.HiCyan(fmt.Sprintf("%d", parallel)))
		if budget > parallelSocketWarnThreshold {
			fmt.Fprintf(os.Stderr, "%s ~%d requests may be in flight at once (%d targets × %d --concurrency); lower -P or --concurrency if that is too aggressive\n",
				terminal.WarnPrefix(), budget, parallel, scanOpts.Concurrency)
		}
		if collisions > 0 {
			fmt.Fprintf(os.Stderr, "%s %d target(s) resolved to a duplicate host; their output files were given an index suffix to avoid clobbering\n",
				terminal.WarnPrefix(), collisions)
		}
	}

	// A parent SIGINT/SIGTERM cancels ctx, which each child's Cancel hook turns
	// into a forwarded SIGINT (not SIGKILL) so children shut down cleanly and
	// remove their temp databases.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Each child is a plain single-target stateless scan writing its own per-host
	// output file; the parent re-adds -t/-o on top of the inherited flags.
	planFor := func(i int, target string) childPlan {
		output := outputs[i]
		return childPlan{
			args:         append(append([]string{"scan"}, baseChildArgs...), "-t", target, "-o", output),
			console:      perTargetConsolePath(output),
			statsBase:    output,
			statsFormats: scanOpts.OutputFormats,
		}
	}

	results, failed := fanOutTargetScans(ctx, exe, targets, parallel, planFor)

	printParallelSummary(results, failed)
	return parallelBatchError(failed, len(targets))
}

// childPlan describes one child scan the parent will spawn: the full argv (with
// "scan" first), the file the child's combined stdout/stderr is captured to, and
// the base path + formats the parent reads back for that child's per-target
// stats. A statsBase of "" disables the per-target counts segment for that child.
type childPlan struct {
	args         []string
	console      string
	statsBase    string
	statsFormats []string
}

// fanOutTargetScans spawns one child `vigolium scan` per target — running up to
// `parallel` concurrently — and returns the per-target results plus how many
// failed. planFor builds each child's argv and the paths the parent reads back.
// It owns the worker semaphore, the live start/done/failed progress lines, and
// (via runChildScan) SIGINT forwarding; callers print the banner before the call
// and the roll-up / unified export after it. Shared by the stateless (per-host
// files) and db-isolate (merge into --db) parallel paths.
func fanOutTargetScans(ctx context.Context, exe string, targets []string, parallel int, planFor func(i int, target string) childPlan) ([]targetResult, int) {
	var (
		mu        sync.Mutex // guards results, completed, failed, and stderr prints
		results   = make([]targetResult, len(targets))
		completed int
		failed    int
		wg        sync.WaitGroup
	)
	sem := make(chan struct{}, parallel)
	total := len(targets)

	for i := range targets {
		i := i
		target := targets[i]
		plan := planFor(i, target)

		wg.Add(1)
		sem <- struct{}{} // throttle launch to `parallel` in flight
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			if !scanOpts.Silent {
				mu.Lock()
				fmt.Fprintf(os.Stderr, "%s %s %s %s\n",
					terminal.BoldYellow(terminal.SymbolStart),
					terminal.BoldHiBlue(fmt.Sprintf("[%d/%d]", i+1, total)),
					terminal.Yellow(padStatus("start")),
					target)
				mu.Unlock()
			}

			start := time.Now()
			runErr := runChildScan(ctx, exe, plan.args, plan.console)
			dur := time.Since(start)

			// Recover per-target counts from the JSONL the child just wrote.
			// Only on success — a failed child may have written nothing.
			var stats childStats
			statsOK := false
			if runErr == nil && plan.statsBase != "" {
				stats, statsOK = readChildStats(plan.statsBase, plan.statsFormats)
			}

			mu.Lock()
			results[i] = targetResult{target: target, output: plan.statsBase, console: plan.console, err: runErr, duration: dur, stats: stats, statsOK: statsOK}
			completed++
			if runErr != nil {
				failed++
			}
			doneCount, failCount := completed, failed
			if !scanOpts.Silent {
				if runErr != nil {
					fmt.Fprintf(os.Stderr, "%s %s %s %s  (%s) — see %s\n",
						terminal.BoldRed(terminal.SymbolError),
						terminal.BoldHiBlue(fmt.Sprintf("[%d/%d]", i+1, total)),
						terminal.Red(padStatus("failed")),
						target,
						terminal.Magenta(dur.Round(time.Second).String()),
						terminal.Gray(plan.console))
				} else {
					fmt.Fprintf(os.Stderr, "%s %s %s %s  (%s) · %s%d/%d done, %d failed\n",
						terminal.BoldGreen(terminal.SymbolSuccess),
						terminal.BoldHiBlue(fmt.Sprintf("[%d/%d]", i+1, total)),
						terminal.Green(padStatus("done")),
						target,
						terminal.Magenta(dur.Round(time.Second).String()),
						statsSegment(stats, statsOK),
						doneCount, total, failCount)
				}
			}
			mu.Unlock()

			if runErr != nil {
				zap.L().Error("Parallel target scan failed",
					zap.String("target", target),
					zap.String("console", plan.console),
					zap.Error(runErr))
			}
		}()
	}

	wg.Wait()
	return results, failed
}

// runIsolatedTargetsParallel scans every target in targets concurrently, up to
// scanOpts.Parallel at a time, as isolated `vigolium scan --db-isolate` child
// processes. Each child scans its one target into a private scratch SQLite
// database and merges the results into the shared destination (--db, else the
// configured DB) under a cross-process merge lock, so the children never contend
// on a single SQLite writer. Once every child has finished and merged, the
// parent exports ONE unified output (the operator's --output/--format) from the
// merged destination — there are no per-host files; the single source of truth
// is the merged DB.
//
// Per-target counts on the progress lines are recovered from a throwaway JSONL
// each child writes into a temporary staging directory (never the operator's
// --output prefix); the staging directory is removed when the batch finishes.
func runIsolatedTargetsParallel(cmd *cobra.Command, settings *config.Settings, strategyName string) error {
	targets, err := readTargetFileLines(scanOpts.TargetsFilePath)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("target file %q contains no targets", scanOpts.TargetsFilePath)
	}

	// One target (or -P 1) has nothing to fan out: a single in-process db-isolate
	// scan over the file already produces a unified output and one merge, with no
	// subprocess overhead.
	if scanOpts.Parallel <= 1 || len(targets) == 1 {
		return executeNativeScan(cmd, settings, strategyName)
	}

	// Resolve and validate the merge destination up front (must be SQLite) so the
	// batch fails fast rather than after every child has run.
	destCfg, err := resolveDBIsolateDest(settings)
	if err != nil {
		return err
	}
	// Surface the destination in the config banner (the parent never calls
	// dbIsolateBegin — each child does — so set it directly here).
	dbIsolateDestPath = destCfg.SQLite.Path

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate the vigolium binary for parallel fan-out: %w", err)
	}

	parallel := scanOpts.Parallel
	if parallel > len(targets) {
		parallel = len(targets)
	}

	if scanOpts.SplitByHost && !scanOpts.Silent {
		fmt.Fprintf(os.Stderr, "%s --split-by-host is ignored under --db-isolate parallel mode; a single unified output is exported from %s instead\n",
			terminal.WarnPrefix(), terminal.Cyan(destCfg.SQLite.Path))
	}

	// Banner once: targets pointed at the batch so the count is right, output left
	// as the literal unified prefix the parent actually writes at the end.
	if !scanOpts.Silent {
		origBannerTargets := scanOpts.Targets
		scanOpts.Targets = targets
		printScanSummary(scanOpts, settings, strategyName, nil)
		scanOpts.Targets = origBannerTargets
		scanOpts.ScanConfigPrinted = true
	}

	// Per-child stats land in a private staging directory, never the operator's
	// --output prefix, and are discarded with the directory when the batch ends.
	stagingDir, err := os.MkdirTemp("", "vigolium-parallel-*")
	if err != nil {
		return fmt.Errorf("create parallel staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(stagingDir) }()

	baseChildArgs := childScanArgs(cmd)

	if !scanOpts.Silent {
		budget := parallel * scanOpts.Concurrency
		fmt.Fprintf(os.Stderr, "\n%s %s scanning %s targets, %s at a time → merging into %s\n",
			terminal.Purple(terminal.SymbolTarget),
			terminal.BoldHiBlue("Parallel"),
			terminal.HiCyan(fmt.Sprintf("%d", len(targets))),
			terminal.HiCyan(fmt.Sprintf("%d", parallel)),
			terminal.Cyan(destCfg.SQLite.Path))
		if budget > parallelSocketWarnThreshold {
			fmt.Fprintf(os.Stderr, "%s ~%d requests may be in flight at once (%d targets × %d --concurrency); lower -P or --concurrency if that is too aggressive\n",
				terminal.WarnPrefix(), budget, parallel, scanOpts.Concurrency)
		}
	}

	// A parent SIGINT/SIGTERM cancels ctx, which each child's Cancel hook turns
	// into a forwarded SIGINT (not SIGKILL) so children shut down cleanly and
	// finish (or abandon) their merge before exiting.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Each child inherits --db-isolate/--db from the parent and writes a
	// throwaway jsonl into staging purely for the parent's per-target stats; the
	// child's own format/output are overridden so it produces no per-host files.
	planFor := func(i int, target string) childPlan {
		statsPath := filepath.Join(stagingDir, fmt.Sprintf("t%03d.jsonl", i))
		args := append(append([]string{"scan"}, baseChildArgs...), "-t", target, "-o", statsPath, "--format", "jsonl")
		return childPlan{
			args:         args,
			console:      perTargetConsolePath(statsPath),
			statsBase:    statsPath,
			statsFormats: []string{"jsonl"},
		}
	}

	results, failed := fanOutTargetScans(ctx, exe, targets, parallel, planFor)

	printParallelSummary(results, failed)

	// Export the unified output only when at least one child merged something —
	// if every child failed there is nothing new in the destination to export.
	if failed < len(targets) {
		if err := exportUnifiedFromDB(destCfg, scanOpts); err != nil {
			fmt.Fprintf(os.Stderr, "%s unified export from %s failed: %v\n",
				terminal.ErrorPrefix(), terminal.Cyan(destCfg.SQLite.Path), err)
		}
	}

	return parallelBatchError(failed, len(targets))
}

// exportUnifiedFromDB opens the merge-destination database and writes the
// operator's requested file outputs (html/report/pdf via maybeGenerateReports,
// jsonl via finishScanJSONLExport) from it, scoped to the run's project. Used by
// the db-isolate parallel path to turn the merged results into the single
// unified --output the operator asked for, after every child has merged in.
func exportUnifiedFromDB(destCfg config.DatabaseConfig, opts *types.Options) error {
	db, err := database.NewDB(&destCfg)
	if err != nil {
		return fmt.Errorf("open destination database: %w", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.CreateSchema(context.Background()); err != nil {
		return fmt.Errorf("prepare destination schema: %w", err)
	}
	maybeGenerateReports(db, opts)
	finishScanJSONLExport(db, opts)
	return nil
}

// parallelBatchError decides the batch's exit status: non-zero only when every
// target failed. A partial success is still a success, so the roll-up's failed
// count is the signal for partial failures; --soft-fail (handled at the root)
// still forces exit 0 regardless of what this returns.
func parallelBatchError(failed, total int) error {
	if total > 0 && failed == total {
		return fmt.Errorf("all %d target scans failed", total)
	}
	return nil
}

// runChildScan runs one child scan process, capturing its combined stdout and
// stderr to consolePath. ctx cancellation is forwarded as a SIGINT (so the child
// can clean up its temp database) followed by a hard kill after childExitGrace.
func runChildScan(ctx context.Context, exe string, args []string, consolePath string) error {
	cmd := exec.CommandContext(ctx, exe, args...)
	// Forward SIGINT instead of the default SIGKILL so the child runs its own
	// signal handler (graceful stop + temp-DB removal) before exiting.
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Signal(syscall.SIGINT)
	}
	cmd.WaitDelay = childExitGrace

	if f, ferr := os.Create(consolePath); ferr == nil {
		defer func() { _ = f.Close() }()
		cmd.Stdout = f
		cmd.Stderr = f
	}
	// If the console file can't be created, the child still runs; its output is
	// simply discarded (Stdout/Stderr left nil ⇒ os.DevNull).

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("interrupted: %w", err)
		}
		return err
	}
	return nil
}

// printParallelSummary prints the final roll-up for the fan-out: counts, total
// wall time, and the per-target console path for each failure.
func printParallelSummary(results []targetResult, failed int) {
	if scanOpts.Silent {
		return
	}
	total := len(results)
	succeeded := total - failed

	var longest time.Duration
	agg := childStats{sev: make(map[string]int)}
	haveStats := false
	for _, r := range results {
		if r.duration > longest {
			longest = r.duration
		}
		if r.statsOK {
			haveStats = true
			agg.records += r.stats.records
			agg.findings += r.stats.findings
			for k, v := range r.stats.sev {
				agg.sev[k] += v
			}
		}
	}

	fmt.Fprintf(os.Stderr, "\n%s %s  %s targets · %s succeeded · %s failed · longest %s\n",
		terminal.Aqua(terminal.SymbolSparkle),
		terminal.BoldAqua("Parallel scan complete"),
		terminal.HiCyan(fmt.Sprintf("%d", total)),
		terminal.BoldGreen(fmt.Sprintf("%d", succeeded)),
		failColor(failed),
		terminal.Gray(longest.Round(time.Second).String()))

	if haveStats {
		findings := terminal.Gray("0 findings")
		if agg.findings > 0 {
			breakdown := severityBreakdown(agg.sev)
			if breakdown != "" {
				breakdown = " " + breakdown
			}
			findings = terminal.Bold(fmt.Sprintf("%d findings", agg.findings)) + breakdown
		}
		fmt.Fprintf(os.Stderr, "  %s Totals: %s · %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.Cyan(fmt.Sprintf("%d records", agg.records)),
			findings)
	}

	if failed > 0 {
		for _, r := range results {
			if r.err == nil {
				continue
			}
			fmt.Fprintf(os.Stderr, "  %s %s — %v (%s)\n",
				terminal.BoldRed(terminal.SymbolError),
				r.target,
				r.err,
				terminal.Gray(r.console))
		}
	}
}

// statsSegment renders the per-target "<R> records · <F> findings[ (sev)] · "
// fragment shown on a done line, trailing separator included so it slots in
// before the progress counter. Returns "" when stats are unavailable (jsonl not
// requested or unreadable) so the line collapses to just the counter.
func statsSegment(st childStats, ok bool) string {
	if !ok {
		return ""
	}
	findings := terminal.Gray("0 findings")
	if st.findings > 0 {
		breakdown := severityBreakdown(st.sev)
		if breakdown != "" {
			breakdown = " " + breakdown
		}
		findings = terminal.Bold(fmt.Sprintf("%d findings", st.findings)) + breakdown
	}
	return fmt.Sprintf("%s · %s · ", terminal.Cyan(fmt.Sprintf("%d records", st.records)), findings)
}

// severityBreakdown renders a compact, colored "(1 crit, 2 high, …)" summary in
// descending severity order, omitting absent severities. Returns "" when empty.
func severityBreakdown(sev map[string]int) string {
	order := []struct {
		key   string
		label string
		color func(string) string
	}{
		{"critical", "crit", terminal.BoldMagenta},
		{"high", "high", terminal.BoldRed},
		{"medium", "med", terminal.BoldYellow},
		{"low", "low", terminal.BoldGreen},
		{"suspect", "susp", terminal.BoldCyan},
		{"info", "info", terminal.BoldBlue},
	}
	var parts []string
	for _, s := range order {
		if c := sev[s.key]; c > 0 {
			parts = append(parts, s.color(fmt.Sprintf("%d %s", c, s.label)))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// failColor renders the failed count red when non-zero, dim otherwise.
func failColor(failed int) string {
	s := fmt.Sprintf("%d", failed)
	if failed > 0 {
		return terminal.BoldRed(s)
	}
	return terminal.Gray(s)
}

// childScanArgs reconstructs the flags the operator set on the scan command,
// dropping the multi-target/parallel/output flags that the parent rewrites per
// child (-T/--target-file, -P/--parallel, --split-by-host, -t/--target,
// -o/--output). Only changed flags are emitted (via Flags().Visit), so every
// other flag the operator passed — proxy, modules, intensity, auth, format,
// headers, etc. — is inherited by each child automatically, with no per-flag
// enumeration to keep in sync as flags are added.
//
// The child therefore runs a plain single-target stateless scan
// (`vigolium scan --stateless -t <target> -o <resolved> ...`) and writes exactly
// the per-host output files it would have produced in the sequential path.
func childScanArgs(cmd *cobra.Command) []string {
	skip := map[string]bool{
		"target-file":   true,
		"target":        true,
		"output":        true,
		"parallel":      true,
		"split-by-host": true,
	}

	var args []string
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if skip[f.Name] {
			return
		}
		name := "--" + f.Name
		switch {
		case f.Value.Type() == "bool":
			// Re-emit booleans as a bare flag (true) or --flag=false so an
			// explicitly-disabled default round-trips correctly.
			if f.Value.String() == "true" {
				args = append(args, name)
			} else {
				args = append(args, name+"=false")
			}
		case isMapFlag(f):
			// stringToString / stringToInt render as "[k=v,k2=v2]"; re-emit each
			// pair as its own --flag k=v so the child rebuilds the same map.
			for _, kv := range parseMapFlagValue(f.Value.String()) {
				args = append(args, name, kv)
			}
		default:
			if sv, ok := f.Value.(pflag.SliceValue); ok {
				// Repeatable flags (--header, --auth, …) re-emit one value each.
				for _, v := range sv.GetSlice() {
					args = append(args, name, v)
				}
			} else {
				args = append(args, name, f.Value.String())
			}
		}
	})
	return args
}

// isMapFlag reports whether a flag is one of pflag's stringTo* map types, whose
// String() form ("[k=v,...]") is not directly re-passable on the command line.
func isMapFlag(f *pflag.Flag) bool {
	switch f.Value.Type() {
	case "stringToString", "stringToInt", "stringToInt64":
		return true
	default:
		return false
	}
}

// parseMapFlagValue splits a pflag map flag's "[k=v,k2=v2]" String() form into
// individual "k=v" tokens. Values containing commas cannot be represented
// unambiguously here, which matches pflag's own comma-separated parsing.
func parseMapFlagValue(s string) []string {
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// withIndexSuffix inserts a zero-padded index before a path's format extension,
// used to disambiguate two targets that resolve to the same per-host output
// path so concurrent children never write the same file.
func withIndexSuffix(path string, idx int) string {
	stripped := types.StripFormatExtension(path)
	rest := strings.TrimPrefix(path, stripped)
	return fmt.Sprintf("%s-%03d%s", stripped, idx+1, rest)
}

// perTargetConsolePath returns the file a child's combined stdout/stderr is
// captured to, derived from its resolved output path.
func perTargetConsolePath(output string) string {
	return types.StripFormatExtension(output) + ".console.log"
}

// perHostOutputPattern turns an --output prefix into the "<prefix>-<host>"
// display pattern used by --split-by-host, preserving any format extension. It
// mirrors perTargetOutputPath but with a literal "<host>" placeholder so the
// banner shows e.g. "roche-vig-<host>.jsonl" — the shape children actually write
// — rather than the literal "roche-vig.jsonl" that no per-host file uses.
func perHostOutputPattern(output string) string {
	if output == "" {
		return output
	}
	stripped := types.StripFormatExtension(output)
	rest := strings.TrimPrefix(output, stripped)
	return stripped + "-<host>" + rest
}

// padStatus right-pads a lifecycle status word ("start"/"done"/"failed") to a
// fixed width so the target column lines up across all three regardless of word
// length. Padding the plain word (the spaces carry no color) keeps the columns
// aligned even though each word is wrapped in ANSI color codes.
func padStatus(s string) string {
	return fmt.Sprintf("%-6s", s)
}

// summarizeTargetList joins up to max targets for display, collapsing the rest
// into a "(+N more)" tail so a large target file doesn't dump thousands of URLs
// into the scan-configuration banner.
func summarizeTargetList(targets []string, max int) string {
	if len(targets) <= max {
		return strings.Join(targets, ", ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(targets[:max], ", "), len(targets)-max)
}
