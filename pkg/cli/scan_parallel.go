package cli

import (
	"context"
	"database/sql"
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
	"github.com/uptrace/bun/driver/sqliteshim"
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
	// Parallel fan-out only operates on a -T/--target-file: it scans each line as
	// its own isolated child. A single -t/inline/stdin target has nothing to fan
	// out, so -P (and the --split-by-host it would pair with) can't take effect.
	// Rather than reject the combination, warn and degrade to a normal one-target
	// scan — the dispatch already falls through to the single-pass path here.
	if len(opts.TargetsFilePaths) == 0 {
		if !opts.Silent {
			fmt.Fprintf(os.Stderr,
				"%s --parallel/-P and --split-by-host apply only to multi-target scans (-T/--target-file); with a single target they are ignored — running a normal scan\n",
				terminal.WarnPrefix())
		}
		opts.Parallel = 1
		opts.SplitByHost = false
		return nil
	}
	statelessOK := opts.Stateless && opts.SplitByHost
	isolateOK := opts.DBIsolate
	if !statelessOK && !isolateOK {
		return fmt.Errorf("--parallel > 1 requires either --stateless (-S) -T --split-by-host, or --db-isolate -T (results merge into --db)")
	}
	return nil
}

// targetResult records the outcome of one child scan in the fan-out.
type targetResult struct {
	target      string
	output      string
	console     string
	err         error
	interrupted bool // batch was canceled (Ctrl-C) before this target finished
	duration    time.Duration
	stats       childStats
	statsOK     bool
}

// childStats are the per-target counts the parent recovers from a child's
// output once it finishes: HTTP records ingested, findings, and a severity
// breakdown. Populated from whichever of the child's output files can carry
// them — JSONL or the standalone SQLite export (see readChildStats).
type childStats struct {
	records  int
	findings int
	sev      map[string]int
}

// readChildStats recovers a child's HTTP-record and finding counts (by severity)
// from whichever of its per-target output files can carry them. It prefers the
// JSONL export (a cheap streaming line-count, no DB driver), then falls back to
// the standalone SQLite database the child writes under --format sqlite — so the
// parent's per-target stats segment and final Totals roll-up render even when the
// operator never requested jsonl (e.g. --format sqlite,html). Returns ok=false
// when neither readable format was produced, so the caller simply omits the
// stats segment rather than guessing.
func readChildStats(output string, formats []string) (childStats, bool) {
	if formatsContain(formats, "jsonl") {
		if st, ok := readChildStatsJSONL(output); ok {
			return st, true
		}
	}
	if formatsContain(formats, "sqlite") {
		if st, ok := readChildStatsSQLite(output); ok {
			return st, true
		}
	}
	return childStats{}, false
}

// formatsContain reports whether want is among the requested output formats.
func formatsContain(formats []string, want string) bool {
	for _, f := range formats {
		if f == want {
			return true
		}
	}
	return false
}

// readChildStatsJSONL counts a child's HTTP records and findings (by severity)
// from its per-target JSONL output. The unified export writes one {"type":...}
// JSON object per line, so consecutive json.Decode calls recover the counts
// without a line-length limit (response bodies can make individual lines large).
// Returns ok=false when the file is missing or unreadable.
func readChildStatsJSONL(output string) (childStats, bool) {
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

// readChildStatsSQLite counts a child's HTTP records and findings (by severity)
// from the standalone .sqlite the child writes under --format sqlite. The export
// is a fully checkpointed VACUUM INTO copy (no WAL sidecar), so it is opened
// query-only with a short busy timeout — read-only SELECTs against the default
// (non-WAL) journal never create -wal/-shm files next to the operator's artifact.
// Returns ok=false when the file is missing or any query fails.
func readChildStatsSQLite(output string) (childStats, bool) {
	path := types.StripFormatExtension(output) + ".sqlite"
	if _, err := os.Stat(path); err != nil {
		return childStats{}, false
	}

	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(2000)&_pragma=query_only(true)", path)
	db, err := sql.Open(sqliteshim.ShimName, dsn)
	if err != nil {
		return childStats{}, false
	}
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	st := childStats{sev: make(map[string]int)}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM http_records").Scan(&st.records); err != nil {
		return childStats{}, false
	}

	rows, err := db.QueryContext(ctx, "SELECT severity, COUNT(*) FROM findings GROUP BY severity")
	if err != nil {
		return childStats{}, false
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			sev string
			n   int
		)
		if err := rows.Scan(&sev, &n); err != nil {
			return childStats{}, false
		}
		st.findings += n
		if sev != "" {
			st.sev[strings.ToLower(sev)] += n
		}
	}
	if err := rows.Err(); err != nil {
		return childStats{}, false
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

	// Progress manifest: a tiny line-cursor sidecar (<output>.progress.json),
	// rewritten atomically whenever the completed prefix advances, so a later
	// --resume can pick up from the next unscanned line without storing a row per
	// target (the list may be huge). allCount is the full batch size; targets is
	// narrowed to the remaining tail when resuming, so the roll-up and exit code
	// still reason about the whole batch (the completed prefix counts as success).
	allCount := len(targets)
	manifestPath := resumeManifestPath(scanOpts.Output, scanOpts.TargetsFilePaths)
	fingerprint := scanSettingsFingerprint(cmd)
	var manifest *resumeManifest

	if scanOpts.Resume {
		if m, ok := loadResumeManifest(manifestPath); ok {
			manifest = m
			manifest.path = manifestPath
			if !scanOpts.Silent && m.SettingsFingerprint != "" && m.SettingsFingerprint != fingerprint {
				fmt.Fprintf(os.Stderr, "%s resume manifest %s was created with different scan settings; the completed prefix is kept as-is (scanned under the old settings)\n",
					terminal.WarnPrefix(), terminal.Cyan(manifestPath))
			}
		} else if !scanOpts.Silent {
			fmt.Fprintf(os.Stderr, "%s no resume manifest at %s — scanning all %d targets\n",
				terminal.WarnPrefix(), terminal.Cyan(manifestPath), allCount)
		}
	}
	if manifest == nil {
		// A fresh (non-resume) run starts a clean manifest, overwriting any stale
		// one immediately so a --resume after an early Ctrl-C — before any target
		// finished this run — never reads a completed prefix from a prior batch.
		manifest = newResumeManifest(manifestPath, scanOpts.Output, scanOpts.OutputFormats, scanOpts.TargetsFilePaths, fingerprint)
		if err := manifest.save(); err != nil {
			zap.L().Warn("Failed to initialize resume manifest", zap.String("path", manifestPath), zap.Error(err))
		}
	}

	// Capture prior progress before the fan-out mutates the cursor, then skip the
	// completed prefix. startOffset maps a scanned target's slice index back to
	// its absolute line for the cursor (see onComplete below).
	startOffset := manifest.startOffset(allCount)
	priorCarry := manifest.carryover()
	if scanOpts.Resume && startOffset > 0 {
		remaining := allCount - startOffset
		if remaining <= 0 {
			if !scanOpts.Silent {
				fmt.Fprintf(os.Stderr, "%s all %d targets already complete — nothing to resume\n",
					terminal.Purple(terminal.SymbolInfo), allCount)
			}
			printParallelSummary(nil, 0, 0, manifestPath, priorCarry)
			return nil
		}
		if !scanOpts.Silent {
			// Sanity-check the cursor against the current file: the target on the
			// cursor line should still be the one the manifest recorded. A mismatch
			// means the completed prefix was edited or reordered, so the cursor may
			// skip or rescan the wrong lines — warn but honor the operator's --resume.
			// startOffset is in [1, allCount), so targets[startOffset-1] is in bounds.
			if targets[startOffset-1] != manifest.CursorTarget {
				fmt.Fprintf(os.Stderr, "%s target file changed since the last run (line %d is now %s, manifest recorded %s); resume cursor may be misaligned\n",
					terminal.WarnPrefix(), startOffset, terminal.Cyan(targets[startOffset-1]), terminal.Cyan(manifest.CursorTarget))
			}
			fmt.Fprintf(os.Stderr, "%s %s %s of %s targets already complete — scanning %s remaining\n",
				terminal.Aqua("↻"),
				terminal.BoldAqua("Resuming:"),
				terminal.HiCyan(fmt.Sprintf("%d", startOffset)),
				terminal.HiCyan(fmt.Sprintf("%d", allCount)),
				terminal.HiCyan(fmt.Sprintf("%d", remaining)))
		}
		targets = targets[startOffset:]
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
	// and Output at the per-host pattern so it reads "acme-vig-<host>.jsonl"
	// (what children actually write) instead of the literal "acme-vig.jsonl"
	// that no file ever uses under --split-by-host.
	if !scanOpts.Silent {
		origBannerTargets := scanOpts.Targets
		origBannerOutput := scanOpts.Output
		scanOpts.Targets = targets
		scanOpts.Output = perHostOutputPattern(scanOpts.Output)
		printScanSummary(scanOpts, settings, strategyName, nil, manifestPath)
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
	// only the per-target -t/-o differ between children. Each child's console is
	// captured to a per-target file, so --captured-console makes that file a useful
	// record (live findings included, no [status] ticker noise).
	baseChildArgs := append(childScanArgs(cmd), "--captured-console")

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

	// Advance the manifest cursor as targets finish cleanly, so a Ctrl-C keeps the
	// record of how far the contiguous completed prefix reached. Runs under the
	// fan-out's result lock (see fanOutTargetScans), so the cursor update and
	// atomic save are serialized against concurrent completions. idx is the index
	// within this run's (possibly narrowed) slice; startOffset maps it back to the
	// absolute line. We only rewrite the file when the cursor actually moved.
	onComplete := func(idx int, res targetResult) {
		if res.err != nil || res.interrupted {
			return
		}
		if manifest.markDone(startOffset+idx, res.target, res.stats) {
			if err := manifest.save(); err != nil {
				zap.L().Warn("Failed to persist resume manifest", zap.String("path", manifestPath), zap.Error(err))
			}
		}
	}

	results, failed, interrupted := fanOutTargetScans(ctx, exe, targets, parallel, planFor, onComplete)

	// priorCarry folds the previously-completed prefix into the roll-up and exit
	// status so they reason about the whole batch, not just this run's remainder.
	printParallelSummary(results, failed, interrupted, manifestPath, priorCarry)
	return parallelBatchError(failed, interrupted, allCount)
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
//
// onComplete, when non-nil, is invoked once per target as it finishes — while
// the result lock is held, so it may safely mutate shared state (the stateless
// path uses it to checkpoint each completed target to the resume manifest). It
// receives the target's index and its fully-populated result.
func fanOutTargetScans(ctx context.Context, exe string, targets []string, parallel int, planFor func(i int, target string) childPlan, onComplete func(idx int, res targetResult)) ([]targetResult, int, int) {
	var (
		mu          sync.Mutex // guards results, completed, failed, interrupted, and stderr prints
		results     = make([]targetResult, len(targets))
		completed   int
		failed      int
		interrupted int
		wg          sync.WaitGroup
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

			// Ctrl-C (ctx canceled) before this child got a worker slot: don't
			// launch it. Record it as interrupted/not-scanned and stay silent —
			// the summary collapses the whole un-started set into one general
			// line instead of printing a start+failed pair (and a zap error) for
			// every queued target the operator never meant to wait on.
			if ctx.Err() != nil {
				mu.Lock()
				results[i] = targetResult{target: target, console: plan.console, err: ctx.Err(), interrupted: true}
				completed++
				interrupted++
				if onComplete != nil {
					onComplete(i, results[i])
				}
				mu.Unlock()
				return
			}

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

			// A child that was killed by the batch-wide Ctrl-C didn't really
			// "fail" — it was cut short. Treat it as interrupted so it joins the
			// general not-scanned tally rather than the genuine-failure list.
			wasInterrupted := runErr != nil && ctx.Err() != nil

			// Recover per-target counts from the JSONL the child just wrote.
			// Only on success — a failed child may have written nothing.
			var stats childStats
			statsOK := false
			if runErr == nil && plan.statsBase != "" {
				stats, statsOK = readChildStats(plan.statsBase, plan.statsFormats)
			}

			mu.Lock()
			results[i] = targetResult{target: target, output: plan.statsBase, console: plan.console, err: runErr, interrupted: wasInterrupted, duration: dur, stats: stats, statsOK: statsOK}
			completed++
			switch {
			case wasInterrupted:
				interrupted++
			case runErr != nil:
				failed++
			}
			doneCount, failCount := completed, failed
			if !scanOpts.Silent {
				switch {
				case wasInterrupted:
					// Muted, single line — no "see <console>", no zap error: this
					// target was stopped by the operator, not by a real fault.
					fmt.Fprintf(os.Stderr, "%s %s %s %s  (interrupted)\n",
						terminal.Gray(terminal.SymbolSkipped),
						terminal.BoldHiBlue(fmt.Sprintf("[%d/%d]", i+1, total)),
						terminal.Gray(padStatus("stopped")),
						terminal.Gray(target))
				case runErr != nil:
					fmt.Fprintf(os.Stderr, "%s %s %s %s  (%s) — see %s\n",
						terminal.BoldRed(terminal.SymbolError),
						terminal.BoldHiBlue(fmt.Sprintf("[%d/%d]", i+1, total)),
						terminal.Red(padStatus("failed")),
						target,
						terminal.Magenta(dur.Round(time.Second).String()),
						terminal.Gray(plan.console))
				default:
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
			if onComplete != nil {
				onComplete(i, results[i])
			}
			mu.Unlock()

			// Only genuine failures are logged at ERROR — an operator Ctrl-C is
			// not an error worth a stack of red log lines.
			if runErr != nil && !wasInterrupted {
				zap.L().Error("Parallel target scan failed",
					zap.String("target", target),
					zap.String("console", plan.console),
					zap.Error(runErr))
			}
		}()
	}

	wg.Wait()
	return results, failed, interrupted
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
	targets, err := readTargetFilesLines(scanOpts.TargetsFilePaths)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("target file(s) %s contain no targets", strings.Join(scanOpts.TargetsFilePaths, ", "))
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
		printScanSummary(scanOpts, settings, strategyName, nil, "")
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

	// Each child's console is captured to a per-target file; --captured-console
	// makes that file a useful record (live findings included, no [status] noise).
	baseChildArgs := append(childScanArgs(cmd), "--captured-console")

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

	// The db-isolate path merges into one shared DB and has no per-host output
	// files, so host-level resume does not apply here (v1): no manifest callback,
	// and the summary prints the generic re-run hint rather than a --resume tip.
	results, failed, interrupted := fanOutTargetScans(ctx, exe, targets, parallel, planFor, nil)

	printParallelSummary(results, failed, interrupted, "", carryoverStats{})

	// Export the unified output only when at least one child merged something —
	// if every child failed or was interrupted there is nothing new in the
	// destination to export.
	if failed+interrupted < len(targets) {
		if err := exportUnifiedFromDB(destCfg, scanOpts); err != nil {
			fmt.Fprintf(os.Stderr, "%s unified export from %s failed: %v\n",
				terminal.ErrorPrefix(), terminal.Cyan(destCfg.SQLite.Path), err)
		}
	}

	return parallelBatchError(failed, interrupted, len(targets))
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

// parallelBatchError decides the batch's exit status. A partial success is
// still a success, so the only non-zero outcomes are: every target genuinely
// failed, or the batch was Ctrl-C'd before a single target finished cleanly
// (everything either failed or was interrupted). A partial interrupt — some
// targets completed before the stop — exits clean, just like a partial failure.
// --soft-fail (handled at the root) still forces exit 0 regardless.
func parallelBatchError(failed, interrupted, total int) error {
	if total == 0 {
		return nil
	}
	if interrupted > 0 && failed+interrupted == total {
		return fmt.Errorf("scan interrupted: %d of %d targets not scanned", interrupted, total)
	}
	if failed == total {
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
// wall time, and the per-target console path for each genuine failure. Targets
// the operator interrupted (Ctrl-C) before they finished are not enumerated —
// they collapse into a single "N not scanned" line, since listing every
// un-started target is pure noise the operator didn't ask to wait on.
// printParallelSummary prints the final roll-up. manifestPath, when set (the
// stateless per-host path), turns the trailing "re-run to finish" hint into a
// copy-pasteable --resume command plus the manifest's done/total progress; an
// empty manifestPath (the db-isolate path) keeps the generic re-run line. carry
// folds a resumed run's previously-completed prefix into the totals so the
// counts reflect the whole batch, not just this run's remainder.
func printParallelSummary(results []targetResult, failed, interrupted int, manifestPath string, carry carryoverStats) {
	if scanOpts.Silent {
		return
	}
	total := carry.count + len(results)
	succeeded := total - failed - interrupted

	var longest time.Duration
	agg := childStats{sev: make(map[string]int)}
	haveStats := carry.count > 0
	agg.records += carry.stats.records
	agg.findings += carry.stats.findings
	for k, v := range carry.stats.sev {
		agg.sev[k] += v
	}
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

	// The header reads "… complete" normally but "… interrupted" when the
	// operator stopped the batch — and only carries the "N not scanned" segment
	// in that case, so a clean run's header stays uncluttered.
	headline := terminal.BoldAqua("Parallel scan complete")
	interruptedSeg := ""
	if interrupted > 0 {
		headline = terminal.BoldYellow("Parallel scan interrupted")
		interruptedSeg = fmt.Sprintf(" · %s not scanned", terminal.BoldYellow(fmt.Sprintf("%d", interrupted)))
	}

	fmt.Fprintf(os.Stderr, "\n%s %s  %s targets · %s succeeded · %s failed%s · longest %s\n",
		terminal.Aqua(terminal.SymbolSparkle),
		headline,
		terminal.HiCyan(fmt.Sprintf("%d", total)),
		terminal.BoldGreen(fmt.Sprintf("%d", succeeded)),
		failColor(failed),
		interruptedSeg,
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

	// Enumerate genuine failures only — each with its console for triage.
	if failed > 0 {
		for _, r := range results {
			if r.err == nil || r.interrupted {
				continue
			}
			fmt.Fprintf(os.Stderr, "  %s %s — %v (%s)\n",
				terminal.BoldRed(terminal.SymbolError),
				r.target,
				r.err,
				terminal.Gray(r.console))
		}
	}

	// Everything the run left undone — interrupted (Ctrl-C) or genuinely failed —
	// can be picked up with --resume, which skips the targets already recorded
	// complete in the manifest. Render the exact resume command so it pastes back.
	remaining := failed + interrupted
	switch {
	case manifestPath != "" && remaining > 0:
		desc := "still need scanning"
		if interrupted == 0 {
			desc = "failed"
		}
		fmt.Fprintf(os.Stderr, "\n  %s %s target(s) %s — resume where you left off:\n\n",
			terminal.Aqua("↻"),
			terminal.BoldYellow(fmt.Sprintf("%d", remaining)),
			desc)
		fmt.Fprintf(os.Stderr, "      %s\n\n", terminal.Cyan(resumeCommandLine(os.Args)))
		fmt.Fprintf(os.Stderr, "  %s Progress saved to %s (%d of %d complete; done hosts will be skipped)\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.Cyan(manifestPath),
			succeeded, total)
	case interrupted > 0:
		// db-isolate path (no per-host manifest): the generic re-run hint. No
		// per-target dump — there is nothing to triage in a target never run.
		fmt.Fprintf(os.Stderr, "  %s %s target(s) stopped before completing and were not scanned — re-run to finish them\n",
			terminal.Gray(terminal.SymbolSkipped),
			terminal.BoldYellow(fmt.Sprintf("%d", interrupted)))
	}
}

// statsSegment renders the per-target "<R> records · <F> findings[ (sev)] · "
// fragment shown on a done line, trailing separator included so it slots in
// before the progress counter. Returns "" when stats are unavailable (neither a
// jsonl nor a sqlite export the parent could tally) so the line collapses to
// just the counter.
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
		"resume":        true, // parent-only fan-out coordination; children scan a single target
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
// banner shows e.g. "acme-vig-<host>.jsonl" — the shape children actually write
// — rather than the literal "acme-vig.jsonl" that no per-host file uses.
func perHostOutputPattern(output string) string {
	if output == "" {
		// No base path: per-host files are named by the host alone (<host>.<ext>),
		// so the banner shows the "<host>" placeholder rather than an empty dest.
		return "<host>"
	}
	stripped := types.StripFormatExtension(output)
	rest := strings.TrimPrefix(output, stripped)
	return stripped + "-<host>" + rest
}

// padStatus right-pads a lifecycle status word ("start"/"done"/"failed"/
// "stopped") to a fixed width so the target column lines up across all of them
// regardless of word length. Padding the plain word (the spaces carry no color)
// keeps the columns aligned even though each word is wrapped in ANSI color
// codes. The width fits the longest word ("stopped").
func padStatus(s string) string {
	return fmt.Sprintf("%-7s", s)
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
