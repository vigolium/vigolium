package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/ingestor"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/httpstack"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

var ingestOpts = ingestor.DefaultOptions()

// ingestKeepBlocked backs --keep-blocked (core.ExecutorConfig.KeepBlocked).
var ingestKeepBlocked bool
var ingestScanUUID string

var ingestCmd = &cobra.Command{
	Use:   "ingest",
	Short: "Ingest HTTP requests into database (locally or via server)",
	Long: `Push HTTP traffic into the database without scanning. Accepts the same input formats as scan: URLs, OpenAPI / Swagger, Burp XML, cURL, Nuclei, HAR.

Two modes:
  • Local — writes directly to the configured SQLite/Postgres database (default)
  • Remote — POSTs to a running 'vigolium server' via -s/--server (requires VIGOLIUM_API_KEY)

Stdin and -i auto-detect the content shape: a URL list, a raw HTTP request,
a Burp request/response pair (split by '***'), or a curl command. Inputs that
already carry a response (Burp pair, HAR, …) are stored as-is — no live
refetch — so the response you pasted is what lands in the database.`,
	Args: cobra.NoArgs,
	RunE: runIngestCmd,
}

func init() {
	rootCmd.AddCommand(ingestCmd)
	flags := ingestCmd.Flags()

	flags.StringVarP(&ingestOpts.ServerURL, "server", "s", "", "Server URL for remote ingestion (omit for local mode)")
	registerScanOnReceiveFlags(flags, "Continuously scan new HTTP records as they arrive in the database")
	flags.BoolVar(&globalFullNativeScanOnReceive, "full-native-scan-on-receive", false, "Run the full native scan pipeline (discovery + spidering + dynamic-assessment) continuously on received records, instead of dynamic-assessment only")
	flags.BoolVar(&globalDisableFetchResponse, "disable-fetch-response", false, "Store requests without fetching responses during ingestion")
	flags.BoolVar(&ingestKeepBlocked, "keep-blocked", false, "Store a fetched response the block detector classifies as a WAF/bot-wall page (remark blocked:<reason>) instead of dropping the record")
	flags.StringVar(&globalScopeOrigin, "scope-origin", "", scopeOriginFlagUsage)

	registerInputSourceFlags(flags)
	registerIngestBatchFlags(flags)
	// Make a repeated -i accumulate rather than overwrite. Installed after the
	// flag exists, and only on ingest: `scan -i` is single-source by design.
	installIngestRepeatableInput(ingestCmd)
	registerHTTPClientFlags(flags)
	registerScanModuleFlags(flags)
	registerSpecFlags(flags)
}

// ingestFollowUpQuery returns the read that actually shows what an ingest just
// stored.
//
// It used to interpolate the INPUT FORMAT into --source: `--source har`,
// `--source urls`, `--source openapi`. Those are two disjoint vocabularies that
// overlap only on the token `burp` — --source takes a record-source label
// (ingest-cli, ingest-server, ingest-proxy, scanner, finding, burp, caido) — so
// the hint reliably returned zero rows right after a successful ingest, which
// reads as "the ingest silently did nothing". A plain recency listing answers
// the question the hint is for without pretending to filter by provenance.
func ingestFollowUpQuery() []string {
	return []string{"traffic", "--json", "-n", "20"}
}

func runIngestCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	// Copy global flags into ingestOpts
	ingestOpts.Input = globalInput
	ingestOpts.InputFormat = globalInputMode
	ingestOpts.TargetFiles = globalTargetFiles
	ingestOpts.RateLimit = globalRateLimit
	ingestOpts.Concurrency = globalConcurrency
	ingestOpts.EnableModules = resolveModules()
	ingestOpts.UseSpecServers = globalSpecURL
	ingestOpts.Headers = globalSpecHeader
	ingestOpts.Variables = globalSpecVar
	ingestOpts.DefaultParam = globalSpecDefault
	ingestScanUUID = globalScanUUID

	// API key from environment only
	ingestOpts.APIKey = os.Getenv("VIGOLIUM_API_KEY")

	// Use global -t as spec base URL
	if len(globalTargets) > 0 {
		ingestOpts.TargetURL = globalTargets[0]
	}

	// Check for blank input: no targets, no input file, no target file, and no
	// piped stdin
	hasTargets := len(globalTargets) > 0
	hasInputFile := ingestOpts.Input != "" && ingestOpts.Input != "-"
	hasTargetFiles := len(globalTargetFiles) > 0
	hasStdin := fileutil.HasStdin()
	// --dir is input in its own right: the directory expands into sources below,
	// after this check, so it must count here or `ingest --dir X` never runs.
	hasDir := strings.TrimSpace(ingestDir) != ""
	if !hasTargets && !hasInputFile && !hasTargetFiles && !hasDir && !hasStdin {
		fmt.Fprintf(os.Stderr, "%s Tip: use %s, %s, %s, %s, or pipe data via stdin\n",
			terminal.InfoSymbol(),
			terminal.Cyan("-t <url>"),
			terminal.Cyan("-T <file>"),
			terminal.Cyan("-i <file>"),
			terminal.Cyan("--dir <dir>"))
		return usageErrorf("no input provided: pass -t, -T, -i or --dir, or pipe data on stdin")
	}

	// Decide whether stdin is really this command's input, by the same rule the
	// scanning commands use.
	//
	// The old test was `Input == "-" && !hasStdin`, which only dropped stdin for
	// a TTY. But -i defaults to "-" (see flag_helpers.go) and HasStdin() is true
	// for ANY stdin that is not a character device, so `vigolium ingest -t URL`
	// under an inherited pipe - a CI runner, an agent harness - kept Input at "-"
	// and handed os.Stdin to the parser. That read has no --input-read-timeout
	// behind it, so unlike the scan path it hung forever rather than for three
	// minutes. A typed `-i -` still asks for stdin explicitly.
	if useStdin, _ := resolveStdinInput(hasStdin, cmd.Flags().Changed("input"), globalInput, len(globalTargets), len(globalTargetFiles)); !useStdin {
		if ingestOpts.Input == "-" {
			ingestOpts.Input = ""
		}
	}

	// Validate mutual exclusivity: -t/--target and --spec-url cannot both be set
	if ingestOpts.TargetURL != "" && ingestOpts.UseSpecServers {
		return usageErrorf("--target/-t and --spec-url are mutually exclusive")
	}

	// Resolve the full source list (repeated -i plus --dir). One process handles
	// all of them: N subprocesses against one SQLite file is the shape this
	// removes, not a concurrency problem to tune.
	sources, srcErr := ingestInputSources(ingestOpts.Input)
	if srcErr != nil {
		return asUsageError(srcErr)
	}

	// Branch: remote vs local mode
	remote := ingestOpts.ServerURL != ""
	run := runLocalIngest
	if remote {
		if globalScanOnReceive {
			zap.L().Warn("--scan-on-receive is ignored in remote mode; the server handles scanning independently")
		}
		run = runRemoteIngest
	}

	// Multi-source: run the same path once per source, swapping only the input.
	// A failing source does not discard its siblings — the point of a batch is
	// that one bad HAR in fifty does not cost the other forty-nine — but the
	// command still exits non-zero and names how many failed.
	//
	// Only an EMPTY list means stdin: ingestInputSources drops "-" and "", so a
	// stdin run resolves to no sources and keeps ingestOpts.Input as resolved
	// above. A single source is used as is — it may be the one file a --dir
	// matched, which ingestOpts.Input never held.
	switch {
	case len(sources) == 0:
		sources = []string{ingestOpts.Input}
	case len(sources) > 1:
		announceIngestBatch(sources)
	}

	// The summary is emitted ONCE, here, from the accumulated outcome. It used
	// to be printed by each per-source run, so a batch of fifty HARs with -j
	// wrote fifty top-level JSON documents to stdout — a stream no single
	// json.Unmarshal can read.
	started := time.Now()
	var total ingestOutcome
	failedSources := 0
	for _, src := range sources {
		ingestOpts.Input = src
		out, err := run(cmd, args)
		total.add(out)
		if err != nil {
			if len(sources) == 1 {
				return err
			}
			failedSources++
			fmt.Fprintf(os.Stderr, "%s ingest %s: %v\n", terminal.WarnPrefix(), src, err)
		}
	}
	return reportIngest(total, remote, failedSources, len(sources), time.Since(started))
}

// reportIngest emits the one completion document for the whole invocation and
// decides the exit code.
//
// What it reports is what the database HOLDS. The old line printed
// `executor.Processed() + directSaved` — items attempted — so an ingest whose
// every fetch failed announced "30 records ingested" and exited 0 over a table
// with no rows in it. A run that could not store everything it read now says so
// and exits non-zero.
func reportIngest(out ingestOutcome, remote bool, failedSources, totalSources int, elapsed time.Duration) error {
	if remote {
		return reportRemoteIngest(out, failedSources, totalSources, elapsed)
	}

	if globalJSON {
		// items is [] rather than nil: the envelope's contract is that `items`
		// is the canonical collection, and a JSON null breaks every consumer
		// that iterates or measures it.
		items := make([]any, 0, len(out.Records))
		for _, r := range out.Records {
			items = append(items, r)
		}
		env := newAgentEnvelope("ingest", "", items, out.Stored, 0, 0).
			asMutation(out.Stored > 0, "ingest", false)
		env.DBPath = resolvedReadDBPath()
		env.With("records_ingested", out.Stored).
			With("records_failed", out.Failed).
			With("records_skipped", out.Skipped).
			With("duration_ms", elapsed.Milliseconds()).
			With("input_format", strings.Join(out.Formats, ",")).
			With("record_source", database.RecordSourceIngestCLI).
			With("items_truncated", out.RecordsTruncated)
		if len(out.Reasons) > 0 {
			env.With("failure_reasons", out.Reasons).With("failures", out.Failures)
		}
		// The obvious next step after an ingest is to look at what landed.
		env.WithQuery(ingestFollowUpQuery()...)
		if err := writeAgentJSON(env); err != nil {
			return err
		}
	} else if !globalSilent {
		fmt.Fprintf(os.Stderr, "\n%s\n", ingestSummaryLine(out, elapsed))
	}

	if out.Failed > 0 {
		return codedErrorf(errCodeIngestIncomplete,
			"stored %d of %d record(s); %d could not be stored%s",
			out.Stored, out.Stored+out.Failed, out.Failed, ingestFailureHint(out.Reasons))
	}
	if failedSources > 0 {
		return fmt.Errorf("%d of %d ingest source(s) failed", failedSources, totalSources)
	}
	return nil
}

// ingestFailureHint names why records were not stored, most common reason
// first, and the flag that fixes the dominant one. The per-record list is in
// -j's `failures`.
func ingestFailureHint(reasons map[string]int64) string {
	if len(reasons) == 0 {
		return " (no response to store, or the write was refused)"
	}
	keys := core.SortedDropReasons(reasons)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, reasons[k]))
	}
	hint := " — " + strings.Join(parts, ", ")
	switch keys[0] {
	case core.DropBlocked:
		hint += ". The answers were WAF/bot-wall pages: --keep-blocked stores them marked, --disable-fetch-response stores the requests without fetching"
	case core.DropFetchError, core.DropQuarantined:
		hint += ". The hosts did not answer: --disable-fetch-response stores the requests without fetching"
	case core.DropBudget:
		hint += ". The request budget ran out: raise --max-requests / --max-requests-per-host"
	case core.DropOutOfScope:
		hint += ". The answers were out of scope and scope.applied_on_ingest is set"
	}
	return hint + " (per-record reasons: -j, `failures`)"
}

// ingestSummaryLine renders the human completion line. A run that stored
// everything keeps the wording it has always had; one that did not leads with
// the shortfall rather than burying it after a success symbol.
func ingestSummaryLine(out ingestOutcome, elapsed time.Duration) string {
	suffix := ""
	if globalDisableFetchResponse {
		suffix = " (no response fetch)"
	}
	if out.Skipped > 0 {
		suffix += fmt.Sprintf(", %d skipped by scope/static filters", out.Skipped)
	}
	if out.Failed > 0 {
		return fmt.Sprintf("%s %s (%.1fs)",
			terminal.ErrorSymbol(),
			terminal.Red(fmt.Sprintf("Ingestion incomplete: %d of %d records stored, %d failed%s",
				out.Stored, out.Stored+out.Failed, out.Failed, suffix)),
			elapsed.Seconds())
	}
	return fmt.Sprintf("%s %s (%.1fs)",
		terminal.SuccessSymbol(),
		terminal.Green(fmt.Sprintf("Ingestion completed: %d records ingested%s", out.Stored, suffix)),
		elapsed.Seconds())
}

// reportRemoteIngest keeps remote mode's established output shape — it counts
// HTTP submissions, not rows, because the server owns the store — while still
// emitting exactly one document for the whole invocation.
func reportRemoteIngest(out ingestOutcome, failedSources, totalSources int, elapsed time.Duration) error {
	if globalJSON {
		// The envelope around the counters remote mode always reported: total is
		// the submissions, and changed says whether the server accepted any.
		env := newAgentEnvelope("ingest", "", []any{}, out.Submitted, 0, 0).
			asMutation(out.Submitted > 0, "submit", false)
		env.With("records_submitted", out.Submitted).
			With("errors", out.Errors).
			With("duration_ms", elapsed.Milliseconds())
		if err := writeAgentJSON(env); err != nil {
			return err
		}
	} else {
		rate := float64(0)
		if secs := elapsed.Seconds(); secs > 0 {
			rate = float64(out.Submitted) / secs
		}
		fmt.Printf("\nSubmitted: %d | Errors: %d | Elapsed: %.1fs | Rate: %.1f/s\n",
			out.Submitted, out.Errors, elapsed.Seconds(), rate)
	}
	if failedSources > 0 {
		return fmt.Errorf("%d of %d ingest source(s) failed", failedSources, totalSources)
	}
	return nil
}

// runRemoteIngest sends requests to a remote vigolium server (existing behavior).
func runRemoteIngest(_ *cobra.Command, _ []string) (ingestOutcome, error) {
	var outcome ingestOutcome

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		zap.L().Info("Interrupt received, stopping...")
		cancel()
	}()

	stats, err := ingestor.Run(ctx, ingestOpts)
	// Stats first: Run reports what it submitted even when an input source
	// failed, and the caller adds this outcome to its total before it looks
	// at the error.
	outcome.Submitted = stats.Submitted
	outcome.Errors = stats.Errors
	return outcome, err
}

// runLocalIngest fetches HTTP responses and stores request/response pairs in
// the database, and reports what it actually stored. The caller owns the
// summary; see reportIngest.
func runLocalIngest(cmd *cobra.Command, _ []string) (ingestOutcome, error) {
	var outcome ingestOutcome

	// --- 1. Auto-detect format ---
	// -I given: the operator's format stands (no sniffing, even for -I urls).
	formatExplicit := cmd.Flags().Changed("input-mode")
	ingestInputFormatExplicit = formatExplicit
	inputFormat := ingestOpts.InputFormat
	if inputFormat == "urls" && ingestOpts.Input != "-" && !formatExplicit {
		if detected := detectInputFormat(ingestOpts.Input); detected != "" {
			inputFormat = detected
			zap.L().Info("Auto-detected input format", zap.String("format", inputFormat))
		}
	}

	// --- 2. OpenAPI defaults: auto-enable UseSpecServers when no -t given ---
	if (inputFormat == "openapi" || inputFormat == "swagger") &&
		ingestOpts.TargetURL == "" && !ingestOpts.UseSpecServers {
		ingestOpts.UseSpecServers = true
		zap.L().Info("Auto-enabled --spec-url (no -t provided)")
	}

	// --- 2b. Stdin/file content auto-detect (raw HTTP, burp-pair, curl) ---
	// When the user did not pin a format (-I), peek the bytes and try to parse
	// them as a single raw HTTP request, a Burp request/response pair, or a
	// curl command. URL line-by-line stdin still falls through to the existing
	// streaming source.
	useStdin := ingestOpts.Input == "-"
	var filePath string
	if !useStdin {
		filePath = ingestOpts.Input
	}

	var preloadedItems []*httpmsg.HttpRequestResponse
	var detectedFormat detect.StdinFormat
	if !cmd.Flags().Changed("input-mode") && inputFormat == "urls" {
		var preloadErr error
		preloadedItems, detectedFormat, preloadErr = tryPreloadAutoDetect(useStdin, filePath)
		// Stdin is consumed here for good; there is no second read to fall back
		// to. A read that failed must stop the run and say why, not continue to
		// a streaming source that can only report an empty pipe.
		if preloadErr != nil {
			return outcome, fmt.Errorf("failed to read ingest input: %w", preloadErr)
		}
	}
	outcome.noteFormat(inputFormat)
	if detectedFormat != "" {
		outcome.Formats = []string{string(detectedFormat)}
	}

	if len(preloadedItems) > 0 && detectedFormat != detect.FormatURLs {
		printIngestPreview(detectedFormat, preloadedItems)
	}

	// Partition preloaded items: those carrying a response are saved as-is
	// later (no refetch); those without one feed the executor.
	preloadedWithResp, preloadedNeedFetch := partitionPreloaded(preloadedItems)

	// --- 3. Create InputSource ---
	var inputSource source.InputSource
	if len(preloadedItems) > 0 {
		// Auto-detected raw HTTP / burp-pair / curl: only items that still
		// need a live response go through the executor. The rest are saved
		// directly below so the response the user pasted is preserved.
		inputSource = source.NewSliceSource(preloadedNeedFetch, ingestOpts.EnableModules)
	} else {
		built, err := source.NewInputSource(source.SourceConfig{
			Targets:        globalTargets,
			FilePath:       filePath,
			FilePaths:      globalTargetFiles,
			Format:         inputFormat,
			FormatExplicit: formatExplicit,
			UseStdin:       useStdin,
			BufferSize:     100,
		})
		if err != nil {
			return outcome, fmt.Errorf("failed to create input source: %w", err)
		}
		inputSource = built
	}
	// If raw-HTTP/burp/curl was preloaded from stdin or -i but -T target files
	// were also supplied, fold those URL-list files in so they aren't dropped
	// (the preloaded branch above builds a slice source that ignores them).
	if len(preloadedItems) > 0 && len(globalTargetFiles) > 0 {
		tfSrc, tfErr := source.NewInputSource(source.SourceConfig{
			FilePaths:      globalTargetFiles,
			Format:         inputFormat,
			FormatExplicit: formatExplicit,
			BufferSize:     100,
		})
		if tfErr != nil {
			return outcome, fmt.Errorf("failed to create target-file source: %w", tfErr)
		}
		inputSource = source.NewMultiSource(inputSource, tfSrc)
	}
	defer func() { _ = inputSource.Close() }()

	// Configure spec-format options (OpenAPI, WSDL, Postman) on the file
	// parser — the same source.ApplySpecOptions scan and the runner use, so it
	// lands even when -t/-T is combined with -i and covers a sniffed spec.
	source.ApplySpecOptions(inputSource, source.SpecOptions{
		BaseURL:              ingestOpts.TargetURL,
		UseSpecServers:       ingestOpts.UseSpecServers,
		Headers:              ingestParseHeaders(ingestOpts.Headers),
		Variables:            ingestParseVariables(ingestOpts.Variables),
		DefaultFallbackValue: ingestOpts.DefaultParam,
	})

	// --- 4. Initialize database ---
	// Global → the resolved project's overlay: the scope judged below (static
	// filtering, --scan-on-receive admission) is the project's, as for `scan`.
	settings, err := loadProjectSettings(globalConfig)
	if err != nil {
		return outcome, err
	}

	// Override scope origin mode if --scope-origin flag is set
	if globalScopeOrigin != "" {
		settings.Scope.CLIOriginMode = globalScopeOrigin
	}

	if globalDB != "" {
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = globalDB
	}

	if err := settings.Database.Validate(); err != nil {
		return outcome, fmt.Errorf("invalid database configuration: %w", err)
	}

	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return outcome, fmt.Errorf("failed to create database connection: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := db.CreateSchema(ctx); err != nil {
		return outcome, fmt.Errorf("failed to create database schema: %w", err)
	}

	repo := database.NewRepository(db)
	zap.L().Info("Database initialized", zap.String("driver", db.Driver()))

	// --- 5. Initialize HTTP stack ---
	opts := types.DefaultOptions()
	globalFlagsToOptions(opts)
	opts.Concurrency = ingestOpts.Concurrency
	stack, err := httpstack.New(httpstack.Config{Options: opts})
	if err != nil {
		return outcome, err
	}
	defer stack.Close()
	svc, httpRequester := stack.Services, stack.Requester

	// --- 6. Signal handling ---
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		zap.L().Info("Interrupt received, stopping...")
		cancel()
	}()

	// --- 7. Run ingestion ---
	// Always create a matcher for static file filtering (unconditional)
	staticMatcher := config.NewScopeMatcher(settings.Scope, globalTargets...)

	// Every record this function writes — the direct-save paths below and the
	// executor further down — belongs to the same project, so resolve it once.
	// Without it records fall through to the default project and become
	// invisible to every project-scoped read (scan feed, findings, exports).
	ingestProjectUUID, projErr := resolveProjectUUID()
	if projErr != nil {
		return outcome, projErr
	}

	// One saver for every record that arrives with its response already
	// attached, whichever path it came in on: the auto-detected preload below,
	// and — through preloadedResponseSource — the format parsers, which used to
	// hand their captured responses to the executor to be discarded and
	// re-fetched.
	saver := &ingestSaver{
		repo:          repo,
		projectUUID:   ingestProjectUUID,
		staticMatcher: staticMatcher,
	}
	if settings.Scope.AppliedOnIngest {
		saver.scopeMatcher = config.NewScopeMatcher(settings.Scope, globalTargets...)
	}

	// Auto-skip refetch: items that already carry a response (Burp pair, etc.)
	// are written straight to the database so the user-supplied response is
	// preserved verbatim.
	for _, rr := range preloadedWithResp {
		saver.save(ctx, rr)
	}

	// If everything was preloaded with responses, there is nothing left for
	// the executor or the no-fetch branch to do.
	if len(preloadedItems) > 0 && len(preloadedNeedFetch) == 0 {
		outcome.add(saver.result())
		noteIngestNoRefetch(outcome.Stored)
		if globalScanOnReceive {
			return outcome, runLocalIngestScan(settings, db, repo, "")
		}
		return outcome, nil
	}

	if globalDisableFetchResponse {
		// Store what the input carries without fetching anything: the same
		// filters and the same accounting as the direct-save path, because it
		// is the same write.
		for {
			item, nextErr := inputSource.Next(ctx)
			if nextErr != nil {
				break
			}
			if item == nil || item.Request == nil {
				continue
			}
			saver.save(ctx, item.Request)
			item.Complete()
		}
		outcome.add(saver.result())
		noteIngestNoRefetch(outcome.Stored)
		if globalScanOnReceive {
			return outcome, runLocalIngestScan(settings, db, repo, "")
		}
		return outcome, nil
	}

	executorCfg := core.ExecutorConfig{
		Workers:           opts.Concurrency,
		Services:          svc,
		HTTPRequester:     httpRequester,
		Repository:        repo,
		ScanUUID:          ingestScanUUID,
		ProjectUUID:       ingestProjectUUID,
		StaticFileMatcher: staticMatcher, // always filter static files
		KeepBlocked:       ingestKeepBlocked,
		OnRecordStored:    saver.noteStored,
	}

	if settings.Scope.AppliedOnIngest {
		executorCfg.ScopeMatcher = config.NewScopeMatcher(settings.Scope, globalTargets...)
		executorCfg.ScopeOnIngest = true
	}

	// Records that already carry a response never reach the executor: a capture
	// is ingested as captured, so ingesting one does not require every origin in
	// it to still resolve.
	executor := core.NewExecutor(executorCfg,
		&preloadedResponseSource{inner: inputSource, save: saver.save}, nil, nil)
	_, err = executor.Execute(ctx)
	if err != nil {
		outcome.add(saver.result())
		return outcome, fmt.Errorf("ingestion failed: %w", err)
	}

	// --- 8. Account for what was stored ---
	outcome.add(saver.result())
	noteIngestNoRefetch(outcome.Stored)
	outcome.add(executorIngestOutcome(executor))

	if globalScanOnReceive {
		return outcome, runLocalIngestScan(settings, db, repo, "")
	}

	return outcome, nil
}

// executorIngestOutcome reads one executor's run as rows rather than attempts.
//
// Stored and StoreFailed are the executor's own tallies. The rest is a
// partition of what it processed: an item that never got a response stored
// nothing and is a failure; one that answered and was neither stored nor
// refused was dropped by a policy filter (static-asset carve-out, body-size
// gate, out-of-scope) and is a skip. Items the executor's PRE-fetch filters
// dropped never reach a worker, so they are outside this accounting entirely.
func executorIngestOutcome(executor *core.Executor) ingestOutcome {
	stored := executor.Stored()
	storeFailed := executor.StoreFailed()
	unreached := nonNegative(executor.Processed() - executor.Responded())
	out := ingestOutcome{
		Stored:  stored,
		Failed:  storeFailed + unreached,
		Skipped: nonNegative(executor.Responded() - stored - storeFailed),
	}
	if reasons := executor.DropReasons(); len(reasons) > 0 {
		out.Reasons = reasons
		out.Failures = executor.DropSamples()
	}
	return out
}

func nonNegative(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}

// noteIngestNoRefetch reports how many records were stored with the response
// they arrived with. Written once per source, on stderr, and only when it
// happened.
func noteIngestNoRefetch(stored int64) {
	if globalSilent || stored <= 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "%s Saved %d record(s) with attached response (no refetch)\n",
		terminal.InfoSymbol(), stored)
}

// tryPreloadAutoDetect peeks at stdin or file content to recognize a single
// raw HTTP request, a Burp request/response pair, or a curl command. When
// stdin is in play we always consume it here (parsing URL lines too) so the
// downstream source does not race with an already-drained pipe. Files are
// only preloaded when the content looks like raw HTTP / burp-pair / curl —
// URL/HAR/OpenAPI files keep streaming through the existing FileSource. The
// file branch caps the peek at 4 MiB.
//
// A stdin read FAILURE is returned rather than folded into the empty result.
// The old code turned every error into "nothing detected" and let the run
// continue to the streaming source, which then read an already-exhausted pipe
// and reported zero items — so a deadline that fired and a genuinely empty pipe
// were indistinguishable, and the one that needed reporting was the one that
// looked like success.
func tryPreloadAutoDetect(useStdin bool, filePath string) ([]*httpmsg.HttpRequestResponse, detect.StdinFormat, error) {
	const maxPeekBytes = 4 * 1024 * 1024

	var content string
	switch {
	case useStdin:
		data, err := readStdin()
		if err != nil {
			return nil, "", err
		}
		if len(data) == 0 {
			return nil, "", nil
		}
		content = string(data)
	case filePath != "":
		f, err := os.Open(filePath)
		if err != nil {
			return nil, "", nil
		}
		defer func() { _ = f.Close() }()
		buf, err := io.ReadAll(io.LimitReader(f, maxPeekBytes+1))
		if err != nil || len(buf) == 0 || len(buf) > maxPeekBytes {
			return nil, "", nil
		}
		content = string(buf)
	default:
		return nil, "", nil
	}

	format := detect.DetectStdinFormat(content)
	// File mode only preloads HTTP-shaped content; URL lists keep streaming.
	if !useStdin && format == detect.FormatURLs {
		return nil, "", nil
	}

	items, err := detect.ParseStdinContent(content, format)
	if err != nil {
		zap.L().Debug("ingest: auto-detect parse failed, falling back",
			zap.String("format", string(format)), zap.Error(err))
		return nil, "", nil
	}
	zap.L().Info("Auto-detected ingest input",
		zap.String("format", string(format)), zap.Int("records", len(items)))
	return items, format, nil
}

// partitionPreloaded splits items into those carrying an attached response
// (saved as-is, no refetch) and those needing a live response (fed to the
// executor).
func partitionPreloaded(items []*httpmsg.HttpRequestResponse) (withResp, needFetch []*httpmsg.HttpRequestResponse) {
	for _, rr := range items {
		if rr == nil {
			continue
		}
		if rr.HasResponse() {
			withResp = append(withResp, rr)
		} else {
			needFetch = append(needFetch, rr)
		}
	}
	return withResp, needFetch
}

// printIngestPreview writes a stderr summary of the auto-detected input —
// format, record count, and the first 5 items (method, URL, status, content
// length). Suppressed when --silent is set.
func printIngestPreview(format detect.StdinFormat, items []*httpmsg.HttpRequestResponse) {
	if globalSilent || len(items) == 0 {
		return
	}

	const previewCap = 5
	withResp := 0
	for _, rr := range items {
		if rr != nil && rr.HasResponse() {
			withResp++
		}
	}

	header := fmt.Sprintf("Detected %s — %d record(s)", format, len(items))
	if withResp > 0 {
		header += fmt.Sprintf(" (%d with attached response)", withResp)
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), terminal.Cyan(header))

	limit := len(items)
	if limit > previewCap {
		limit = previewCap
	}
	for i := 0; i < limit; i++ {
		fmt.Fprintln(os.Stderr, formatIngestPreviewLine(i+1, items[i]))
	}
	if remaining := len(items) - limit; remaining > 0 {
		fmt.Fprintf(os.Stderr, "  %s\n", terminal.Gray(fmt.Sprintf("… and %d more", remaining)))
	}
}

// formatIngestPreviewLine renders a single preview row.
func formatIngestPreviewLine(idx int, rr *httpmsg.HttpRequestResponse) string {
	if rr == nil || rr.Request() == nil {
		return fmt.Sprintf("  [%d] (invalid record)", idx)
	}

	url := ""
	if u, err := rr.URL(); err == nil {
		url = u.String()
	}
	if url == "" {
		url = rr.Request().Path()
	}

	method := rr.Request().Method()
	reqLen := len(rr.Request().Body())

	if rr.HasResponse() {
		resp := rr.Response()
		ct := resp.Header("Content-Type")
		if ct == "" {
			ct = "-"
		}
		return fmt.Sprintf("  [%d] %s %s  →  %d  ct=%s  cl=%d  (req cl=%d)",
			idx, method, url, resp.StatusCode(), ct, len(resp.Body()), reqLen)
	}
	return fmt.Sprintf("  [%d] %s %s  (request only, req cl=%d)", idx, method, url, reqLen)
}

// detectInputFormat names the format of an -i input given with the URL-list
// default when the caller must know it before the source is built: OpenAPI
// (--spec-url is auto-enabled without -t) and WSDL (including a WCF/ASMX URL).
// Files are classified by source.DetectFormat, the one content detector.
//
// Every other format is left to NewFileSource, which runs the same detector
// per file. Returning it here would pin the format for the -T target files
// built alongside -i, and would bypass ingest's preload path that keeps the
// response of a pasted Burp request/response pair.
func detectInputFormat(input string) string {
	// URL convenience: a bare WCF/ASMX service endpoint (or an explicit ?wsdl
	// URL) is a WSDL source. The wsdl loader fetches ?singleWsdl / ?WSDL for the
	// bare .svc/.asmx forms. A remote input has no file head to sniff, so decide
	// by URL shape here.
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		lower := strings.ToLower(input)
		pathPart := lower
		if i := strings.IndexByte(pathPart, '?'); i >= 0 {
			pathPart = pathPart[:i]
		}
		if strings.HasSuffix(pathPart, ".svc") || strings.HasSuffix(pathPart, ".asmx") ||
			strings.Contains(lower, "?wsdl") || strings.Contains(lower, "?singlewsdl") {
			return "wsdl"
		}
		return ""
	}

	det, err := source.DetectFormat(input)
	if err != nil {
		return ""
	}
	switch det.Format {
	case "openapi", "wsdl":
		return det.Format
	}
	return ""
}

// ingestParseHeaders parses header strings in "Name: Value" format.
func ingestParseHeaders(headers []string) map[string]string {
	result := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

// ingestParseVariables parses variable strings in "key=value" format.
func ingestParseVariables(variables []string) map[string]string {
	result := make(map[string]string)
	for _, v := range variables {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

// runLocalIngestScan runs a vulnerability scan on ingested records using a one-shot DB source.
// If scanUUID is empty, a new Scan record is created automatically.
func runLocalIngestScan(settings *config.Settings, db *database.DB, repo *database.Repository, scanUUID string) error {
	if !globalSilent {
		fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.InfoSymbol(), terminal.Cyan("Starting scan on ingested records..."))
	}

	// Build scan options from global flags
	opts := types.DefaultOptions()
	globalScanFlagsToOptions(opts)

	// Modules are already resolved via resolveModules()
	opts.Modules = ingestOpts.EnableModules

	// Create a Scan record if none provided
	ingestScanProjectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}
	// The runner must scan under the same project the Scan row below is created
	// with: the record feed resolves its project from that row, so leaving this
	// empty makes the executor write findings to the default project while the
	// feed reads this one — the scan then streams findings that its own project
	// can never see.
	opts.ProjectUUID = ingestScanProjectUUID
	// A capture names many hosts; scan only its primary one unless -t or
	// --scope-origin all says otherwise.
	opts.ScopeTargets, opts.ScopeCensus = ingestScanScope(settings)
	if scanUUID == "" {
		scan := &database.Scan{
			UUID:        fmt.Sprintf("scan-%d", time.Now().UnixNano()),
			ProjectUUID: ingestScanProjectUUID,
			Name:        "ingest-scan",
			Status:      "running",
			Modules:     strings.Join(opts.Modules, ","),
			ScanSource:  "cli",
			ScanMode:    "full",
			StartedAt:   time.Now(),
		}
		if err := repo.CreateScanWithCursor(context.Background(), scan); err != nil {
			return fmt.Errorf("failed to create scan: %w", err)
		}
		scanUUID = scan.UUID
	}

	// Create one-shot DB input source with cursor tracking
	dbSource := database.NewOneShotDBInputSource(db, repo, scanUUID)

	scanRunner, err := runner.NewWithInputSource(opts, dbSource)
	if err != nil {
		return fmt.Errorf("failed to create scan runner: %w", err)
	}
	defer scanRunner.Close()

	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(repo)

	runErr := scanRunner.RunNativeScan()
	webhook.FireNativeScan(settings, repo, opts.ScanUUID)
	if runErr != nil {
		return fmt.Errorf("scan failed: %w", runErr)
	}

	if !globalSilent {
		fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.Green(terminal.SymbolSparkle), terminal.BoldGreen("Native scan completed"))
	}

	return nil
}

// ingestInputFormatExplicit records whether -I was typed for the current
// ingest (the derived scan scope must judge the format the parser used).
var ingestInputFormatExplicit bool
