package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/ingestor"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

var ingestOpts = ingestor.DefaultOptions()
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
	RunE: runIngestCmd,
}

func init() {
	rootCmd.AddCommand(ingestCmd)
	flags := ingestCmd.Flags()

	flags.StringVarP(&ingestOpts.ServerURL, "server", "s", "", "Server URL for remote ingestion (omit for local mode)")
	flags.BoolVarP(&globalScanOnReceive, "scan-on-receive", "S", false, "Continuously scan new HTTP records as they arrive in the database")
	flags.BoolVar(&globalFullNativeScanOnReceive, "full-native-scan-on-receive", false, "Run the full native scan pipeline (discovery + spidering + dynamic-assessment) continuously on received records, instead of dynamic-assessment only")
	flags.BoolVar(&globalDisableFetchResponse, "disable-fetch-response", false, "Store requests without fetching responses during ingestion")
	flags.StringVar(&globalScopeOrigin, "scope-origin", "", "Host scope strictness: all, relaxed, balanced, strict")

	registerInputSourceFlags(flags)
	registerHTTPClientFlags(flags)
	registerScanModuleFlags(flags)
	registerSpecFlags(flags)
}

func runIngestCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	// Copy global flags into ingestOpts
	ingestOpts.Input = globalInput
	ingestOpts.InputFormat = globalInputMode
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

	// Check for blank input: no targets, no input file, and no piped stdin
	hasTargets := len(globalTargets) > 0
	hasInputFile := ingestOpts.Input != "" && ingestOpts.Input != "-"
	hasStdin := fileutil.HasStdin()
	if !hasTargets && !hasInputFile && !hasStdin {
		fmt.Fprintf(os.Stderr, "%s Tip: use %s, %s, or pipe data via stdin\n",
			terminal.InfoSymbol(),
			terminal.Cyan("-t <url>"),
			terminal.Cyan("-i <file>"))
		return fmt.Errorf("no input provided")
	}

	// Validate mutual exclusivity: -t/--target and --spec-url cannot both be set
	if ingestOpts.TargetURL != "" && ingestOpts.UseSpecServers {
		return fmt.Errorf("--target/-t and --spec-url are mutually exclusive")
	}

	// Branch: remote vs local mode
	if ingestOpts.ServerURL != "" {
		if globalScanOnReceive {
			zap.L().Warn("--scan-on-receive/-S is ignored in remote mode; the server handles scanning independently")
		}
		return runRemoteIngest(cmd, args)
	}
	return runLocalIngest(cmd, args)
}

// runRemoteIngest sends requests to a remote vigolium server (existing behavior).
func runRemoteIngest(_ *cobra.Command, _ []string) error {
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
	if err != nil {
		return err
	}

	if globalJSON {
		out := map[string]interface{}{
			"records_submitted": stats.Submitted,
			"errors":            stats.Errors,
			"duration_ms":       stats.Elapsed.Milliseconds(),
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(out)
	}

	elapsed := stats.Elapsed.Seconds()
	rate := float64(0)
	if elapsed > 0 {
		rate = float64(stats.Submitted) / elapsed
	}
	fmt.Printf("\nSubmitted: %d | Errors: %d | Elapsed: %.1fs | Rate: %.1f/s\n",
		stats.Submitted, stats.Errors, elapsed, rate)
	return nil
}

// runLocalIngest fetches HTTP responses and stores request/response pairs in the database.
func runLocalIngest(cmd *cobra.Command, _ []string) error {
	startTime := time.Now()

	// --- 1. Auto-detect format ---
	inputFormat := ingestOpts.InputFormat
	if inputFormat == "urls" && ingestOpts.Input != "-" {
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
		preloadedItems, detectedFormat = tryPreloadAutoDetect(useStdin, filePath)
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
			Targets:    globalTargets,
			FilePath:   filePath,
			Format:     inputFormat,
			UseStdin:   useStdin,
			BufferSize: 100,
		})
		if err != nil {
			return fmt.Errorf("failed to create input source: %w", err)
		}
		inputSource = built
	}
	defer func() { _ = inputSource.Close() }()

	// Configure OpenAPI options if applicable (same pattern as runner.go)
	if inputFormat == "openapi" || inputFormat == "swagger" {
		if fs, ok := inputSource.(*source.FileSource); ok {
			if openapiFormat, ok := fs.Format().(*openapi.Format); ok {
				openapiFormat.SetOpenAPIOptions(openapi.Options{
					BaseURL:              ingestOpts.TargetURL,
					UseSpecServers:       ingestOpts.UseSpecServers,
					Headers:              ingestParseHeaders(ingestOpts.Headers),
					Variables:            ingestParseVariables(ingestOpts.Variables),
					DefaultFallbackValue: ingestOpts.DefaultParam,
				})
			}
		}
	}

	// --- 4. Initialize database ---
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
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
		return fmt.Errorf("invalid database configuration: %w", err)
	}

	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return fmt.Errorf("failed to create database connection: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := db.CreateSchema(ctx); err != nil {
		return fmt.Errorf("failed to create database schema: %w", err)
	}

	repo := database.NewRepository(db)
	zap.L().Info("Database initialized", zap.String("driver", db.Driver()))

	// --- 5. Initialize HTTP stack ---
	opts := types.DefaultOptions()
	opts.Concurrency = ingestOpts.Concurrency
	opts.Timeout = globalTimeout
	opts.ProxyURL = globalProxy
	opts.Verbose = globalVerbose
	opts.Debug = globalDebug
	opts.DumpTraffic = globalDumpTraffic
	opts.MaxPerHost = globalMaxPerHost

	if err := network.Init(opts); err != nil {
		return fmt.Errorf("failed to initialize network: %w", err)
	}

	dedupMgr := dedup.NewManager()
	defer dedupMgr.Close()

	svc := &services.Services{
		Options:      opts,
		DedupManager: dedupMgr,
	}

	hostLimiter := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
		MaxPerHost:    opts.MaxPerHost,
		MaxEntries:    1000,
		EvictAfter:    30 * time.Second,
		EvictInterval: 10 * time.Second,
	})
	defer func() { _ = hostLimiter.Close() }()
	svc.HostLimiter = hostLimiter

	httpRequester, err := http.NewRequester(opts, svc)
	if err != nil {
		return fmt.Errorf("failed to create HTTP requester: %w", err)
	}

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

	// Auto-skip refetch: items that already carry a response (Burp pair, etc.)
	// are written straight to the database so the user-supplied response is
	// preserved verbatim.
	directSaved := 0
	if len(preloadedWithResp) > 0 {
		ingestProjectUUID, projErr := resolveProjectUUID()
		if projErr != nil {
			return projErr
		}
		var ingestScopeMatcher *config.ScopeMatcher
		if settings.Scope.AppliedOnIngest {
			ingestScopeMatcher = config.NewScopeMatcher(settings.Scope, globalTargets...)
		}
		for _, rr := range preloadedWithResp {
			if staticMatcher.IsStaticFile(rr.Request().Path()) {
				continue
			}
			if ingestScopeMatcher != nil {
				if !ingestScopeMatcher.InScopeRequest(
					rr.Service().Host(),
					rr.Request().Path(),
					rr.Request().Header("Content-Type"),
					string(rr.Request().Raw()),
				) {
					continue
				}
			}
			if _, saveErr := repo.SaveRecord(ctx, rr, "ingest-cli", ingestProjectUUID); saveErr != nil {
				zap.L().Debug("Failed to save preloaded record", zap.Error(saveErr))
				continue
			}
			directSaved++
		}
		if !globalSilent && directSaved > 0 {
			fmt.Fprintf(os.Stderr, "%s Saved %d record(s) with attached response (no refetch)\n",
				terminal.InfoSymbol(), directSaved)
		}
	}

	// If everything was preloaded with responses, there is nothing left for
	// the executor or the no-fetch branch to do.
	if len(preloadedItems) > 0 && len(preloadedNeedFetch) == 0 {
		if globalJSON {
			out := map[string]interface{}{
				"records_ingested": directSaved,
				"duration_ms":      time.Since(startTime).Milliseconds(),
				"source":           string(detectedFormat),
			}
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			return encoder.Encode(out)
		}
		elapsed := time.Since(startTime).Seconds()
		if !globalSilent {
			fmt.Fprintf(os.Stderr, "\n%s %s (%.1fs)\n",
				terminal.SuccessSymbol(),
				terminal.Green(fmt.Sprintf("Ingestion completed: %d records ingested", directSaved)),
				elapsed)
		}
		if globalScanOnReceive {
			return runLocalIngestScan(settings, db, repo, "")
		}
		return nil
	}

	if globalDisableFetchResponse {
		// Save requests directly without fetching responses
		var scopeMatcher *config.ScopeMatcher
		if settings.Scope.AppliedOnIngest {
			scopeMatcher = config.NewScopeMatcher(settings.Scope, globalTargets...)
		}

		ingestProjectUUID, projErr := resolveProjectUUID()
		if projErr != nil {
			return projErr
		}

		var count int
		for {
			item, nextErr := inputSource.Next(ctx)
			if nextErr != nil {
				break
			}
			// Always filter static files
			if staticMatcher.IsStaticFile(item.Request.Request().Path()) {
				continue
			}
			// Request-only scope check (no response available)
			if scopeMatcher != nil {
				rr := item.Request
				if !scopeMatcher.InScopeRequest(
					rr.Service().Host(),
					rr.Request().Path(),
					rr.Request().Header("Content-Type"),
					string(rr.Request().Raw()),
				) {
					continue
				}
			}
			if _, saveErr := repo.SaveRecord(ctx, item.Request, "ingest-cli", ingestProjectUUID); saveErr != nil {
				zap.L().Debug("Failed to save record", zap.Error(saveErr))
				continue
			}
			count++
		}

		total := count + directSaved
		if globalJSON {
			out := map[string]interface{}{
				"records_ingested": total,
				"duration_ms":      time.Since(startTime).Milliseconds(),
				"source":           inputFormat,
			}
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			return encoder.Encode(out)
		}

		elapsed := time.Since(startTime).Seconds()
		if !globalSilent {
			fmt.Fprintf(os.Stderr, "\n%s %s (%.1fs)\n",
				terminal.SuccessSymbol(),
				terminal.Green(fmt.Sprintf("Ingestion completed: %d records ingested (no response fetch)", total)),
				elapsed)
		}

		if globalScanOnReceive {
			return runLocalIngestScan(settings, db, repo, "")
		}
		return nil
	}

	executorCfg := core.ExecutorConfig{
		Workers:           opts.Concurrency,
		Services:          svc,
		HTTPRequester:     httpRequester,
		Repository:        repo,
		ScanUUID:          ingestScanUUID,
		StaticFileMatcher: staticMatcher, // always filter static files
	}

	if settings.Scope.AppliedOnIngest {
		executorCfg.ScopeMatcher = config.NewScopeMatcher(settings.Scope, globalTargets...)
		executorCfg.ScopeOnIngest = true
	}

	executor := core.NewExecutor(executorCfg, inputSource, nil, nil)
	_, err = executor.Execute(ctx)
	if err != nil {
		return fmt.Errorf("ingestion failed: %w", err)
	}

	// --- 8. Print summary ---
	totalIngested := executor.Processed() + int64(directSaved)
	summarySource := inputFormat
	if detectedFormat != "" {
		summarySource = string(detectedFormat)
	}
	if globalJSON {
		out := map[string]interface{}{
			"records_ingested": totalIngested,
			"duration_ms":      time.Since(startTime).Milliseconds(),
			"source":           summarySource,
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(out)
	}

	elapsed := time.Since(startTime).Seconds()
	if !globalSilent {
		fmt.Fprintf(os.Stderr, "\n%s %s (%.1fs)\n",
			terminal.SuccessSymbol(),
			terminal.Green(fmt.Sprintf("Ingestion completed: %d records ingested", totalIngested)),
			elapsed)
	}

	if globalScanOnReceive {
		return runLocalIngestScan(settings, db, repo, "")
	}

	return nil
}

// tryPreloadAutoDetect peeks at stdin or file content to recognize a single
// raw HTTP request, a Burp request/response pair, or a curl command. When
// stdin is in play we always consume it here (parsing URL lines too) so the
// downstream source does not race with an already-drained pipe. Files are
// only preloaded when the content looks like raw HTTP / burp-pair / curl —
// URL/HAR/OpenAPI files keep streaming through the existing FileSource. The
// file branch caps the peek at 4 MiB.
func tryPreloadAutoDetect(useStdin bool, filePath string) ([]*httpmsg.HttpRequestResponse, detect.StdinFormat) {
	const maxPeekBytes = 4 * 1024 * 1024

	var content string
	switch {
	case useStdin:
		data, err := io.ReadAll(os.Stdin)
		if err != nil || len(data) == 0 {
			return nil, ""
		}
		content = string(data)
	case filePath != "":
		f, err := os.Open(filePath)
		if err != nil {
			return nil, ""
		}
		defer func() { _ = f.Close() }()
		buf, err := io.ReadAll(io.LimitReader(f, maxPeekBytes+1))
		if err != nil || len(buf) == 0 || len(buf) > maxPeekBytes {
			return nil, ""
		}
		content = string(buf)
	default:
		return nil, ""
	}

	format := detect.DetectStdinFormat(content)
	// File mode only preloads HTTP-shaped content; URL lists keep streaming.
	if !useStdin && format == detect.FormatURLs {
		return nil, ""
	}

	items, err := detect.ParseStdinContent(content, format)
	if err != nil {
		zap.L().Debug("ingest: auto-detect parse failed, falling back",
			zap.String("format", string(format)), zap.Error(err))
		return nil, ""
	}
	zap.L().Info("Auto-detected ingest input",
		zap.String("format", string(format)), zap.Int("records", len(items)))
	return items, format
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

// detectInputFormat auto-detects the input format from the file extension and content.
func detectInputFormat(input string) string {
	ext := strings.ToLower(filepath.Ext(input))
	if ext == ".json" || ext == ".yaml" || ext == ".yml" {
		data, err := os.ReadFile(input)
		if err != nil {
			return ""
		}
		if openapi.IsOpenAPISpec(data) {
			return "openapi"
		}
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
	opts.Concurrency = globalConcurrency
	opts.Timeout = globalTimeout
	opts.ProxyURL = globalProxy
	opts.Verbose = globalVerbose
	opts.Silent = globalSilent
	opts.Debug = globalDebug
	opts.DumpTraffic = globalDumpTraffic
	opts.JSONOutput = globalJSON
	opts.MaxPerHost = globalMaxPerHost
	opts.MaxHostError = globalMaxHostError
	opts.MaxFindingsPerModule = globalMaxFindingsPerModule
	opts.ConfigPath = globalConfig

	// Modules are already resolved via resolveModules()
	opts.Modules = ingestOpts.EnableModules
	opts.NoTechFilter = globalNoTechFilter

	// Create a Scan record if none provided
	ingestScanProjectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}
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
