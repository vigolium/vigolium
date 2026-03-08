package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

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
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var ingestOpts = ingestor.DefaultOptions()
var ingestScanUUID string

var ingestCmd = &cobra.Command{
	Use:   "ingest",
	Short: "Ingest HTTP requests into database (locally or via server)",
	RunE:  runIngestCmd,
}

func init() {
	rootCmd.AddCommand(ingestCmd)
	flags := ingestCmd.Flags()

	flags.StringVarP(&ingestOpts.ServerURL, "server", "s", "", "Server URL for remote ingestion (omit for local mode)")
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
	ingestScanUUID = globalScanID

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
		cmd.SilenceUsage = true
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
func runLocalIngest(_ *cobra.Command, _ []string) error {
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

	// --- 3. Create InputSource ---
	useStdin := ingestOpts.Input == "-"
	var filePath string
	if !useStdin {
		filePath = ingestOpts.Input
	}

	inputSource, err := source.NewInputSource(source.SourceConfig{
		Targets:    globalTargets,
		FilePath:   filePath,
		Format:     inputFormat,
		UseStdin:   useStdin,
		BufferSize: 100,
	})
	if err != nil {
		return fmt.Errorf("failed to create input source: %w", err)
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

	// Resolve --source-url: clone and use as source path
	if scanOpts.SourceURL != "" {
		if globalSourcePath != "" {
			return fmt.Errorf("cannot use both --source and --source-url")
		}
		clonedPath, cloneErr := cloneGitRepo(scanOpts.SourceURL)
		if cloneErr != nil {
			return fmt.Errorf("failed to clone --source-url: %w", cloneErr)
		}
		globalSourcePath = clonedPath
	}

	// Auto-create source repo if --source or --source-url is provided
	if globalSourcePath != "" {
		if err := upsertSourceRepo(ctx, repo, globalTargets, globalSourcePath); err != nil {
			zap.L().Warn("Failed to link source repo", zap.Error(err))
		}
	}

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

	if globalDisableFetchResponse {
		// Save requests directly without fetching responses
		var scopeMatcher *config.ScopeMatcher
		if settings.Scope.AppliedOnIngest {
			scopeMatcher = config.NewScopeMatcher(settings.Scope, globalTargets...)
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
			if _, saveErr := repo.SaveRecord(ctx, item.Request, "ingest-cli", resolveProjectUUID()); saveErr != nil {
				zap.L().Debug("Failed to save record", zap.Error(saveErr))
				continue
			}
			count++
		}

		if globalJSON {
			out := map[string]interface{}{
				"records_ingested": count,
				"duration_ms":     time.Since(startTime).Milliseconds(),
				"source":          inputFormat,
			}
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			return encoder.Encode(out)
		}

		elapsed := time.Since(startTime).Seconds()
		if !globalSilent {
			fmt.Fprintf(os.Stderr, "\n%s %s (%.1fs)\n",
				terminal.SuccessSymbol(),
				terminal.Green(fmt.Sprintf("Ingestion completed: %d requests ingested (no response fetch)", count)),
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
	if globalJSON {
		out := map[string]interface{}{
			"records_ingested": executor.Processed(),
			"duration_ms":     time.Since(startTime).Milliseconds(),
			"source":          inputFormat,
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(out)
	}

	elapsed := time.Since(startTime).Seconds()
	if !globalSilent {
		processed := executor.Processed()
		fmt.Fprintf(os.Stderr, "\n%s %s (%.1fs)\n",
			terminal.SuccessSymbol(),
			terminal.Green(fmt.Sprintf("Ingestion completed: %d requests ingested", processed)),
			elapsed)
	}

	if globalScanOnReceive {
		return runLocalIngestScan(settings, db, repo, "")
	}

	return nil
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

	// Create a Scan record if none provided
	if scanUUID == "" {
		scan := &database.Scan{
			UUID:        fmt.Sprintf("scan-%d", time.Now().UnixNano()),
			ProjectUUID: resolveProjectUUID(),
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

	if err := scanRunner.RunEnumeration(); err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if !globalSilent {
		fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.Green(terminal.SymbolSparkle), terminal.BoldGreen("Scan completed"))
	}

	return nil
}
