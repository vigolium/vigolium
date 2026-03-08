package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
)

// scan-url flags
var (
	scanURLMethod    string
	scanURLBody      string
	scanURLHeaders   []string
	scanURLNoPassive bool
	scanURLNoIP      bool
)

// Phase enable flags (shared by scan-url and scan-request)
var (
	scanPhaseDiscover        bool
	scanPhaseSpider          bool
	scanPhaseExternalHarvest bool
	scanPhaseSPA             bool
)

// registerPhaseFlags adds --discover, --spider, --external-harvest, and --spa
// flags to the given FlagSet. Called from both scan-url and scan-request init().
func registerPhaseFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&scanPhaseDiscover, "discover", false, "Run content discovery before scanning")
	flags.BoolVar(&scanPhaseSpider, "spider", false, "Run browser-based spidering before scanning")
	flags.BoolVar(&scanPhaseExternalHarvest, "external-harvest", false, "Run external intelligence harvesting before scanning")
	flags.BoolVar(&scanPhaseSPA, "spa", false, "Run security posture assessment (Nuclei/Kingfisher)")
}

// hasPhaseFlags returns true if any phase flag is set.
func hasPhaseFlags() bool {
	return scanPhaseDiscover || scanPhaseSpider || scanPhaseExternalHarvest || scanPhaseSPA
}

var scanURLCmd = &cobra.Command{
	Use:   "scan-url <url>",
	Short: "Scan a single URL for vulnerabilities",
	Long:  "Run active and passive scanner modules against a single URL.\nDesigned for quick, targeted scans and AI agent integration.",
	Args:  cobra.ExactArgs(1),
	RunE:  runScanURLCmd,
}

func init() {
	rootCmd.AddCommand(scanURLCmd)
	flags := scanURLCmd.Flags()

	flags.StringVar(&scanURLMethod, "method", "GET", "HTTP method")
	flags.StringVar(&scanURLBody, "body", "", "Request body")
	flags.StringSliceVarP(&scanURLHeaders, "header", "H", nil, "Custom header (repeatable, e.g. -H 'Cookie: x=1')")
	flags.BoolVar(&scanURLNoPassive, "no-passive", false, "Skip passive modules")
	flags.BoolVar(&scanURLNoIP, "no-insertion-points", false, "Skip insertion point testing")

	registerPhaseFlags(flags)
}

func runScanURLCmd(_ *cobra.Command, args []string) error {
	defer syncLogger()

	target := args[0]

	// Build HttpRequestResponse
	rr, err := buildRequestFromFlags(target, scanURLMethod, scanURLBody, scanURLHeaders)
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}

	// Delegate to Runner when any phase flag is set
	if hasPhaseFlags() {
		return runPhaseMode(rr, target, scanURLMethod)
	}

	return runScanWithRR(rr, target, scanURLMethod)
}

// --- Shared helpers used by both scan-url and scan-request ---

// scanResult is the JSON output struct for scan-url and scan-request.
type scanResult struct {
	Target         string                `json:"target"`
	Method         string                `json:"method"`
	ScanDurationMs int64                 `json:"scan_duration_ms"`
	ModulesRun     int                   `json:"modules_run"`
	Findings       []*output.ResultEvent `json:"findings"`
	Errors         []string              `json:"errors,omitempty"`
}

// buildRequestFromFlags constructs an HttpRequestResponse from CLI flags.
func buildRequestFromFlags(target, method, body string, headers []string) (*httpmsg.HttpRequestResponse, error) {
	method = strings.ToUpper(method)

	// Simple case: GET with no body or custom headers
	if method == "GET" && body == "" && len(headers) == 0 {
		return httpmsg.GetRawRequestFromURL(target)
	}

	// Build raw HTTP request manually
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	path := u.RequestURI()
	host := u.Host

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&sb, "Host: %s\r\n", host)

	// Add custom headers
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			fmt.Fprintf(&sb, "%s: %s\r\n", strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	// Add Content-Length if body is present
	if body != "" {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	}

	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}

	rr, err := httpmsg.ParseRawRequestWithURL(sb.String(), target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request: %w", err)
	}

	return rr, nil
}

// setupScanHTTPStack initializes the HTTP stack for scanning.
// Returns requester, services, and a cleanup function.
func setupScanHTTPStack() (*http.Requester, *services.Services, func(), error) {
	opts := types.DefaultOptions()
	opts.Concurrency = globalConcurrency
	opts.Timeout = globalTimeout
	opts.ProxyURL = globalProxy
	opts.Verbose = globalVerbose
	opts.Debug = globalDebug
	opts.DumpTraffic = globalDumpTraffic
	opts.MaxPerHost = globalMaxPerHost
	opts.MaxHostError = globalMaxHostError
	if globalNoClustering {
		opts.ClusterRequests = false
	}

	if err := network.Init(opts); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to initialize network: %w", err)
	}

	dedupMgr := dedup.NewManager()

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
	svc.HostLimiter = hostLimiter

	httpRequester, err := http.NewRequester(opts, svc)
	if err != nil {
		dedupMgr.Close()
		_ = hostLimiter.Close()
		return nil, nil, nil, fmt.Errorf("failed to create HTTP requester: %w", err)
	}

	cleanup := func() {
		dedupMgr.Close()
		_ = hostLimiter.Close()
	}

	return httpRequester, svc, cleanup, nil
}

// getFilteredModules returns active and passive modules based on CLI flags.
func getFilteredModules(moduleIDs []string, noPassive bool) ([]modules.ActiveModule, []modules.PassiveModule) {
	var active []modules.ActiveModule
	var passive []modules.PassiveModule

	// Resolve fuzzy patterns to exact IDs
	resolved := modules.ResolveModulePatterns(moduleIDs)
	isAll := len(resolved) == 0 || (len(resolved) == 1 && resolved[0] == "all")

	if !isAll {
		active = modules.GetActiveModulesByIDs(resolved)
		if !noPassive {
			passive = modules.GetPassiveModulesByIDs(resolved)
		}
	} else {
		active = modules.GetActiveModules()
		if !noPassive {
			passive = modules.GetPassiveModules()
		}
	}

	return active, passive
}

// runScanWithRR executes a scan with the given HttpRequestResponse and outputs results.
func runScanWithRR(rr *httpmsg.HttpRequestResponse, target, method string) error {
	startTime := time.Now()
	resolvedModules := resolveModules()

	// Set up HTTP stack
	httpRequester, svc, cleanup, err := setupScanHTTPStack()
	if err != nil {
		return err
	}
	defer cleanup()

	// Get modules
	active, passive := getFilteredModules(resolvedModules, scanURLNoPassive)

	// Optional database
	var repo *database.Repository
	db, dbErr := getDB()
	if dbErr == nil {
		ctx := context.Background()
		if schemaErr := db.CreateSchema(ctx); schemaErr != nil {
			zap.L().Warn("Failed to create schema", zap.Error(schemaErr))
		}
		repo = database.NewRepository(db)
		defer closeDatabaseOnExit()
	}

	// Create source
	src := source.NewSingleSource(rr, resolvedModules)

	// Collect findings
	var mu sync.Mutex
	var findings []*output.ResultEvent
	var scanErrors []string

	executorCfg := core.ExecutorConfig{
		Workers:              globalConcurrency,
		Services:             svc,
		HTTPRequester:        httpRequester,
		Repository:           repo,
		ScanUUID:             globalScanID,
		MaxFindingsPerModule: globalMaxFindingsPerModule,
		OnResult: func(result *output.ResultEvent) {
			mu.Lock()
			findings = append(findings, result)
			mu.Unlock()
		},
	}

	executor := core.NewExecutor(executorCfg, src, active, passive)

	// Signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// Execute
	_, execErr := executor.Execute(ctx)
	if execErr != nil {
		scanErrors = append(scanErrors, execErr.Error())
	}

	duration := time.Since(startTime)

	result := &scanResult{
		Target:         target,
		Method:         method,
		ScanDurationMs: duration.Milliseconds(),
		ModulesRun:     len(active) + len(passive),
		Findings:       findings,
		Errors:         scanErrors,
	}
	if result.Findings == nil {
		result.Findings = make([]*output.ResultEvent, 0)
	}

	return outputScanResult(result)
}

// runScanWithRRCollect executes a scan and returns findings instead of printing.
// Used by agent loop to collect scan results programmatically.
func runScanWithRRCollect(rr *httpmsg.HttpRequestResponse, target, method string) ([]*output.ResultEvent, error) {
	resolvedModules := resolveModules()

	// Set up HTTP stack
	httpRequester, svc, cleanup, err := setupScanHTTPStack()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Get modules
	active, passive := getFilteredModules(resolvedModules, scanURLNoPassive)

	// Optional database
	var repo *database.Repository
	db, dbErr := getDB()
	if dbErr == nil {
		ctx := context.Background()
		if schemaErr := db.CreateSchema(ctx); schemaErr != nil {
			zap.L().Warn("Failed to create schema", zap.Error(schemaErr))
		}
		repo = database.NewRepository(db)
	}

	// Create source
	src := source.NewSingleSource(rr, resolvedModules)

	// Collect findings
	var mu sync.Mutex
	var findings []*output.ResultEvent

	executorCfg := core.ExecutorConfig{
		Workers:              globalConcurrency,
		Services:             svc,
		HTTPRequester:        httpRequester,
		Repository:           repo,
		ScanUUID:             globalScanID,
		MaxFindingsPerModule: globalMaxFindingsPerModule,
		OnResult: func(result *output.ResultEvent) {
			mu.Lock()
			findings = append(findings, result)
			mu.Unlock()
		},
	}

	executor := core.NewExecutor(executorCfg, src, active, passive)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, execErr := executor.Execute(ctx); execErr != nil {
		return findings, execErr
	}

	return findings, nil
}

// --- Phase mode: delegates to the Runner for full-pipeline phases ---

// buildPhaseOptions creates a *types.Options populated from global flags and phase flags.
func buildPhaseOptions(target string) *types.Options {
	opts := types.DefaultOptions()

	// Target
	opts.Targets = []string{target}

	// Modules
	opts.Modules = resolveModules()

	// Passive modules
	if scanURLNoPassive {
		opts.PassiveModules = nil
	}

	// Global CLI flags
	opts.ScanUUID = globalScanID
	opts.Timeout = globalTimeout
	opts.Concurrency = globalConcurrency
	opts.MaxPerHost = globalMaxPerHost
	opts.MaxHostError = globalMaxHostError
	opts.Verbose = globalVerbose
	opts.Silent = globalSilent
	opts.Debug = globalDebug
	opts.DumpTraffic = globalDumpTraffic
	opts.JSONOutput = globalJSON
	opts.ProxyURL = globalProxy
	opts.ConfigPath = globalConfig
	opts.ScopeOriginMode = globalScopeOrigin
	opts.OutputFormat = globalFormat

	// Reconcile --json and --format
	if globalJSON && globalFormat == "console" {
		opts.OutputFormat = "jsonl"
	}
	if opts.OutputFormat == "jsonl" {
		opts.JSONOutput = true
	}

	// Phase flags
	opts.DiscoverEnabled = scanPhaseDiscover
	opts.SpideringEnabled = scanPhaseSpider
	opts.ExternalHarvestEnabled = scanPhaseExternalHarvest
	opts.SPAEnabled = scanPhaseSPA

	// Heuristics: not useful for single-target phase mode
	opts.HeuristicsCheck = "none"

	if globalNoClustering {
		opts.ClusterRequests = false
	}

	return opts
}

// runPhaseMode delegates scanning to the Runner when any phase flag is set.
// This enables full-pipeline phases (discover, spider, external-harvest, SPA)
// from the lightweight scan-url and scan-request commands.
func runPhaseMode(_ *httpmsg.HttpRequestResponse, target, _ string) error {
	opts := buildPhaseOptions(target)

	// Load settings from config file
	settings, err := config.LoadSettings(opts.ConfigPath)
	if err != nil {
		if !opts.Silent {
			fmt.Fprintf(os.Stderr, "%s Config file not found, using defaults\n",
				terminal.Gray(terminal.SymbolPending))
		}
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	// Apply CLI overrides
	if opts.ScopeOriginMode != "" {
		settings.Scope.CLIOriginMode = opts.ScopeOriginMode
	}
	if globalDB != "" {
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = globalDB
	}

	// Validate database config
	if err := settings.Database.Validate(); err != nil {
		return fmt.Errorf("invalid database configuration: %w", err)
	}

	// Validate per-phase configs when enabled
	if opts.DiscoverEnabled {
		if err := settings.Discovery.Validate(); err != nil {
			return fmt.Errorf("invalid discovery configuration: %w", err)
		}
	}
	if opts.SpideringEnabled {
		if err := settings.Spidering.Validate(); err != nil {
			return fmt.Errorf("invalid spidering configuration: %w", err)
		}
	}
	if opts.ExternalHarvestEnabled {
		if err := settings.ExternalHarvester.Validate(); err != nil {
			return fmt.Errorf("invalid external harvester configuration: %w", err)
		}
	}
	if opts.SPAEnabled {
		if err := settings.SPA.Validate(); err != nil {
			return fmt.Errorf("invalid SPA configuration: %w", err)
		}
	}

	// Database is mandatory for phase mode
	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return fmt.Errorf("phase mode requires a database; use --db <path> or configure vigolium-configs.yaml: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		return fmt.Errorf("failed to create database schema: %w", err)
	}
	repo := database.NewRepository(db)

	// Create Runner from options (creates InputSource from opts.Targets)
	scanRunner, err := runner.New(opts)
	if err != nil {
		return fmt.Errorf("failed to create scan runner: %w", err)
	}
	if scanRunner == nil {
		return nil
	}
	defer scanRunner.Close()

	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(repo)

	setupScanSignalHandler(scanRunner)

	if err := scanRunner.RunEnumeration(); err != nil {
		zap.L().Info("Could not run scanner", zap.Error(err))
	}

	if !opts.Silent {
		fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.Aqua(terminal.SymbolSparkle), terminal.BoldAqua("Scan completed"))
		printScanCompletionSummary(repo)
	}

	return nil
}

// outputScanResult writes the scan result as JSON or human-readable table.
func outputScanResult(result *scanResult) error {
	if globalJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	// Human-readable output
	fmt.Fprintf(os.Stderr, "\n%s Scan completed: %s (%s %s) in %dms\n",
		terminal.SuccessSymbol(),
		terminal.Cyan(result.Target),
		result.Method,
		terminal.Gray(fmt.Sprintf("%d modules", result.ModulesRun)),
		result.ScanDurationMs)

	if len(result.Findings) == 0 {
		fmt.Fprintf(os.Stderr, "%s No findings.\n", terminal.InfoSymbol())
		return nil
	}

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "SEVERITY", "MODULE", "MATCHED", "NAME")
	for _, f := range result.Findings {
		tbl.AddRow(
			colorSeverity(f.Info.Severity.String()),
			terminal.Cyan(f.ModuleID),
			f.Matched,
			f.Info.Name,
		)
	}
	tbl.Print()

	if len(result.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "\n%s Errors:\n", terminal.WarningSymbol())
		for _, e := range result.Errors {
			fmt.Fprintf(os.Stderr, "  - %s\n", e)
		}
	}

	return nil
}
