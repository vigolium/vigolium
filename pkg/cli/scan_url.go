package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

// scan-url flags
var (
	scanURLMethod    string
	scanURLBody      string
	scanURLHeaders   []string
	scanURLNoPassive bool
)

// Phase enable flags (shared by scan-url and scan-request)
var (
	scanPhaseDiscover        bool
	scanPhaseSpider          bool
	scanPhaseExternalHarvest bool
	scanPhaseKnownIssueScan  bool
)

// registerPhaseFlags adds --discover, --spider, --external-harvest, and --known-issue-scan
// flags to the given FlagSet. Called from both scan-url and scan-request init().
func registerPhaseFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&scanPhaseDiscover, "discover", false, "Run content discovery before scanning")
	flags.BoolVar(&scanPhaseSpider, "spider", false, "Run browser-based spidering before scanning")
	flags.BoolVar(&scanPhaseExternalHarvest, "external-harvest", false, "Run external intelligence harvesting before scanning")
	flags.BoolVar(&scanPhaseKnownIssueScan, "known-issue-scan", false, "Run known issue scan (Nuclei/Kingfisher)")
}

// hasPhaseFlags returns true if any phase flag is set.
func hasPhaseFlags() bool {
	return scanPhaseDiscover || scanPhaseSpider || scanPhaseExternalHarvest || scanPhaseKnownIssueScan
}

var scanURLCmd = &cobra.Command{
	Use:   "scan-url [url]",
	Short: "Scan a single URL for vulnerabilities",
	Long: `Run active and passive scanner modules against a single URL.
Accepts a URL as argument or reads from stdin (auto-detects raw HTTP, curl, or URLs).
Designed for quick, targeted scans and AI agent integration.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScanURLCmd,
}

func init() {
	rootCmd.AddCommand(scanURLCmd)
	flags := scanURLCmd.Flags()

	flags.StringVar(&scanURLMethod, "method", "GET", "HTTP method")
	flags.StringVar(&scanURLBody, "body", "", "Request body")
	flags.StringSliceVarP(&scanURLHeaders, "header", "H", nil, "Custom header (repeatable, e.g. -H 'Cookie: x=1')")
	flags.BoolVar(&scanURLNoPassive, "no-passive", false, "Skip passive modules")
	flags.StringSliceVarP(&globalTargets, "target", "t", nil, "Target URL to scan (repeatable; alternative to the positional URL argument)")
	registerScanModuleFlags(flags)
	registerHTTPClientFlags(flags)
	registerPhaseFlags(flags)
	registerLightweightScanIOFlags(flags)
}

// hasFileOutputFormat reports whether --format requests a file-materialized
// format (jsonl/html/report/pdf) as opposed to the default console view. The
// lightweight commands route to the Runner for these so the export tail
// (finishStatelessExport / maybeGenerateReports / finishScanJSONLExport) runs.
// Plain --json / --ci-output-format leave globalFormat at "console" and keep the
// fast in-memory direct path, preserving the JSON shape AI agents consume.
func hasFileOutputFormat() bool {
	for _, f := range parseFormats(globalFormat) {
		switch f {
		case "jsonl", "html", "report", "pdf":
			return true
		}
	}
	return false
}

// needsRunnerScan reports whether the request must run through the full
// native-scan Runner rather than the lightweight in-memory direct path. That is
// required whenever a phase is enabled, results are persisted/exported to a file
// (-o), the run is stateless (-S), phases are skipped (--skip), or a file output
// format is requested — none of which the direct path implements.
func needsRunnerScan() bool {
	return hasPhaseFlags() ||
		globalStateless ||
		scanOpts.Output != "" ||
		len(globalSkipPhases) > 0 ||
		hasFileOutputFormat()
}

// dispatchSingleScan routes one parsed request to either the Runner-backed scan
// (when output/persistence/phase flags are in play) or the fast direct path.
func dispatchSingleScan(rr *httpmsg.HttpRequestResponse, target, method string) error {
	if needsRunnerScan() {
		return runRunnerScan(rr, target)
	}
	return runScanWithRR(rr, target, method)
}

func runScanURLCmd(_ *cobra.Command, args []string) error {
	defer syncLogger()

	// Targets come from the positional URL argument and/or repeatable -t/--target
	// flags. The positional arg is kept for the original single-URL ergonomics;
	// -t lets the command match `vigolium scan`'s muscle memory and pass several
	// URLs at once.
	targets := append([]string{}, args...)
	targets = append(targets, globalTargets...)

	if len(targets) > 0 {
		var lastErr error
		for _, target := range targets {
			rr, err := buildRequestFromFlags(target, scanURLMethod, scanURLBody, scanURLHeaders)
			if err != nil {
				return fmt.Errorf("failed to build request: %w", err)
			}
			if err := dispatchSingleScan(rr, target, scanURLMethod); err != nil {
				lastErr = err
			}
		}
		return lastErr
	}

	// No args — try reading from stdin
	if !fileutil.HasStdin() {
		return fmt.Errorf("no URL argument provided and no stdin input detected")
	}

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read stdin: %w", err)
	}

	content := strings.TrimSpace(string(raw))
	if content == "" {
		return fmt.Errorf("empty stdin input")
	}

	detected := detect.DetectStdinFormat(content)
	items, err := detect.ParseStdinContent(content, detected)
	if err != nil {
		return err
	}

	// Scan each parsed request
	var lastErr error
	for _, rr := range items {
		target := rr.Target()
		method := rr.Request().Method()
		if err := dispatchSingleScan(rr, target, method); err != nil {
			lastErr = err
		}
	}

	return lastErr
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

// colorStreamingModuleType returns the module-type colored for the streaming
// finding line (active=BoldOrange / passive=BoldBlue). Mirrors the palette
// used by the server's formatFindingLine so the CLI and server console
// produce identical output.
func colorStreamingModuleType(t string) string {
	switch strings.ToLower(t) {
	case "active":
		return terminal.BoldOrange(t)
	case "passive":
		return terminal.BoldBlue(t)
	default:
		return t
	}
}

// streamingSeverityBracket renders the `[<symbol> <severity>]` field used by
// the streaming finding line. Symbol and text share a single color matching
// the severity palette (critical=magenta, high=orange, medium=yellow,
// low=green, suspect=cyan, info=blue).
func streamingSeverityBracket(s severity.Severity) string {
	sevStr := s.String()
	inner := ""
	switch s {
	case severity.Critical:
		inner = terminal.BoldMagenta("✖ " + sevStr)
	case severity.High:
		inner = terminal.BoldOrange("❖ " + sevStr)
	case severity.Medium:
		inner = terminal.BoldYellow("◆ " + sevStr)
	case severity.Low:
		inner = terminal.BoldGreen("• " + sevStr)
	case severity.Suspect:
		inner = terminal.BoldCyan("? " + sevStr)
	case severity.Info:
		inner = terminal.BoldBlue("◇ " + sevStr)
	default:
		inner = sevStr
	}
	return "[" + inner + "]"
}

// formatStreamingFindingLine renders a single finding as one line of console
// output for the `vigolium scan` / `vigolium scan-request` streaming view.
// Format (matching pkg/server/handlers_scan_url.go):
//
//	❯ scan-request │ [type] [module-id] [<sym> severity] METHOD URL[ [evidence]]
//
// METHOD is elided when the result has no request attached (typical for
// passive findings). The URL is truncated to fit the terminal width, and
// result.ExtractedResults + FuzzingParameter surface as a trailing cyan
// bracket.
func formatStreamingFindingLine(result *output.ResultEvent) string {
	prefix := terminal.Muted(terminal.SymbolChevron + " scan-request " + terminal.SymbolPipe)

	typeStr := result.ModuleType
	if typeStr == "" {
		typeStr = "?"
	}

	method := ""
	if result.Request != "" {
		if m, err := httpmsg.GetMethod([]byte(result.Request)); err == nil {
			method = m
		}
	}

	urlStr := result.Matched
	if urlStr == "" {
		urlStr = result.URL
	}

	suffix := ""
	if len(result.ExtractedResults) > 0 {
		suffix = " [" + output.EscapeOneLine(strings.Join(result.ExtractedResults, ",")) + "]"
	}
	if result.IsFuzzingResult && result.FuzzingParameter != "" {
		suffix += " [" + result.FuzzingParameter + "]"
	}

	// Visible-char accounting so the URL gets the remaining terminal width.
	// Hand-count the non-URL portion (ANSI escapes excluded).
	visibleLen := len("❯ scan-request │ ") +
		len("[") + len(typeStr) + len("] ") +
		len("[") + len(result.ModuleID) + len("] ") +
		len("[") + len("✖ ") + len(result.Info.Severity.String()) + len("] ")
	if method != "" {
		visibleLen += len(method) + 1
	}

	if termWidth := terminal.TerminalWidth(); termWidth > 0 {
		remaining := termWidth - visibleLen - len(suffix)
		if remaining > 20 && len(urlStr) > remaining {
			urlStr = terminal.Truncate(urlStr, remaining)
		}
	}

	var b strings.Builder
	b.WriteString(prefix)
	b.WriteString(" [")
	b.WriteString(colorStreamingModuleType(typeStr))
	b.WriteString("] [")
	b.WriteString(terminal.White(result.ModuleID))
	b.WriteString("] ")
	b.WriteString(streamingSeverityBracket(result.Info.Severity))
	if method != "" {
		b.WriteString(" ")
		b.WriteString(terminal.Bold(method))
	}
	b.WriteString(" ")
	b.WriteString(urlStr)
	if suffix != "" {
		b.WriteString(terminal.HiCyan(suffix))
	}
	b.WriteString("\n")
	return b.String()
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

	// Startup line so the user sees what's about to run rather than staring at
	// silence until the first module-level zap log fires.
	if !globalSilent {
		fmt.Fprintf(os.Stderr, "  %s Scanning %s %s with %s active + %s passive modules\n",
			terminal.InfoSymbol(),
			terminal.BoldCyan(method),
			terminal.Cyan(target),
			terminal.Orange(fmt.Sprintf("%d", len(active))),
			terminal.Orange(fmt.Sprintf("%d", len(passive))))
	}

	// Collect findings
	var mu sync.Mutex
	var findings []*output.ResultEvent
	var scanErrors []string

	executorCfg := core.ExecutorConfig{
		Workers:              globalConcurrency,
		Services:             svc,
		HTTPRequester:        httpRequester,
		Repository:           repo,
		ScanUUID:             globalScanUUID,
		MaxFindingsPerModule: globalMaxFindingsPerModule,
		TechFilterDisabled:   globalNoTechFilter,
		OnResult: func(result *output.ResultEvent) {
			mu.Lock()
			findings = append(findings, result)
			mu.Unlock()
			if globalSilent || result == nil {
				return
			}
			// Per-finding stderr line so the user gets immediate feedback as
			// findings come in. Format:
			//   ◆ finding [severity] [type] [confidence] module-id — url
			// Severity is color-coded to match the canonical scheme used by
			// the results table renderer (format_screen.go). Optional [type]
			// and [confidence] brackets surface module class and signal
			// quality at a glance.
			fmt.Fprint(os.Stderr, formatStreamingFindingLine(result))
		},
		StatusInterval: 30 * time.Second,
	}

	// Forward-declared so OnStatus can read the executor's considered-module
	// counter (which counts modules whose CanProcess was evaluated, fired or
	// not — so the X/Y can actually reach parity instead of stalling on the
	// "always-rejected" set forever).
	var scanExecutor *core.Executor

	// Periodic status line so the user can tell the scan is alive during long
	// runs (some modules can take minutes per insertion point).
	if !globalSilent {
		executorCfg.OnStatus = func(processed, total, findingsCount, distinctModules, activeCount, passiveCount, timedOut int64, elapsed time.Duration) {
			totalModules := activeCount + passiveCount
			scannedModules := distinctModules
			if scanExecutor != nil {
				scannedModules = scanExecutor.ConsideredModuleCount()
			}
			modulesStr := terminal.FormatModuleCount(scannedModules, totalModules, timedOut)
			fmt.Fprintf(os.Stderr, "  %s %s Modules: %s | Findings: %s | Elapsed: %s\n",
				terminal.InfoSymbol(),
				terminal.BoldCyan("[status]"),
				terminal.Yellow(modulesStr),
				terminal.Orange(fmt.Sprintf("%d", findingsCount)),
				terminal.Gray(elapsed.Round(time.Second).String()))
		}
	}

	// Verbose: log every HTTP request as it goes out, like burp-style debug.
	// Off by default so the console isn't flooded for typical scans.
	if globalVerbose && !globalSilent {
		executorCfg.OnTraffic = func(reqMethod, reqURL string, statusCode int, contentType string) {
			fmt.Fprintf(os.Stderr, "  %s [%s] %s %s\n",
				terminal.Muted(terminal.SymbolChevron+" scan-request "+terminal.SymbolPipe),
				terminal.Orange(fmt.Sprintf("%d", statusCode)),
				terminal.BoldCyan(reqMethod),
				terminal.Gray(reqURL))
		}
	}

	scanExecutor = core.NewExecutor(executorCfg, src, active, passive)
	executor := scanExecutor

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

// --- Phase mode: delegates to the Runner for full-pipeline phases ---

// buildPhaseOptions creates a *types.Options populated from global flags and phase flags.
func buildPhaseOptions(target string) *types.Options {
	opts := types.DefaultOptions()

	// Target
	opts.Targets = []string{target}

	// Modules
	opts.Modules = resolveModules()
	opts.NoTechFilter = globalNoTechFilter

	// Passive modules
	if scanURLNoPassive {
		opts.PassiveModules = nil
	}

	// Global CLI flags
	opts.ScanUUID = globalScanUUID
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
	opts.OutputFormats = parseFormats(globalFormat)
	// reconcileOutputFormats errors are ignored here because buildPhaseOptions
	// is called with already-validated global flags. It also sets
	// DeferredJSONLExport, which the post-scan jsonl export keys off of.
	_ = reconcileOutputFormats(opts)

	// Output / persistence flags (shared with `vigolium scan`).
	opts.Output = scanOpts.Output
	opts.Stateless = globalStateless
	opts.SkipPhases = globalSkipPhases
	opts.OmitResponse = scanOpts.OmitResponse
	if projectUUID, perr := resolveProjectUUID(); perr == nil {
		opts.ProjectUUID = projectUUID
	}

	// Phase flags
	opts.DiscoverEnabled = scanPhaseDiscover
	opts.SpideringEnabled = scanPhaseSpider
	opts.ExternalHarvestEnabled = scanPhaseExternalHarvest
	opts.KnownIssueScanEnabled = scanPhaseKnownIssueScan

	// Heuristics: not useful for single-target phase mode
	opts.HeuristicsCheck = "none"

	if globalNoClustering {
		opts.ClusterRequests = false
	}

	return opts
}

// validateRunnerScanOutput rejects output-format / -o combinations the export
// tail cannot satisfy, mirroring the equivalent guards on `vigolium scan` so the
// lightweight commands fail the same way instead of silently producing nothing.
func validateRunnerScanOutput(opts *types.Options) error {
	if opts.Output == "" {
		if opts.HasFormat("html") || opts.HasFormat("report") || opts.HasFormat("pdf") {
			return fmt.Errorf("--format html/report/pdf requires -o/--output to specify the report file path")
		}
		if len(opts.OutputFormats) > 1 {
			return fmt.Errorf("multiple --format values require -o/--output as a base path")
		}
	}
	return nil
}

// runRunnerScan scans a single parsed request (or, when phase flags are set, the
// target URL) through the full native-scan Runner so the lightweight scan-url /
// scan-request commands honor -o/--output, -S/--stateless, --skip, and file
// output formats (jsonl/html/...) exactly like `vigolium scan`. It mirrors
// executeNativeScan's stateless temp-DB lifecycle and post-scan export tail.
//
// With no phase flags the exact request (method/body/headers) is fed straight to
// the executor via a SingleSource, so scan-request's raw POST bodies survive. A
// phase flag (discover/spider/...) instead routes through runner.New, which
// crawls from the target URL like the full pipeline.
func runRunnerScan(rr *httpmsg.HttpRequestResponse, target string) (err error) {
	scanStart := time.Now()
	opts := buildPhaseOptions(target)

	if err := validateRunnerScanOutput(opts); err != nil {
		return err
	}
	if opts.Stateless && globalDB != "" {
		return fmt.Errorf("--stateless and --db are mutually exclusive")
	}
	if opts.Stateless && opts.Output == "" && !opts.Silent {
		fmt.Fprintf(os.Stderr,
			"%s %s: no %s set — scan results will be discarded with the temporary database. "+
				"Pass %s %s and %s %s to persist results.\n",
			terminal.WarnPrefix(), terminal.BoldCyan("--stateless"), terminal.BoldCyan("-o/--output"),
			terminal.BoldCyan("--output"), terminal.BoldYellow("<path>"),
			terminal.BoldCyan("--format"), terminal.BoldYellow("jsonl|html"))
	}

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

	// Stateless mode: scan into a throwaway temp SQLite DB that is removed after
	// the run, so the main DB stays untouched (mirrors `vigolium scan -S`).
	var statelessDBPath string
	if opts.Stateless {
		tmpFile, tmpErr := os.CreateTemp("", "vigolium-stateless-*.sqlite")
		if tmpErr != nil {
			return fmt.Errorf("failed to create temporary database: %w", tmpErr)
		}
		statelessDBPath = tmpFile.Name()
		_ = tmpFile.Close()
		defer func() {
			_ = os.Remove(statelessDBPath)
			_ = os.Remove(statelessDBPath + "-wal")
			_ = os.Remove(statelessDBPath + "-shm")
		}()
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = statelessDBPath
	} else if globalDB != "" {
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = globalDB
	}
	applyGlobalExtFlagsToSettings(settings)

	// Validate database config
	if err := settings.Database.Validate(); err != nil {
		return fmt.Errorf("invalid database configuration: %w", err)
	}
	if err := settings.DynamicAssessment.Extensions.Validate(); err != nil {
		return fmt.Errorf("invalid extensions configuration: %w", err)
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
	if opts.KnownIssueScanEnabled {
		if err := settings.KnownIssueScan.Validate(); err != nil {
			return fmt.Errorf("invalid KnownIssueScan configuration: %w", err)
		}
	}

	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return fmt.Errorf("scan requires a database; use --db <path> or configure vigolium-configs.yaml: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		return fmt.Errorf("failed to create database schema: %w", err)
	}
	repo := database.NewRepository(db)

	// Stateless + -o: suppress StandardWriter's live file output and materialize
	// every requested format from the temp DB post-scan (mirrors executeNativeScan).
	var statelessOutputPath string
	if opts.Stateless && opts.Output != "" {
		statelessOutputPath = opts.Output
		opts.Output = ""
	}
	// Export tail. Registered before the runner is closed; both read the DB after
	// the explicit scanRunner.Close() below flushes records, but before db.Close().
	defer func() { finishStatelessExport(db, opts, statelessOutputPath, false) }()
	defer func() {
		// Skip the deferred jsonl envelope when stateless already materialized
		// every format to the file, or when a persisted scan hard-failed (don't
		// write a success-looking file of stale data).
		if opts.Stateless && statelessOutputPath != "" {
			return
		}
		if err != nil && !opts.Stateless {
			return
		}
		finishScanJSONLExport(db, opts)
	}()

	// Build the Runner. No phase flags → scan the exact request via SingleSource;
	// a phase flag → crawl from the target URL via the standard input source.
	var scanRunner *runner.Runner
	if hasPhaseFlags() {
		scanRunner, err = runner.New(opts)
	} else {
		scanRunner, err = runner.NewWithInputSource(opts, source.NewSingleSource(rr, opts.Modules))
	}
	if err != nil {
		return fmt.Errorf("failed to create scan runner: %w", err)
	}
	if scanRunner == nil {
		return nil
	}
	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(repo)
	setupScanSignalHandler(scanRunner)

	// Close before the export defers read the DB so any buffered records land
	// first. A failed scan must abort visibly (non-zero, no success banner).
	scanErr := scanRunner.RunNativeScan()
	scanRunner.Close()
	if scanErr != nil {
		err = scanErr
		return err
	}

	// maybeGenerateReports self-guards on opts.Output=="" (blanked above for the
	// stateless path, where finishStatelessExport handles reports instead).
	maybeGenerateReports(db, opts)
	if !opts.Silent {
		fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.Aqua(terminal.SymbolSparkle), terminal.BoldAqua("Native scan completed"))
		printScanCompletionSummary(repo, time.Since(scanStart))
	}

	return nil
}

// outputScanResult writes the scan result as JSON or human-readable table.
func outputScanResult(result *scanResult) error {
	// CI output: one JSONL line per finding, nothing else
	if globalCIOutput {
		for _, f := range result.Findings {
			data, err := json.Marshal(f)
			if err != nil {
				return err
			}
			_, _ = os.Stdout.Write(data)
			_, _ = os.Stdout.Write([]byte("\n"))
		}
		return nil
	}

	if globalJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	// Human-readable output
	fmt.Fprintf(os.Stderr, "\n%s Native scan completed: %s (%s %s) in %s\n",
		terminal.SuccessSymbol(),
		terminal.Cyan(result.Target),
		result.Method,
		terminal.Gray(fmt.Sprintf("%d modules", result.ModulesRun)),
		(time.Duration(result.ScanDurationMs) * time.Millisecond).Round(time.Second))

	if len(result.Findings) == 0 {
		fmt.Fprintf(os.Stderr, "%s No findings.\n", terminal.InfoSymbol())
		return nil
	}

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "SEVERITY", "MODULE", "TYPE", "MATCHED", "NAME")
	for _, f := range result.Findings {
		tbl.AddRow(
			clicommon.ColorSeverity(f.Info.Severity.String()),
			terminal.Cyan(f.ModuleID),
			colorModuleType(f.ModuleType),
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
