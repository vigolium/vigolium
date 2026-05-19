package knownissuescan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

// Config holds configuration for a known-issue scan.
type Config struct {
	Targets      []string                  // scheme://host:port URLs to scan
	Concurrency  int                       // nuclei host concurrency (default: 5)
	RateLimit    int                       // requests/sec (default: 150)
	Tags         []string                  // template tags to include (empty = all)
	ExcludeTags  []string                  // template tags to exclude
	Severities   []string                  // filter by severity (empty = all)
	TemplatesDir string                    // custom templates directory
	Timeout      time.Duration             // max known-issue scan duration (default: 30m)
	Headers      []string                  // custom headers
	ProxyURL     string                    // proxy URL
	OnResult     func(*output.ResultEvent) // callback per finding
	Repository   *database.Repository      // for saving findings
	ScanUUID     string
	ProjectUUID  string
}

// Run executes the known-issue scan using the nuclei Go library.
func Run(ctx context.Context, cfg Config) error {
	if len(cfg.Targets) == 0 {
		return fmt.Errorf("knownissuescan: no targets provided")
	}

	// Apply defaults
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 50
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 100
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Minute
	}

	// Ensure nuclei templates are available before attempting to scan
	if err := ensureTemplates(cfg.TemplatesDir); err != nil {
		return err
	}

	// Create a properly initialized logger for nuclei to avoid nil pointer
	// panics from the bare default logger in nuclei's DefaultOptions().
	scanLogger := &gologger.Logger{}
	scanLogger.SetFormatter(formatter.NewCLI(false))
	scanLogger.SetWriter(writer.NewCLI())
	// Always silence nuclei's gologger — its [WRN]/[INF]/[VER] messages are
	// noisy and not actionable. Vigolium uses its own zap logger for output.
	scanLogger.SetMaxLevel(levels.LevelSilent)
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)

	// Build engine options
	opts := buildEngineOptions(ctx, cfg, scanLogger)

	zap.L().Info("Starting known-issue scan",
		zap.Int("targets", len(cfg.Targets)),
		zap.Int("concurrency", cfg.Concurrency),
		zap.Int("rate_limit", cfg.RateLimit),
		zap.Strings("tags", cfg.Tags),
		zap.Strings("exclude_tags", cfg.ExcludeTags),
		zap.Duration("timeout", cfg.Timeout),
	)

	// Create nuclei engine with timeout context
	scanCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	ne, err := nuclei.NewNucleiEngineCtx(scanCtx, opts...)
	if err != nil {
		return fmt.Errorf("knownissuescan: failed to create nuclei engine: %w", err)
	}
	defer ne.Close()

	// Load targets
	ne.LoadTargets(cfg.Targets, false)

	// Execute with callback
	var findingCount int
	err = ne.ExecuteCallbackWithCtx(scanCtx, func(event *nucleiOutput.ResultEvent) {
		// Only process genuine matches — nuclei fires the callback for all
		// template evaluations, including non-matches.
		if !event.MatcherStatus {
			return
		}

		result := convertResult(event)
		result.ModuleType = database.ModuleTypeKnownIssueScan
		result.FindingSource = database.FindingSourceKnownIssueScan
		findingCount++

		// Invoke user callback
		if cfg.OnResult != nil {
			cfg.OnResult(result)
		}

		// Persist to database
		if cfg.Repository != nil {
			var httpRecordUUIDs []string
			if result.Request != "" {
				fuzzedRR := httpmsg.NewHttpRequestResponse(
					httpmsg.NewHttpRequest([]byte(result.Request)),
					httpmsg.NewHttpResponse([]byte(result.Response)),
				)
				recordUUID, recErr := cfg.Repository.SaveRecord(ctx, fuzzedRR, "spa", cfg.ProjectUUID)
				if recErr != nil {
					zap.L().Debug("KnownIssueScan: failed to save http record", zap.Error(recErr))
				} else {
					httpRecordUUIDs = []string{recordUUID}
				}
			}
			if saveErr := cfg.Repository.SaveFinding(ctx, result, httpRecordUUIDs, cfg.ScanUUID, cfg.ProjectUUID); saveErr != nil {
				zap.L().Debug("KnownIssueScan: failed to save finding", zap.Error(saveErr))
			}
		}
	})
	if err != nil {
		return fmt.Errorf("knownissuescan: execution failed: %w", err)
	}

	zap.L().Info("Known-issue scan completed", zap.Int("findings", findingCount))
	return nil
}

// buildEngineOptions constructs nuclei SDK options from known-issue scan config.
func buildEngineOptions(ctx context.Context, cfg Config, logger *gologger.Logger) []nuclei.NucleiSDKOptions {
	var opts []nuclei.NucleiSDKOptions

	// Template filters
	filters := nuclei.TemplateFilters{
		Tags:        cfg.Tags,
		ExcludeTags: cfg.ExcludeTags,
	}
	if len(cfg.Severities) > 0 {
		filters.Severity = strings.Join(cfg.Severities, ",")
	}
	opts = append(opts, nuclei.WithTemplateFilters(filters))

	// Custom templates directory
	if cfg.TemplatesDir != "" {
		opts = append(opts, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{cfg.TemplatesDir},
		}))
	}

	// Rate limit
	opts = append(opts, nuclei.WithGlobalRateLimitCtx(ctx, cfg.RateLimit, time.Second))

	// Concurrency
	opts = append(opts, nuclei.WithConcurrency(nuclei.Concurrency{
		TemplateConcurrency:           10,
		HostConcurrency:               cfg.Concurrency,
		HeadlessHostConcurrency:       1,
		HeadlessTemplateConcurrency:   1,
		JavascriptTemplateConcurrency: 1,
		TemplatePayloadConcurrency:    25,
		ProbeConcurrency:              50,
	}))

	// Proxy
	if cfg.ProxyURL != "" {
		opts = append(opts, nuclei.WithProxy([]string{cfg.ProxyURL}, false))
	}

	// Custom headers
	if len(cfg.Headers) > 0 {
		opts = append(opts, nuclei.WithHeaders(cfg.Headers))
	}

	// Always run nuclei in silent mode — its internal logging is noisy and
	// not useful. Vigolium's own zap logger handles verbose/debug output.
	opts = append(opts, nuclei.WithVerbosity(nuclei.VerbosityOptions{
		Verbose: false,
		Silent:  true,
	}))

	// Disable update checks in library mode
	opts = append(opts, nuclei.DisableUpdateCheck())

	// Pass our properly initialized logger to avoid nil pointer panics
	// from nuclei's bare default logger.
	opts = append(opts, nuclei.WithLogger(logger))

	return opts
}

// convertResult maps a nuclei output.ResultEvent to a vigolium ResultEvent.
func convertResult(nr *nucleiOutput.ResultEvent) *output.ResultEvent {
	result := &output.ResultEvent{
		ModuleID: nr.TemplateID,
		Info: output.Info{
			Name:        nr.Info.Name,
			Description: nr.Info.Description,
			Severity:    parseSeverity(nr.Info.SeverityHolder.Severity.String()),
			Confidence:  severity.Firm,
		},
		Type:             nr.Type,
		Host:             nr.Host,
		Matched:          nr.Matched,
		URL:              nr.URL,
		IP:               nr.IP,
		Request:          nr.Request,
		Response:         nr.Response,
		ExtractedResults: nr.ExtractedResults,
		MatcherStatus:    nr.MatcherStatus,
		Timestamp:        time.Now(),
		ModuleShort:      nr.Info.Description,
	}

	// Map tags
	if !nr.Info.Tags.IsEmpty() {
		result.Info.Tags = nr.Info.Tags.ToSlice()
	}

	// Map references
	if nr.Info.Reference != nil && !nr.Info.Reference.IsEmpty() {
		result.Info.Reference = nr.Info.Reference.ToSlice()
	}

	// Fallback URL
	if result.URL == "" {
		result.URL = nr.Host
	}

	return result
}

// ensureTemplates checks that nuclei templates are available and attempts to
// download them if missing. When Vigolium embeds nuclei as a library, the
// automatic template download that the nuclei CLI performs does not run, so
// fresh environments (Docker, VPS) may not have templates installed.
func ensureTemplates(customDir string) error {
	dir := customDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("knownissuescan: cannot determine home directory: %w", err)
		}
		dir = filepath.Join(home, "nuclei-templates")
	}

	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return nil
	}

	zap.L().Info("KnownIssueScan: nuclei templates not found, attempting to download",
		zap.String("path", dir))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1",
		"https://github.com/projectdiscovery/nuclei-templates.git", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("knownissuescan: nuclei templates not found at %s and auto-download failed: %s\n"+
			"Install manually: git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git %s",
			dir, strings.TrimSpace(string(out)), dir)
	}

	zap.L().Info("KnownIssueScan: nuclei templates downloaded successfully", zap.String("path", dir))
	return nil
}

// parseSeverity maps a nuclei severity string to vigolium severity.
func parseSeverity(s string) severity.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return severity.Critical
	case "high":
		return severity.High
	case "medium":
		return severity.Medium
	case "low":
		return severity.Low
	case "info":
		return severity.Info
	default:
		return severity.Undefined
	}
}
