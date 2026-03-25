// Package spitolas provides browser-based web crawling (spidering) for vigolium.
// It wraps the internal crawler engine and exposes a minimal public API
// for integration into vigolium's scan pipeline.
package spitolas

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	appconfig "github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	ipilot "github.com/vigolium/vigolium/pkg/spitolas/internal/pilot"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/crawler"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/form"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// RecordSaver persists HTTP request/response pairs to a database.
type RecordSaver interface {
	SaveRecord(ctx context.Context, httpRR *httpmsg.HttpRequestResponse, source string, projectUUID string) (string, error)
	SaveRecordBatch(ctx context.Context, records []*httpmsg.HttpRequestResponse, source string, projectUUID string) ([]string, error)
}

// SpiderConfig configures the browser-based spidering engine.
type SpiderConfig struct {
	TargetURL           string
	MaxDepth            int
	MaxStates           int
	MaxDuration         time.Duration
	MaxConsecutiveFails int
	Headless            bool
	BrowserCount        int
	Strategy            string // "normal", "random", "oldest_first", "shallow_first", "adaptive"
	IncludeResponseBody bool
	IncludeHeaders      bool
	Silent              bool
	Verbose             bool   // show all traffic including static files
	BrowserEngine       string // "chromium" or "ungoogled"
	NoCDP               bool   // disable CDP event listener detection
	NoForms             bool   // disable automatic form filling
	ProxyURL            string // HTTP proxy URL for browser traffic
	ScopeFilter         func(host, path string) bool
	ProjectUUID         string

	// Pilot mode: AI-powered crawling
	PilotMode       bool               // enable pilot-driven crawl mode
	PilotAuth       PilotAuthConfig    // auth config for pilot mode
	PilotAgent         appconfig.AgentDef // ACP agent definition
	PilotSessions      string             // session directory for action log
	PilotScreenshot    bool               // include screenshot with every action (more tokens)
	PilotMaxRetries    int                // max ACP prompt retries on timeout
	PilotStallTimeout time.Duration // no-tool-call timeout before retry (0 = 7m default)
}

// SpiderResult contains the results of a spidering run.
type SpiderResult struct {
	StatesDiscovered int
	ActionsExecuted  int
	ActionsFailed    int
	FormsSubmitted   int
	Duration         time.Duration
	RecordsSaved     int
	// Pilot mode results
	FeaturesExplored int
	FeaturesPending  int
}

// RunSpider executes browser-based spidering against the target URL,
// saving all captured traffic to the repository via the "spidering" source.
func RunSpider(ctx context.Context, cfg SpiderConfig, repo RecordSaver) (*SpiderResult, error) {
	crawlerCfg, err := config.New(cfg.TargetURL)
	if err != nil {
		return nil, err
	}

	// Apply configuration
	crawlerCfg.MaxDepth = cfg.MaxDepth
	crawlerCfg.MaxStates = cfg.MaxStates
	crawlerCfg.MaxDuration = cfg.MaxDuration
	crawlerCfg.MaxConsecutiveFails = cfg.MaxConsecutiveFails
	crawlerCfg.Headless = cfg.Headless
	crawlerCfg.Silent = cfg.Silent
	crawlerCfg.Verbose = cfg.Verbose
	crawlerCfg.IncludeResponseBody = cfg.IncludeResponseBody
	crawlerCfg.IncludeResponseHeaders = cfg.IncludeHeaders

	if cfg.BrowserCount > 0 {
		crawlerCfg.BrowserCount = cfg.BrowserCount
	}
	if cfg.Strategy != "" {
		crawlerCfg.CrawlStrategy = config.CrawlStrategy(cfg.Strategy)
	}
	if cfg.BrowserEngine != "" {
		crawlerCfg.BrowserEngine = cfg.BrowserEngine
	}
	crawlerCfg.UseCDPDetection = !cfg.NoCDP
	crawlerCfg.FormFillEnabled = !cfg.NoForms
	if cfg.ProxyURL != "" {
		crawlerCfg.ProxyURL = cfg.ProxyURL
	}

	// Create writer that saves to vigolium's HTTPRecord table
	writer := network.NewRepositoryWriter(repo, "spidering", cfg.ProjectUUID)
	writer.ScopeFilter = cfg.ScopeFilter

	// Pilot mode: use PilotCrawler instead of standard Crawler
	if cfg.PilotMode {
		return runPilotSpider(ctx, crawlerCfg, cfg, writer)
	}

	// Standard crawler mode
	c, err := crawler.New(crawlerCfg)
	if err != nil {
		return nil, err
	}
	c.SetWriter(writer)

	result, err := c.Run(ctx)
	if err != nil {
		return nil, err
	}

	return &SpiderResult{
		StatesDiscovered: result.Stats.StatesDiscovered,
		ActionsExecuted:  result.Stats.ActionsExecuted,
		ActionsFailed:    result.Stats.ActionsFailed,
		FormsSubmitted:   result.Stats.FormsSubmitted,
		Duration:         result.Duration(),
		RecordsSaved:     writer.Count(),
	}, nil
}

// runPilotSpider executes a pilot-driven crawl using an ACP agent.
func runPilotSpider(ctx context.Context, crawlerCfg *config.Config, cfg SpiderConfig, writer *network.RepositoryWriter) (*SpiderResult, error) {
	zap.L().Info("pilot mode enabled — ACP agent will control the browser")

	// Create sub-components directly (bypassing Crawler)
	pool, err := browser.NewPool(crawlerCfg)
	if err != nil {
		return nil, fmt.Errorf("pilot: create browser pool: %w", err)
	}
	defer func() { _ = pool.Close() }()

	graph := state.NewGraph()
	formHandler := form.NewHandler(crawlerCfg)
	extractor := action.NewCandidateElementExtractor(crawlerCfg)
	extractor.SetClickOnce(false)
	if !cfg.NoCDP {
		extractor.EnableCDP(true)
	}

	capture := network.New(writer, crawlerCfg.NoColor, crawlerCfg.Silent, crawlerCfg.Verbose,
		crawlerCfg.IncludeResponseBody, crawlerCfg.IncludeResponseHeaders,
		crawlerCfg.URL.Hostname(), "pilot")

	// Session trace — single LLM-readable file capturing the entire crawl session
	tracePath := ""
	sessionDir := ""
	if cfg.PilotSessions != "" {
		runID := fmt.Sprintf("pilot-%d", time.Now().UnixMilli())
		var dirErr error
		sessionDir, dirErr = agent.EnsureSessionDir(cfg.PilotSessions, runID)
		if dirErr != nil {
			return nil, fmt.Errorf("pilot: ensure session dir: %w", dirErr)
		}
		tracePath = filepath.Join(sessionDir, "session_trace.md")
	}
	trace, err := ipilot.NewSessionTrace(tracePath)
	if err != nil {
		return nil, fmt.Errorf("pilot: create session trace: %w", err)
	}
	defer func() { _ = trace.Close() }()

	pilotCfg := &ipilot.PilotConfig{
		Enabled:       true,
		Screenshot:    cfg.PilotScreenshot,
		MaxRetries:    cfg.PilotMaxRetries,
		StallTimeout: cfg.PilotStallTimeout,
		Auth: ipilot.PilotAuthConfig{
			Enabled:      cfg.PilotAuth.Enabled,
			AutoRegister: cfg.PilotAuth.AutoRegister,
			Username:     cfg.PilotAuth.Username,
			Password:     cfg.PilotAuth.Password,
		},
	}

	bc := ipilot.NewPilotCrawler(
		crawlerCfg,
		pilotCfg,
		cfg.PilotAgent,
		pool,
		graph,
		formHandler,
		extractor,
		capture,
		trace,
		filepath.Join(sessionDir, "checkpoints.json"),
	)

	result, err := bc.Run(ctx)
	if err != nil {
		// ACP errors (timeout, prompt failure) are non-fatal if we have partial results.
		// The browser was fine — the AI agent just failed. Use what was discovered.
		if result != nil && isACPRetryableError(err) {
			zap.L().Warn("pilot ACP session ended with error, using partial results",
				zap.Error(err),
				zap.Int("statesDiscovered", result.StatesDiscovered),
				zap.Int("checkpointsCompleted", result.CheckpointsCompleted))
		} else {
			return nil, err
		}
	}

	return &SpiderResult{
		StatesDiscovered: result.StatesDiscovered,
		ActionsExecuted:  result.ActionsExecuted,
		Duration:         result.Duration,
		RecordsSaved:     writer.Count(),
		FeaturesExplored: result.CheckpointsCompleted,
		FeaturesPending:  result.CheckpointsPending,
	}, nil
}

// isACPRetryableError returns true if the error is a retryable ACP error
// (timeout or prompt failure). The browser was fine — only the AI agent failed.
func isACPRetryableError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "ACP prompt timed out") || strings.Contains(msg, "ACP prompt failed")
}
