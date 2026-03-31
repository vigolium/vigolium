// Package spitolas provides browser-based web crawling (spidering) for vigolium.
// It wraps the internal crawler engine and exposes a minimal public API
// for integration into vigolium's scan pipeline.
package spitolas

import (
	"context"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/crawler"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
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
}

// SpiderResult contains the results of a spidering run.
type SpiderResult struct {
	StatesDiscovered int
	ActionsExecuted  int
	ActionsFailed    int
	FormsSubmitted   int
	Duration         time.Duration
	RecordsSaved     int
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
