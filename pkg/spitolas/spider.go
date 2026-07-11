// Package spitolas provides browser-based web crawling (spidering) for vigolium.
// It wraps the internal crawler engine and exposes a minimal public API
// for integration into vigolium's scan pipeline.
package spitolas

import (
	"context"
	"net/http"
	"net/url"
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
	BrowserPath         string // explicit path to browser binary (overrides auto-detection)
	NoCDP               bool   // disable CDP event listener detection
	NoForms             bool   // disable automatic form filling
	ProxyURL            string // HTTP proxy URL for browser traffic
	ScopeFilter         func(host, path string) bool
	ProjectUUID         string
	Source              string // http_records source tag; "" defaults to "spidering"

	// Authentication bridged into the browser so the crawl explores authenticated
	// content instead of only the unauthenticated shell. These mirror the session
	// (--auth/--auth-file) and custom-header context the HTTP scan phases use.
	//   - InitialCookies: seeded into the browser cookie jar before navigation.
	//   - ExtraHeaders:   non-cookie headers (Authorization, X-Api-Key, -H headers)
	//                     applied to every browser request via CDP.
	//   - BasicAuthUser/Pass: HTTP Basic credentials embedded in the start URL.
	InitialCookies []*http.Cookie
	ExtraHeaders   map[string]string
	BasicAuthUser  string
	BasicAuthPass  string

	// LoginCredentialAttempts enables trying a small documented list of common
	// default credentials against a CONFIRMED local login form so the crawl can
	// proceed authenticated. Single-flighted per host, negative-control gated,
	// never a wordlist. Off by default; the runner enables it at balanced and deep.
	LoginCredentialAttempts bool

	// LoginCredentialFullList selects the full documented credential list (deep)
	// versus the minimal set (balanced: admin:admin, admin:123456). Ignored when
	// LoginCredentialAttempts is false.
	LoginCredentialFullList bool
}

// SpiderResult contains the results of a spidering run.
type SpiderResult struct {
	StatesDiscovered int
	ActionsExecuted  int
	ActionsFailed    int
	FormsSubmitted   int
	Duration         time.Duration
	RecordsSaved     int

	// LandingURL is the final URL of the index (start) page after any redirects
	// the browser followed during initial navigation. When the start URL issues
	// a cross-host redirect (e.g. to an SSO/login provider), this is the
	// post-redirect URL, which differs from the configured TargetURL.
	LandingURL string

	// OffHostRedirect is true when the start URL redirected the browser to a
	// host outside the target's scope (a classic SSO/auth-wall bounce).
	OffHostRedirect bool

	// LandingIsLogin is true when an off-host landing looked like a login/SSO
	// wall. The crawler can't proceed unauthenticated, so the run yields almost
	// nothing — the caller should advise supplying authentication.
	LandingIsLogin bool

	// HostAdopted is true when an off-host landing did NOT look like a login
	// wall and its host was pulled into scope so the crawl could continue
	// against the relocated app.
	HostAdopted bool

	// LoginCTADriven is true when the crawler found and clicked a login
	// call-to-action on the landing to enter an OAuth/SAML/SSO flow. LoginCTAText
	// is the CTA's visible label.
	LoginCTADriven bool
	LoginCTAText   string

	// LoginCredsTried / LoginCredsSucceeded report the common-credential login
	// pass: the number of credential pairs submitted and the number of login
	// forms where a pair authenticated. LoginCredsURL is the last login form the
	// pass ran against.
	LoginCredsTried     int
	LoginCredsSucceeded int
	LoginCredsURL       string

	// HarvestedCookies is the browser's cookie jar at end of crawl and
	// BrowserUserAgent the UA it presented. The runner carries these forward into
	// content discovery and dynamic assessment so those phases inherit the
	// WAF/bot-cleared session the real browser established. Empty when the crawl
	// harvested nothing (e.g. the browser wedged before teardown).
	HarvestedCookies []*http.Cookie
	BrowserUserAgent string
}

// buildCrawlerConfig maps a public SpiderConfig onto the internal crawler config,
// including the browser-auth bridge and the operator-scope→CrawlScope adapter.
// Shared by RunSpider (one-shot) and SpiderSession (browser reused across seeds).
func buildCrawlerConfig(cfg SpiderConfig) (*config.Config, error) {
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
	if cfg.BrowserPath != "" {
		crawlerCfg.BrowserPath = cfg.BrowserPath
	}
	crawlerCfg.UseCDPDetection = !cfg.NoCDP
	crawlerCfg.FormFillEnabled = !cfg.NoForms
	crawlerCfg.LoginCredentialAttempts = cfg.LoginCredentialAttempts
	crawlerCfg.LoginCredentialFullList = cfg.LoginCredentialFullList
	if cfg.ProxyURL != "" {
		crawlerCfg.ProxyURL = cfg.ProxyURL
	}

	// Bridge operator authentication into the browser (cookies + non-cookie
	// headers + HTTP Basic) so the crawl runs authenticated.
	crawlerCfg.InitialCookies = cfg.InitialCookies
	crawlerCfg.ExtraHeaders = cfg.ExtraHeaders
	crawlerCfg.BasicAuthUser = cfg.BasicAuthUser
	crawlerCfg.BasicAuthPass = cfg.BasicAuthPass

	// Enforce the operator's scope inside the browser too, not just at the
	// persistence writer. Without this the crawler falls back to a broad
	// same-domain rule and only discards out-of-scope traffic AFTER navigating —
	// paying for a real browser request that gets thrown away. Assigning CrawlScope
	// makes the crawler reject out-of-scope pages using the operator's exact
	// boundary, so it stops wandering off-scope in the first place.
	if cfg.ScopeFilter != nil {
		scope := cfg.ScopeFilter
		crawlerCfg.CrawlScope = func(rawURL string) bool {
			u, perr := url.Parse(rawURL)
			if perr != nil || u.Hostname() == "" {
				// Un-parseable or scheme-relative — let the crawler's other logic
				// decide rather than hard-dropping it here.
				return true
			}
			return scope(u.Hostname(), u.Path)
		}
	}
	return crawlerCfg, nil
}

// spiderResultFromCrawl converts an internal crawl Result into the public
// SpiderResult. recordsSaved is supplied by the caller because the writer is
// per-run (RunSpider) or shared (SpiderSession, which reports a per-seed delta).
func spiderResultFromCrawl(result *crawler.Result, recordsSaved int) *SpiderResult {
	// Start-redirect handling is decided inside the crawler (it alone has the
	// rendered landing page to classify login vs. relocated app); surface its
	// verdict verbatim so the caller can report it without re-deriving anything.
	return &SpiderResult{
		StatesDiscovered: result.Stats.StatesDiscovered,
		ActionsExecuted:  result.Stats.ActionsExecuted,
		ActionsFailed:    result.Stats.ActionsFailed,
		FormsSubmitted:   result.Stats.FormsSubmitted,
		Duration:         result.Duration(),
		RecordsSaved:     recordsSaved,
		LandingURL:       result.Stats.LandingURL,
		OffHostRedirect:  result.Stats.OffHostLanding,
		LandingIsLogin:   result.Stats.LandingIsLogin,
		HostAdopted:      result.Stats.HostAdopted,
		LoginCTADriven:   result.Stats.LoginCTADriven,
		LoginCTAText:     result.Stats.LoginCTAText,

		LoginCredsTried:     result.Stats.LoginCredsTried,
		LoginCredsSucceeded: result.Stats.LoginCredsSucceeded,
		LoginCredsURL:       result.Stats.LoginCredsURL,

		HarvestedCookies: result.HarvestedCookies,
		BrowserUserAgent: result.BrowserUserAgent,
	}
}

// RunSpider executes browser-based spidering against the target URL,
// saving all captured traffic to the repository via the "spidering" source.
func RunSpider(ctx context.Context, cfg SpiderConfig, repo RecordSaver) (*SpiderResult, error) {
	crawlerCfg, err := buildCrawlerConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Create writer that saves to vigolium's HTTPRecord table. The source tag
	// defaults to "spidering"; callers (e.g. the targeted re-spider phase) can
	// override it to distinguish their records.
	source := cfg.Source
	if source == "" {
		source = "spidering"
	}
	writer := network.NewRepositoryWriter(repo, source, cfg.ProjectUUID)
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

	return spiderResultFromCrawl(result, writer.Count()), nil
}
