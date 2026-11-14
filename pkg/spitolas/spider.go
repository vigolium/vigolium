// Package spitolas provides browser-based web crawling (spidering) for vigolium.
// It wraps the internal crawler engine and exposes a minimal public API
// for integration into vigolium's scan pipeline.
package spitolas

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/crawler"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
	"go.uber.org/zap"
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
	DrainGrace          time.Duration // stop scheduling new states this long before the deadline, so in-flight work drains inside the budget; 0 = off
	MaxConsecutiveFails int
	Headless            bool
	BrowserCount        int
	Tabs                int    // tabs of the one browser crawling the shared state graph; 0 or 1 = single-threaded
	TabIsolation        string // "shared" (or ""): tabs share the default context; "context": one browser context per extra tab; see TabIsolationModes
	Strategy            string // "normal", "random", "oldest_first", "shallow_first", "adaptive"
	IncludeResponseBody bool
	IncludeHeaders      bool
	Silent              bool
	Verbose             bool   // show all traffic including static files
	BrowserEngine       string // "chromium" or "ungoogled"
	BrowserPath         string // explicit path to browser binary (overrides auto-detection)
	NoCDP               bool   // disable CDP event listener detection
	Stealth             string // "auto" (or ""), "on", "off"; see StealthModes
	NoForms             bool   // disable automatic form filling
	ProxyURL            string // HTTP proxy URL for browser traffic
	ScopeFilter         func(host, path string) bool
	ProjectUUID         string
	Source              string // http_records source tag; "" defaults to "spidering"

	// MaxListenerProbeNodes caps the listener-bearing nodes the CDP listener
	// pass turns into click candidates per state (0 = default 2000, negative =
	// no cap).
	MaxListenerProbeNodes int

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

	// RequireAuth fails the crawl instead of continuing anonymously when
	// InitialCookies/ExtraHeaders were given but could not be applied to the
	// start page (SpiderResult.AuthState reports the outcome either way).
	RequireAuth bool

	// LoginCredentialAttempts enables trying a small documented list of common
	// default credentials against a CONFIRMED local login form so the crawl can
	// proceed authenticated. Single-flighted per host, negative-control gated,
	// never a wordlist. Off by default; the runner defaults it on at balanced and
	// deep unless spidering.interaction.login_attempts says otherwise.
	LoginCredentialAttempts bool

	// LoginCredentialFullList selects the full documented credential list (deep)
	// versus the minimal set (balanced: admin:admin, admin:123456). Ignored when
	// LoginCredentialAttempts is false.
	LoginCredentialFullList bool

	// SelfRegister lets the crawl complete a public signup form and continue as
	// the account it created, so an app whose real surface sits behind open
	// registration is crawled rather than bounced at the door. Creating an
	// account is a write, so this stays off unless the caller asks; no
	// intensity turns it on (spidering.interaction.register_account does).
	SelfRegister bool

	// Policy, when set, is the interaction policy the crawl enforces and
	// supersedes NoForms, SelfRegister and LoginCredentialAttempts above. Nil
	// keeps the pre-policy behavior: the defaults with those three switches
	// applied (see EffectivePolicy). The runner sets both, consistently.
	Policy *InteractionPolicy

	// DenyClickPattern overrides the destructive-click guard's regex (SAFE-9):
	// nil keeps the built-in destructive pattern, a pointer to "" disables it.
	DenyClickPattern *string
	// ExcludeSelectors are CSS selectors the crawl never clicks.
	ExcludeSelectors []string
	// MethodAllowed is the scan's traffic policy (scope.methods): requests
	// with a refused method are failed in the browser. nil = every method.
	MethodAllowed func(method string) bool

	// BrowserCompat, when set, is the set of browser security exceptions the
	// crawl launches with; nil means DefaultBrowserCompat.
	BrowserCompat *BrowserCompat

	// MaxCaptureBodyBytes caps the encoded size of a dynamic response body the
	// capture keeps: 0 = default (16 MiB), negative = no ceiling. Over it the
	// record is stored without its body, marked too-large in the capture.
	MaxCaptureBodyBytes int64

	// IdentityEmailDomain is the domain of generated email addresses (signup,
	// login, plain email fields). "" means example.com — reserved, with a null
	// MX, so nothing is ever delivered. Never derived from the target.
	IdentityEmailDomain string

	// GraphOutputDir, when set, is the directory the finished crawl graph is
	// written into — the states reached and the selector/inputs of every
	// transition between them. Captured traffic records what was requested; this
	// records how the crawler got there, which is what makes a run reproducible.
	//
	// A directory rather than a path so the file is named from the crawl's OWN
	// target. A session reuses one base config across a host's seeds and only
	// TargetURL is replaced per seed, so a precomputed path would be whatever the
	// first target implied and every later seed would write to it. Each graph is
	// crawl-graph-<host>-<RunID>-<seq>.json, written 0600 and atomically.
	GraphOutputDir string

	// GraphIncludeValues keeps credential-bearing values (password/hidden field
	// values, sensitive query parameters, value/data-* attributes) in the graph.
	// Off by default: the graph is redacted and says so (redacted: true).
	GraphIncludeValues bool

	// RunID names the run in graph file names and manifests — the scan UUID
	// when the runner has one. Empty falls back to a per-process timestamp.
	RunID string

	// RequestCounter, when set, is incremented for every http(s) request the
	// browser sends — third-party and out-of-scope included, each redirect hop
	// separately — so a caller can report the crawl's network cost while it
	// runs. InScopeRequestCounter counts the share the ScopeFilter admits (all
	// of them without one). Shared across concurrent crawls is fine.
	RequestCounter        *atomic.Int64
	InScopeRequestCounter *atomic.Int64

	// ExtraSeeds are entry points browsed into the frontier after the
	// robots/sitemap seeds; see SeedURL. MaxExtraSeeds caps how many one crawl
	// browses (0 = DefaultMaxExtraSeeds). A SpiderSession browses them on its
	// first Crawl only.
	ExtraSeeds    []SeedURL
	MaxExtraSeeds int
}

// requestCounters is cfg's live counter pair in the capture's shape.
func (cfg SpiderConfig) requestCounters() network.RequestCounters {
	return network.RequestCounters{Sent: cfg.RequestCounter, InScope: cfg.InScopeRequestCounter}
}

// SpiderResult contains the results of a spidering run.
type SpiderResult struct {
	StatesDiscovered int
	ActionsExecuted  int
	ActionsFailed    int
	// FormsSubmitted counts form submissions dispatched by every mechanism
	// (submit clicks, Enter, GET-form synthesis, POST-form triggers, credential
	// attempts, registration). FormSubmitsPrevented counts submissions the
	// interaction policy refused; FormSubmitsUncertain counts POST forms whose
	// outcome could not be attributed (no fallback was sent).
	FormsSubmitted       int
	FormSubmitsPrevented int
	FormSubmitsUncertain int
	Duration             time.Duration
	RecordsSaved         int

	// RequestsSent counts every http(s) request the browser sent during the run
	// (third-party included); RequestsInScope is the share the scope admits.
	// See SpiderConfig.RequestCounter for the live figure.
	RequestsSent    int64
	RequestsInScope int64

	// Capture is what the run's traffic capture actually retained (see
	// CaptureReceipt.Complete). From RunSpider it is final. A SpiderSession
	// seed shares the session's writer, which is still open after the seed, so
	// its receipt carries this seed's deltas with DrainComplete=false; the
	// session's final receipt comes from SpiderSession.Receipt after Close.
	Capture CaptureReceipt

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

	// WallHosts are the hosts denied as login/SSO walls: the landing host plus
	// every redirect hop that served an authentication endpoint. Callers feed
	// these into the scan-wide fuzz exclusion so a later phase never brute-forces
	// the identity provider. Includes hops LandingURL alone would miss — an OAuth
	// bounce commonly crosses an authorize endpoint on one host before reaching
	// the login form on another.
	WallHosts []string

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

	// HarvestedAuthorization is a bare JWT/Bearer token read from the app's client
	// storage after a confirmed default-credential login, carried forward so
	// token-auth SPAs are scanned authenticated. Empty when no login succeeded.
	HarvestedAuthorization string

	// DOMXssFindings holds browser-confirmed DOM-based XSS on reflected client
	// routes (SPA hash routes / query params) discovered during the crawl.
	DOMXssFindings []DOMXssFinding

	// SeedURLsDiscovered / SeedURLsCrawled report the frontier seeding from the
	// host's robots.txt and sitemap: how many in-scope locations those files
	// declared, and how many of them were additionally browsed into states (the
	// remainder are requested and recorded only).
	SeedURLsDiscovered int
	SeedURLsCrawled    int

	// ExtraSeedsAccepted counts SpiderConfig.ExtraSeeds that survived
	// resolution, scope, dedup and the cap; ExtraSeedsCrawled how many of them
	// were browsed into the crawl.
	ExtraSeedsAccepted int
	ExtraSeedsCrawled  int

	// SpeculativeLinksFetched counts URL-like strings scraped from the rendered
	// document's comments and inline script that were fetched and recorded.
	SpeculativeLinksFetched int

	// SelfRegistered reports that a signup form was completed and accepted;
	// SelfRegisterIdentity is the identity created, which later login attempts
	// reuse.
	SelfRegistered       bool
	SelfRegisterIdentity string

	// FollowUpPassesRun counts extra sweeps run after the first pass drained.
	// ActionsRetried / ActionsRecovered report the end-of-crawl retry sweep.
	FollowUpPassesRun int
	ActionsRetried    int
	ActionsRecovered  int

	// AuthState is what happened to the configured authentication:
	// "not-requested", "configured", "applied" or "failed" — never "verified"
	// (applying credentials does not prove the application accepted them).
	// CredentialHostsDenied names hosts the credential headers were kept from
	// because the operator scope does not admit them (an off-host start
	// redirect); CredentialOriginsDenied is their count. Hosts only, no values.
	AuthState               string
	CredentialOriginsDenied int
	CredentialHostsDenied   []string

	// AuxFetchesDenied counts URLs the in-page primers (iframe, GET-form,
	// anchor, seed, speculative) did not fetch because the operator scope did
	// not admit them.
	AuxFetchesDenied int

	// WaitConditionsFailed counts readiness (wait) conditions that never met
	// within their timeout; WaitConditionFailures names up to five of their
	// selectors. Non-zero on a near-empty run means "a required readiness
	// condition never met", not "the site has no content".
	WaitConditionsFailed  int
	WaitConditionFailures []string
}

// Authentication states reported in SpiderResult.AuthState. There is no
// "verified": applying credentials does not prove the application accepted
// them.
const (
	AuthNotRequested = crawler.AuthNotRequested
	AuthConfigured   = crawler.AuthConfigured
	AuthApplied      = crawler.AuthApplied
	AuthFailed       = crawler.AuthFailed
)

// DOMXssFinding is a browser-confirmed DOM-based XSS on a client route: an
// execution canary placed in a reflected query parameter ran in the page.
type DOMXssFinding struct {
	URL      string // exact route + injected param that executed the canary
	Param    string // the injected query parameter name
	Payload  string // the canary payload (decoded)
	Evidence string // the sink element as rendered
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
	crawlerCfg.DrainGrace = cfg.DrainGrace
	crawlerCfg.MaxConsecutiveFails = cfg.MaxConsecutiveFails
	crawlerCfg.Headless = cfg.Headless
	crawlerCfg.Silent = cfg.Silent
	crawlerCfg.Verbose = cfg.Verbose
	crawlerCfg.IncludeResponseBody = cfg.IncludeResponseBody
	crawlerCfg.IncludeResponseHeaders = cfg.IncludeHeaders
	crawlerCfg.MaxCaptureBodyBytes = cfg.MaxCaptureBodyBytes
	crawlerCfg.ExtraSeeds = extraSeedsToInternal(cfg.ExtraSeeds)
	crawlerCfg.MaxExtraSeeds = cfg.MaxExtraSeeds

	if cfg.BrowserCount > 0 {
		crawlerCfg.BrowserCount = cfg.BrowserCount
	}
	crawlerCfg.Tabs = cfg.Tabs
	crawlerCfg.TabIsolation = cfg.TabIsolation
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
	if cfg.MaxListenerProbeNodes != 0 {
		crawlerCfg.MaxListenerProbeNodes = cfg.MaxListenerProbeNodes
	}
	crawlerCfg.Stealth = cfg.Stealth
	// The policy sets form filling, GET/POST form submission, self-registration
	// and credential attempts in one place; see config.ApplyPolicy.
	crawlerCfg.ApplyPolicy(config.InteractionPolicy(cfg.EffectivePolicy()))
	if cfg.DenyClickPattern != nil {
		crawlerCfg.DenyClickPattern = *cfg.DenyClickPattern
	}
	crawlerCfg.ExcludeSelectors = append(crawlerCfg.ExcludeSelectors, cfg.ExcludeSelectors...)
	crawlerCfg.MethodAllowed = cfg.MethodAllowed
	crawlerCfg.BrowserCompat = config.BrowserCompat(cfg.EffectiveCompat())
	crawlerCfg.LoginCredentialFullList = cfg.LoginCredentialFullList
	if cfg.IdentityEmailDomain != "" {
		crawlerCfg.IdentityEmailDomain = cfg.IdentityEmailDomain
	}
	if cfg.ProxyURL != "" {
		crawlerCfg.ProxyURL = cfg.ProxyURL
	}

	// Bridge operator authentication into the browser (cookies + non-cookie
	// headers + HTTP Basic) so the crawl runs authenticated.
	crawlerCfg.InitialCookies = cfg.InitialCookies
	crawlerCfg.ExtraHeaders = cfg.ExtraHeaders
	crawlerCfg.BasicAuthUser = cfg.BasicAuthUser
	crawlerCfg.BasicAuthPass = cfg.BasicAuthPass
	crawlerCfg.RequireAuth = cfg.RequireAuth

	// Enforce the operator's scope inside the browser too, not just at the
	// persistence writer. Without this the crawler falls back to a broad
	// same-domain rule and only discards out-of-scope traffic AFTER navigating —
	// paying for a real browser request that gets thrown away. Assigning CrawlScope
	// makes the crawler reject out-of-scope pages using the operator's exact
	// boundary, so it stops wandering off-scope in the first place.
	if cfg.ScopeFilter != nil {
		scope := cfg.ScopeFilter
		// Carried in both shapes: the URL form for the crawler's scope checks, the
		// native (host, path) form for the capture's log filter. See
		// config.Config.ScopeFilter for why the capture does not reuse the wrapper.
		crawlerCfg.ScopeFilter = scope
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
// mapDOMXssFindings converts the internal crawler DOM-XSS findings to the public
// spider type so callers never depend on internal/crawler.
func mapDOMXssFindings(in []crawler.DOMXssFinding) []DOMXssFinding {
	if len(in) == 0 {
		return nil
	}
	out := make([]DOMXssFinding, 0, len(in))
	for _, f := range in {
		out = append(out, DOMXssFinding{URL: f.URL, Param: f.Param, Payload: f.Payload, Evidence: f.Evidence})
	}
	return out
}

func spiderResultFromCrawl(result *crawler.Result, recordsSaved int) *SpiderResult {
	// Start-redirect handling is decided inside the crawler (it alone has the
	// rendered landing page to classify login vs. relocated app); surface its
	// verdict verbatim so the caller can report it without re-deriving anything.
	return &SpiderResult{
		StatesDiscovered: result.Stats.StatesDiscovered,
		ActionsExecuted:  result.Stats.ActionsExecuted,
		ActionsFailed:    result.Stats.ActionsFailed,
		FormsSubmitted:   result.Stats.FormsSubmitted,

		FormSubmitsPrevented: result.Stats.FormSubmitsPrevented,
		FormSubmitsUncertain: result.Stats.FormSubmitsUncertain,

		Duration:        result.Duration(),
		RecordsSaved:    recordsSaved,
		LandingURL:      result.Stats.LandingURL,
		OffHostRedirect: result.Stats.OffHostLanding,
		LandingIsLogin:  result.Stats.LandingIsLogin,
		HostAdopted:     result.Stats.HostAdopted,
		WallHosts:       result.Stats.WallHosts,
		LoginCTADriven:  result.Stats.LoginCTADriven,
		LoginCTAText:    result.Stats.LoginCTAText,

		LoginCredsTried:     result.Stats.LoginCredsTried,
		LoginCredsSucceeded: result.Stats.LoginCredsSucceeded,
		LoginCredsURL:       result.Stats.LoginCredsURL,

		HarvestedCookies:       result.HarvestedCookies,
		BrowserUserAgent:       result.BrowserUserAgent,
		HarvestedAuthorization: result.HarvestedAuthorization,
		DOMXssFindings:         mapDOMXssFindings(result.DOMXssFindings),

		SeedURLsDiscovered:      result.Stats.SeedURLsDiscovered,
		SeedURLsCrawled:         result.Stats.SeedURLsCrawled,
		ExtraSeedsAccepted:      result.Stats.ExtraSeedsAccepted,
		ExtraSeedsCrawled:       result.Stats.ExtraSeedsCrawled,
		SpeculativeLinksFetched: result.Stats.SpeculativeLinksFetched,
		SelfRegistered:          result.Stats.SelfRegistered,
		SelfRegisterIdentity:    result.Stats.SelfRegisterIdentity,
		FollowUpPassesRun:       result.Stats.FollowUpPassesRun,
		ActionsRetried:          result.Stats.ActionsRetried,
		ActionsRecovered:        result.Stats.ActionsRecovered,

		WaitConditionsFailed:  result.Stats.WaitConditionsFailed,
		WaitConditionFailures: result.Stats.WaitConditionFailures,

		AuthState:               result.Stats.AuthState,
		CredentialOriginsDenied: result.Stats.CredentialOriginsDenied,
		CredentialHostsDenied:   result.Stats.CredentialHostsDenied,
		AuxFetchesDenied:        result.Stats.AuxFetchesDenied,
	}
}

// RunSpider executes browser-based spidering against the target URL,
// saving all captured traffic to the repository via the "spidering" source.
// When the crawl itself fails after starting, the returned result is non-nil
// alongside the error and carries only RecordsSaved, Capture and AuthState.
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
		// NewRepositoryWriter started its flush goroutine, so the writer is
		// closed on this path too. Nothing was written yet, so there is no
		// loss for Close to report.
		_ = writer.Close()
		return nil, err
	}
	c.SetWriter(writer)
	// This run's own counters for the result, plus the caller's live ones.
	runCounters := network.RequestCounters{Sent: new(atomic.Int64), InScope: new(atomic.Int64)}
	c.AddRequestCounters(runCounters)
	c.AddRequestCounters(cfg.requestCounters())

	result, runErr := c.Run(ctx)
	// The crawl's capture closes the writer on its way out (on every path that
	// started it); Close is idempotent and hands back the drop tally either way.
	closeErr := writer.Close()
	receipt := newCaptureReceipt(writer.Receipt(), cfg.IncludeResponseBody, cfg.IncludeHeaders)
	if runErr != nil {
		if closeErr != nil {
			zap.L().Warn("Spidering: capture lost records on a failed crawl", zap.Error(closeErr))
		}
		// What a failed crawl captured was still persisted (or lost), so the
		// account goes back with the error.
		// AuthState travels too: a RequireAuth failure is this error, and the
		// caller should be able to say why without parsing it.
		return &SpiderResult{
			RecordsSaved:    writer.Count(),
			Capture:         receipt,
			AuthState:       c.GetStats().AuthState,
			RequestsSent:    runCounters.Sent.Load(),
			RequestsInScope: runCounters.InScope.Load(),
		}, runErr
	}

	res := spiderResultFromCrawl(result, writer.Count())
	if result != nil {
		receipt.BodiesFailed = result.Stats.BodiesFailed
	}
	res.Capture = receipt
	res.RequestsSent = runCounters.Sent.Load()
	res.RequestsInScope = runCounters.InScope.Load()
	writeCrawlGraph(c, cfg, crawlerCfg, receipt)
	return res, nil
}

// graphSeq numbers the graphs this process writes, so same-host seeds of one
// run never share a file name.
var graphSeq atomic.Int64

// fallbackRunID is the run id for graphs written without one: the process's
// first graph time, so every graph of one process shares it.
var fallbackRunID = sync.OnceValue(func() string {
	return time.Now().UTC().Format("20060102T150405Z")
})

// writeCrawlGraph writes the finished crawl's graph when cfg asks for one,
// after the crawl's capture has reported its receipt. Best-effort: the crawl
// succeeded whether or not its map could be written, so a failure is logged.
func writeCrawlGraph(c *crawler.Crawler, cfg SpiderConfig, crawlerCfg *config.Config, receipt CaptureReceipt) {
	if cfg.GraphOutputDir == "" || c == nil {
		return
	}
	runID := cfg.RunID
	if runID == "" {
		runID = fallbackRunID()
	}
	seq := fmt.Sprintf("%03d", graphSeq.Add(1))
	path := crawler.GraphOutputPathFor(cfg.GraphOutputDir, crawlerCfg.URL.Hostname(), runID, seq)
	m := crawler.GraphManifest{
		RunID:    runID,
		Seed:     seq,
		Policy:   cfg.EffectivePolicy().Fields(),
		Security: EffectiveBrowserSecurity(cfg.EffectiveCompat()).Fields(),
		Capture:  receipt,
	}
	if err := c.WriteGraphDump(path, m, cfg.GraphIncludeValues); err != nil {
		zap.L().Warn("Spidering: crawl graph not written", zap.String("path", path), zap.Error(err))
	}
}
