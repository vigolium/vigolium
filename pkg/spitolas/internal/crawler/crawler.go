package crawler

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/condition"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/form"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/fragment"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/mab"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/metrics"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// Crawler is the main web crawler engine.
type Crawler struct {
	config      *config.Config
	graph       *state.Graph
	candidates  *action.UnfiredFragmentCandidates
	browserPool *browser.Pool
	// browser is the single browser instance the crawler operates on. The pool
	// is used to construct it (and remains owned by the pool), but Pool.Get()
	// uses round-robin, which would silently switch browsers between calls —
	// so we cache one reference here and use it for the entire crawl session.
	browser *browser.Browser
	// extractor and formHandler are the first tab's (primary's); the other
	// tabs get their own (see newTabWorker), sharing the crawl-wide memory
	// each keeps — the clickOnce set and the fill context.
	extractor *action.CandidateElementExtractor
	// postFormsJS is postFormsScript's result, built once.
	postFormsJS     string
	postFormsJSOnce sync.Once
	comparator      *state.Comparator
	formHandler     *form.Handler
	fragManager     *fragment.Manager

	// primary is the first tab: the page initializeIndexState opens, which
	// also runs the single-threaded steps around the crawl loop (seeding,
	// follow-up passes, retry sweep). extraTabs are the spidering.tabs-1 more
	// tabs crawlLoop opens on first use and crawlWithBrowser closes; guarded by
	// tabsMu, which is never held while a tab crawls.
	primary    *tabWorker
	tabsMu     sync.Mutex
	extraTabs  []*tabWorker
	tabsOpened bool

	// Conditions
	crawlConditions []*condition.Condition
	waitConditions  []*condition.WaitCondition

	// Invariants - conditions that must always hold
	invariants []*condition.Condition

	// Invariant checker (optional) - structured invariant management
	invariantChecker *condition.InvariantChecker

	// Form input cache - stores successful form inputs per action
	// Uses DetectedInput for Go extension metadata (value rotation, etc.)
	// Guarded by formCacheMu.
	formCacheMu sync.Mutex
	formCache   map[string][]*form.DetectedInput

	// Form trainer (optional) - for reproducible form testing
	formTrainer *form.FormTrainer

	// ND Cluster manager (optional) - for near-duplicate state clustering
	clusterMgr *state.NDClusterManager

	session *CrawlSession

	// Used to generate action combinations with different form input values.
	eventableConditions *condition.EventableConditionChecker

	// consecutiveFails is the crawl-wide streak of failed actions (any tab's
	// failure extends it, any tab's success resets it), checked against
	// MaxConsecutiveFails. Mirrored into Stats.ConsecutiveFailures on read.
	consecutiveFails atomic.Int32

	// Metrics collector for benchmark tracking (optional)
	metricsCollector *metrics.Collector

	// MAB policy for adaptive action selection (optional, used when strategy=adaptive)
	// RLCRAWLER PARITY: Exp3.1 Multi-Armed Bandit algorithm
	mabPolicy *mab.MABExp3Policy

	// Writer for network traffic capture output
	writer network.Writer

	// requestCounters are added to the capture Run creates (see
	// AddRequestCounters). RunOnBrowser uses the caller's capture instead.
	requestCounters []network.RequestCounters

	// adoptedHost is an off-host redirect target that the start URL bounced to
	// and that did NOT look like a login/SSO wall. When set, isInScope treats it
	// as in-scope (alongside the configured target host) so the crawl can follow
	// an app that simply relocated to another domain. Only ever set under the
	// default host-scope rule — an explicit CrawlScope is never widened.
	adoptedHost string

	// wallHosts are hosts classified as a login/SSO wall. isInScope denies them
	// ahead of the configured scope rule, so they are out of scope no matter what
	// the operator's scope mode would otherwise say.
	//
	// The denial has to override the scope rule rather than defer to it, because
	// the case that motivated it is one the scope rule gets wrong by design: an
	// organization's IdP usually shares the target's registrable domain (or its
	// brand keyword), so every mode short of "strict" admits it. Without this the
	// wall classification was advisory only — the crawler would identify the wall,
	// log "supply --auth", and then spend the whole crawl budget interacting with
	// the identity provider's login page: seeding from its robots.txt, filling and
	// submitting its form, and re-entering the OAuth flow each time the reset loop
	// sent the browser back to the start URL.
	//
	// Guarded by wallHostsMu; read on the hot in-scope path from crawl goroutines.
	// hasWallHosts mirrors "the map is non-empty" so that path can skip the lock
	// entirely on the overwhelming majority of crawls, which never see a wall.
	wallHostsMu  sync.RWMutex
	wallHosts    map[string]bool
	hasWallHosts atomic.Bool

	// startWalled records that the START URL's landing was a wall, which ends the
	// crawl — a different question from "is this host denied" (hasWallHosts), and
	// asked at different call sites.
	//
	// Denying the host alone is not enough to stop the crawl: with the landing out
	// of scope the main loop resets, navigates back to the start URL, is
	// redirected to the same wall, and goes out of scope again — an oscillation
	// that ran until the time budget expired, re-entering the OAuth flow (and
	// re-arming the provider's CAPTCHA) on every lap. There is nothing reachable
	// to crawl, so the honest move is to stop and hand the remaining budget back
	// to the phases that can use it.
	startWalled atomic.Bool

	// observedLoginHosts reports the hosts seen serving an authentication endpoint
	// so far. Set from the network capture in crawlWithBrowser, which is the only
	// component that sees individual redirect hops — Chrome collapses server
	// redirects into one history entry, so the crawler cannot name the chain from
	// the landing page alone. nil until the capture is wired.
	observedLoginHosts func() []string

	// primedFrames dedups iframe-source priming across the whole crawl so a frame
	// that recurs in many states (a persistent header/captcha iframe) is fetched
	// once, not once per state. Guarded by primedFramesMu.
	primedFramesMu sync.Mutex
	primedFrames   map[string]bool

	// submittedForms dedups GET-form submit priming across the whole crawl so the
	// same synthesized submit URL (e.g. a search box present on every catalog page
	// → /catalog?searchTerm=a) is fetched once, not once per state. submittedPostForms
	// is the POST-form counterpart, keyed by (action + field-name) signature so the
	// same JS-driven form (e.g. a stock-check present on every product page) is only
	// triggered once. Both guarded by submittedFormsMu; both capped by
	// config.SubmitFormMaxVariants (shared budget).
	submittedFormsMu   sync.Mutex
	submittedForms     map[string]bool
	submittedPostForms map[string]bool

	// primedLinks dedups parameterized-anchor priming across the whole crawl (each
	// URL fetched once) and primedLinkShapes caps how many distinct value-variants
	// of one endpoint shape are primed (mirrors the capture's MaxParamValueVariants
	// so priming never fetches more than the capture would keep). Guarded by
	// primedLinksMu.
	primedLinksMu    sync.Mutex
	primedLinks      map[string]bool
	primedLinkShapes map[string]int

	// loginCTAPrimed marks that the one-shot login-CTA drive has already run, so a
	// crawl that revisits the landing does not re-enter the auth flow repeatedly.
	loginCTAPrimed bool

	// loginCredHosts single-flights the common-credential login pass per host, so
	// a login form reachable from many states is only sprayed once. Guarded by
	// loginCredMu.
	loginCredMu    sync.Mutex
	loginCredHosts map[string]bool

	// selfRegisterHosts single-flights the self-registration pass per host.
	// Registering is a write, so it must happen at most once regardless of how
	// many states expose the signup form. Guarded by selfRegisterMu.
	selfRegisterMu    sync.Mutex
	selfRegisterHosts map[string]bool

	// speculativeScript is the link-discovery script with the crawl's cap already
	// substituted. Rendered once: the cap is fixed for the crawl and the script is
	// several KB, so rebuilding it per state would re-ship the same bytes on the
	// hottest path.
	speculativeScript string

	// failedActions collects actions that errored mid-crawl so the retry sweep can
	// re-attempt them after the queue drains. Guarded by failedActionsMu.
	failedActionsMu sync.Mutex
	failedActions   []failedAction

	mu      sync.Mutex
	stats   Stats
	running bool
	// harvestedAuth is a JWT/Bearer token read from the app's client storage after
	// a confirmed default-credential login, carried forward so token-based SPAs are
	// scanned authenticated (guarded by mu). Empty when no login succeeded.
	harvestedAuth string

	// authOps installs credentials on a page (zero value: the page's own
	// methods). credentialHeadersWithdrawn is set once the crawl leaves the
	// credential scope; later pages do not get the headers back (guarded by mu).
	authOps pageAuthOps
	// authGen is the live-session credential generation last applied;
	// guarded by mu.
	authGen uint64
	// domXssHasCandidates / domXssCheckedAt memoize the DOM-XSS prefilter for
	// the drain check.
	domXssHasCandidates atomic.Bool
	domXssCheckedAt     atomic.Int64
	// popupSeeded is how many of Stats.PopupURLs have been browsed as
	// frontier seeds (guarded by mu).
	popupSeeded int
	// authDirty is set by the AuthMonitor's Changed channel; the next action
	// re-applies the session's credentials.
	authDirty                  atomic.Bool
	credentialHeadersWithdrawn bool
}

// browserCountClampWarn makes the browser_count clamp warn once per process
// rather than once per target crawl.
var browserCountClampWarn sync.Once

// Stats holds crawl statistics.
type Stats struct {
	StatesDiscovered    int
	StatesDuplicate     int
	ActionsExecuted     int
	ActionsFailed       int
	ConsecutiveFailures int // Current streak of consecutive failures (across tabs)
	// FormsSubmitted counts form submissions dispatched by every mechanism
	// (see submitMechanisms); written only by countSubmitDispatched.
	// FormSubmitsPrevented counts submissions the interaction policy refused at
	// a dispatch point. FormSubmitsUncertain counts POST forms whose outcome
	// could not be attributed, so no fallback was sent.
	FormsSubmitted       int
	FormSubmitsPrevented int
	FormSubmitsUncertain int
	// SkippedDestructive counts click candidates the destructive-click guard
	// dropped (spidering.interaction.deny_click_pattern).
	SkippedDestructive int64
	// SkippedControls is a bounded sample of those refusals by name
	// (scanevents.MaxSkippedControlSample).
	SkippedControls []scanevents.SkippedControl
	// BodiesFailed counts captured responses whose body fetch failed;
	// they were stored provisionally, upgradeable by a later copy.
	BodiesFailed int
	// PopupSeedsCrawled counts popup URLs browsed into the frontier.
	PopupSeedsCrawled int
	// PopupURLs are in-scope URLs opened in popups by crawl actions;
	// their traffic is captured and the runner can seed them.
	PopupURLs      []string
	BacktrackCount int
	InvariantFails int
	StartTime      time.Time
	EndTime        time.Time

	// Start-redirect observations (default host-scope rule only).
	// OffHostLanding is true when the start URL redirected the browser to a host
	// outside the target's scope. LandingURL is that post-redirect URL.
	// LandingIsLogin marks it as an apparent login/SSO wall (crawl can't proceed
	// unauthenticated). HostAdopted marks a non-login landing whose host was
	// pulled into scope so the crawl continued.
	OffHostLanding bool
	LandingURL     string
	LandingIsLogin bool
	HostAdopted    bool

	// WallHosts are the hosts denied as login/SSO walls during the crawl — the
	// landing host plus every redirect hop that looked like an authentication
	// endpoint. The caller feeds these into the scan-wide fuzz exclusion, so a
	// later phase never brute-forces the identity provider. Reporting the whole
	// chain rather than just the landing matters: an OAuth bounce routinely
	// crosses two hosts (an authorize endpoint on one, the login form on
	// another), and excluding only the last one leaves the first a fuzz target.
	WallHosts []string

	// LoginCTADriven is true when the one-shot login-CTA priming found and clicked
	// a login call-to-action on the landing, driving the OAuth/SAML/SSO flow.
	// LoginCTAText is the CTA's visible label (for logging).
	LoginCTADriven bool
	LoginCTAText   string

	// Common-credential login pass (only runs at --intensity deep, against a
	// confirmed local login form). LoginCredsTried counts credential pairs
	// submitted across the crawl; LoginCredsSucceeded counts forms where a pair
	// authenticated; LoginCredsURL is the last login form the pass ran against.
	LoginCredsTried     int
	LoginCredsSucceeded int
	LoginCredsURL       string

	// Frontier seeding from robots.txt / sitemap.xml. SeedURLsDiscovered counts
	// in-scope locations those files declared; SeedURLsCrawled counts how many of
	// them were additionally browsed into states (the rest are recorded only).
	SeedURLsDiscovered int
	SeedURLsCrawled    int

	// Caller-supplied seeds (Config.ExtraSeeds, e.g. client routes from the
	// target's JavaScript): ExtraSeedsAccepted survived resolution, scope,
	// dedup and the cap; ExtraSeedsCrawled were browsed into the frontier.
	ExtraSeedsAccepted int
	ExtraSeedsCrawled  int

	// SpeculativeLinksFetched counts URL-like strings scraped from comments and
	// inline script that were fetched and recorded.
	SpeculativeLinksFetched int

	// Self-registration. SelfRegistered is true when a signup form was completed
	// and the app accepted it; SelfRegisterIdentity is the identity created, which
	// the login pass then reuses.
	SelfRegistered       bool
	SelfRegisterIdentity string

	// FollowUpPassesRun counts extra sweeps run after the first pass drained.
	// ActionsRetried / ActionsRecovered count the end-of-crawl retry sweep and how
	// many of those retries then succeeded.
	FollowUpPassesRun int
	ActionsRetried    int
	ActionsRecovered  int

	// AuthState is the authentication outcome: AuthNotRequested,
	// AuthConfigured, AuthApplied or AuthFailed (see page_auth.go).
	// CredentialOriginsDenied counts hosts the operator's credential headers
	// were kept from (outside the operator scope); CredentialHostsDenied names
	// them — hosts only, never header values.
	AuthState               string
	CredentialOriginsDenied int
	CredentialHostsDenied   []string

	// AuxFetchesDenied counts URLs an in-page primer (iframe, GET-form, anchor,
	// seed, speculative) wanted to fetch but the operator scope (or a denied
	// login wall) did not admit — see admissibleFetchURLs.
	AuxFetchesDenied int

	// WaitConditionsFailed counts readiness (wait) conditions that timed out;
	// WaitConditionFailures holds up to maxWaitConditionFailures of their
	// distinct selectors.
	WaitConditionsFailed  int
	WaitConditionFailures []string
}

// New creates a new crawler.
func New(cfg *config.Config) (*Crawler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	candidatesConfig := &action.UnfiredFragmentCandidatesConfig{
		MaxRepeat:             action.DefaultMaxRepeat,
		SkipExploredActions:   true,
		ApplyNonSelAdvantage:  false,
		RestoreConnectedEdges: false,
	}

	c := &Crawler{
		config:              cfg,
		graph:               state.NewGraph(),
		candidates:          action.NewUnfiredFragmentCandidates(candidatesConfig, nil), // StateProvider set after graph init
		extractor:           action.NewCandidateElementExtractor(cfg),
		comparator:          state.NewComparator(cfg),
		formHandler:         form.NewHandler(cfg),
		fragManager:         fragment.NewManager(),
		crawlConditions:     make([]*condition.Condition, 0),
		waitConditions:      make([]*condition.WaitCondition, 0),
		invariants:          make([]*condition.Condition, 0),
		formCache:           make(map[string][]*form.DetectedInput),
		eventableConditions: condition.NewEventableConditionChecker(),
		writer:              network.NopWriter{}, // Default no-op; override with SetWriter()
		stats:               Stats{},
		loginCredHosts:      make(map[string]bool),
		selfRegisterHosts:   make(map[string]bool),
		wallHosts:           make(map[string]bool),
		speculativeScript:   renderSpeculativeScript(cfg.SpeculativeMaxLinks),
		// NOTE: the primary tab's stateMachine and crawlPath, and session, are
		// initialized in initializeIndexState()
	}
	c.primary = &tabWorker{id: 0, formHandler: c.formHandler, extractor: c.extractor}

	// Attach a per-crawl fill context so form values become response-aware:
	// identity values (email/username/password) stay consistent across a
	// register→login flow, on-page examples are preferred, and email/username are
	// derived from the target. The login-credential pass reads back the same
	// context to reuse an identity registered earlier in the crawl.
	c.formHandler.SetFillContext(form.NewFillContext(cfg.URL))

	// Convert config conditions
	for _, cc := range cfg.CrawlConditions {
		c.crawlConditions = append(c.crawlConditions, condition.NewFromConfig(cc))
	}

	for _, wc := range cfg.WaitConditions {
		c.waitConditions = append(c.waitConditions, condition.NewWaitConditionFromConfig(wc))
	}

	c.stats.AuthState = c.initialAuthState()

	// Initialize MAB policy if strategy is adaptive
	// RLCRAWLER PARITY: Use DefaultK=100 for Exp3.1 algorithm
	if cfg.CrawlStrategy == config.CrawlStrategyAdaptive {
		c.mabPolicy = mab.NewMABExp3Policy(mab.DefaultK)
		c.candidates.SetMABPolicy(c.mabPolicy)
		zap.L().Debug("MAB Exp3.1 policy initialized",
			zap.Int("K", mab.DefaultK),
			zap.String("strategy", string(cfg.CrawlStrategy)))
	}

	return c, nil
}

// SetWriter sets the network traffic writer used during crawling.
// Must be called before Run().
func (c *Crawler) SetWriter(w network.Writer) {
	c.writer = w
}

// AddRequestCounters registers counters the crawl's capture increments for every
// request the browser sends. Must be called before Run; RunOnBrowser counts
// through the capture it is handed, so it ignores these.
func (c *Crawler) AddRequestCounters(rc network.RequestCounters) {
	c.requestCounters = append(c.requestCounters, rc)
}

// AddInvariant adds an invariant condition that must always hold.
func (c *Crawler) AddInvariant(inv *condition.Condition) {
	c.invariants = append(c.invariants, inv)
}

// SetInvariantChecker sets the invariant checker for structured invariant management.
func (c *Crawler) SetInvariantChecker(checker *condition.InvariantChecker) {
	c.invariantChecker = checker
}

// SetFormTrainer sets the form trainer for reproducible form testing.
func (c *Crawler) SetFormTrainer(trainer *form.FormTrainer) {
	c.formTrainer = trainer
}

// GetFormTrainer returns the form trainer.
func (c *Crawler) GetFormTrainer() *form.FormTrainer {
	return c.formTrainer
}

// SetMetricsCollector sets the metrics collector for benchmark tracking.
func (c *Crawler) SetMetricsCollector(collector *metrics.Collector) {
	c.metricsCollector = collector
}

// GetMetricsCollector returns the metrics collector.
func (c *Crawler) GetMetricsCollector() *metrics.Collector {
	return c.metricsCollector
}

// SetClusterManager sets the ND cluster manager for near-duplicate state clustering.
func (c *Crawler) SetClusterManager(mgr *state.NDClusterManager) {
	c.clusterMgr = mgr
}

// GetClusterManager returns the ND cluster manager.
func (c *Crawler) GetClusterManager() *state.NDClusterManager {
	return c.clusterMgr
}

// AddEventableCondition adds an eventable condition for form-to-element linking.
// This enables generating multiple action variants with different form input values.
func (c *Crawler) AddEventableCondition(ec *condition.EventableCondition) {
	c.eventableConditions.Add(ec)
}

// GetEventableConditions returns the eventable condition checker.
func (c *Crawler) GetEventableConditions() *condition.EventableConditionChecker {
	return c.eventableConditions
}

// Run starts the crawl.
func (c *Crawler) Run(ctx context.Context) (*Result, error) {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil, fmt.Errorf("crawler is already running")
	}
	c.running = true
	c.stats.StartTime = time.Now()
	c.mu.Unlock()

	zap.L().Debug("Crawler starting",
		zap.String("url", c.config.URL.String()),
		zap.Int("max_states", c.config.MaxStates),
		zap.Int("max_depth", c.config.MaxDepth),
		zap.String("strategy", string(c.config.CrawlStrategy)))

	defer func() {
		c.mu.Lock()
		c.running = false
		c.stats.EndTime = time.Now()
		c.mu.Unlock()
	}()

	// The crawler pins exactly one browser for the entire crawl (see the
	// Pool.Get() note below) and parallelizes with tabs inside it, so launching
	// the configured BrowserCount>1 only burns startup time and memory without
	// adding any crawl throughput. Cap it to one and point at tabs.
	if c.config.BrowserCount > 1 {
		browserCountClampWarn.Do(func() {
			zap.L().Warn("Spidering: browser_count > 1 requested, but the crawler drives one browser — launching 1; set spidering.tabs to crawl with several tabs in it",
				zap.Int("configured", c.config.BrowserCount))
		})
		c.config.BrowserCount = 1
	}

	// Create browser pool FIRST (needed for browser-level capture)
	pool, err := browser.NewPoolWithContext(ctx, c.config)
	if err != nil {
		return nil, fmt.Errorf("failed to create browser pool: %w", err)
	}
	c.browserPool = pool
	zap.L().Debug("Browser pool created", zap.Int("size", c.config.BrowserCount))
	defer func() {
		if err := pool.Close(); err != nil {
			zap.L().Warn("Browser pool close failed", zap.Error(err))
		}
	}()

	// Bind the crawl context to every page the pool creates so the deadline /
	// cancellation reaches rod's per-operation timeouts. Without this the
	// max-duration is only honored at Go-level loop boundaries, while in-flight
	// browser work (navigation, WaitStable, clicks, form fills, the per-page
	// priming steps) runs to its own fixed rod timeouts — the spider overshoots
	// the deadline by however long the current browser operation takes to wind
	// down. Must run before initializeIndexState creates the first page.
	pool.SetCrawlContext(ctx)

	// Create traffic capture with the configured writer
	capture := network.New(c.writer, c.config.NoColor, c.config.Silent, c.config.Verbose, c.config.IncludeResponseBody, c.config.IncludeResponseHeaders, c.config.URL.Hostname(), "spider")
	// Keep several distinct query-value variants per endpoint shape (category/
	// filter/tab/search links) instead of collapsing them to one representative.
	capture.SetMaxParamValueVariants(c.config.MaxParamValueVariants)
	capture.SetMaxBodyBytes(c.config.MaxCaptureBodyBytes)
	for _, rc := range c.requestCounters {
		capture.AddRequestCounters(rc)
	}
	// Keep out-of-scope subresources (a login page's CAPTCHA widget, analytics
	// beacons) out of the live log — they are dropped before storage anyway.
	capture.ScopeFilter = c.config.ScopeFilter
	// Feed in-scope document/XHR responses to the live session's logged-out
	// detector, and re-apply its credentials when it re-logs in.
	if mon := c.config.AuthMonitor; mon != nil {
		capture.OnResponse = c.observeAuthResponse
		c.watchAuthChanges(ctx, mon)
	}
	// Classify the same responses for edge blocks and challenge pages.
	capture.OnBlock = c.config.OnBlock
	// A finished crawl is not failed over a flush error: the capture close
	// error is the writer's drop tally, which the caller reads from the
	// writer's receipt. Logged so it is never silent.
	defer func() {
		if err := capture.Close(); err != nil {
			zap.L().Warn("Traffic capture closed with lost records", zap.Error(err))
		}
		c.mu.Lock()
		c.stats.BodiesFailed = capture.BodiesFailed()
		c.mu.Unlock()
	}()

	// Start capture at BROWSER level (captures ALL pages, every tab included).
	// Pin one browser for the entire crawl — Pool.Get() round-robins, so calling
	// it from each helper would silently rotate to a different browser whose
	// CurrentPage is nil. This Crawler fans out across tabs of this one browser,
	// never across browsers.
	br := pool.Get()
	if br == nil {
		return nil, fmt.Errorf("browser pool returned nil browser")
	}
	c.browser = br
	zap.L().Debug("Starting network capture",
		zap.Bool("include_body", c.config.IncludeResponseBody),
		zap.Bool("include_headers", c.config.IncludeResponseHeaders))
	if err := capture.Start(br.RodBrowser()); err != nil {
		return nil, fmt.Errorf("failed to start traffic capture: %w", err)
	}
	zap.L().Debug("Traffic capture enabled")

	return c.crawlWithBrowser(ctx, br, capture)
}

// RunOnBrowser crawls this seed using a browser + capture owned by an external
// SpiderSession instead of creating (and tearing down) its own pool/capture. This
// is how one browser context is reused across several same-host seeds so cookies,
// local storage, and capture-level dedup persist between them. The session owns
// the pool/capture lifecycle; this method only rebinds the seed's deadline onto
// the shared browser and runs the crawl.
func (c *Crawler) RunOnBrowser(ctx context.Context, br *browser.Browser, capture *network.Capture) (*Result, error) {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil, fmt.Errorf("crawler is already running")
	}
	c.running = true
	c.stats.StartTime = time.Now()
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.running = false
		c.stats.EndTime = time.Now()
		c.mu.Unlock()
	}()

	if br == nil {
		return nil, fmt.Errorf("RunOnBrowser: nil browser")
	}
	c.browserPool = nil // session owns the pool; never close it from here
	// Rebind THIS seed's deadline/cancellation onto every page the shared browser
	// creates, exactly as Run does via pool.SetCrawlContext for a fresh pool.
	br.SetCrawlContext(ctx)

	zap.L().Debug("Crawler starting on shared browser",
		zap.String("url", c.config.URL.String()),
		zap.Int("max_states", c.config.MaxStates),
		zap.String("strategy", string(c.config.CrawlStrategy)))

	return c.crawlWithBrowser(ctx, br, capture)
}

// crawlWithBrowser runs the seed-level crawl once the browser and capture are
// ready: it pins the browser, initializes the index state, runs the main loop,
// and builds the result. It is the shared body of Run (own pool/capture) and
// RunOnBrowser (session-owned pool/capture).
func (c *Crawler) crawlWithBrowser(ctx context.Context, br *browser.Browser, capture *network.Capture) (*Result, error) {
	if br == nil {
		return nil, fmt.Errorf("browser pool returned nil browser")
	}
	c.browser = br
	// Upload fixtures are generated on demand into a run-owned directory; hold
	// it for the crawl so the last crawl out removes it.
	form.RetainGeneratedFiles()
	defer form.ReleaseGeneratedFiles()
	// Both entry points funnel through here with the capture in hand, so this is
	// the one place the wiring cannot be missed. Setting it on the Config instead
	// silently failed on the multi-seed SpiderSession path, which rebuilds a fresh
	// Config per seed and never carried the hook across.
	if capture != nil {
		c.observedLoginHosts = capture.LoginHostsSeen
	}

	if c.eventableConditions != nil && c.eventableConditions.Count() > 0 {
		c.extractor.SetFormHandler(&formHandlerAdapter{checker: c.eventableConditions})
	}

	// Extra tabs are opened by the first crawlLoop; close them however this
	// returns. The explicit close below runs first on the normal path, so the
	// DOM-XSS probe does not share the browser with idle tabs.
	defer c.closeExtraTabs()

	// Initialize
	if err := c.initializeIndexState(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize: %w", err)
	}

	// If the start URL bounced off-host and we adopted the landing host into
	// scope (evaluateStartRedirect, called during init), re-point the capture's
	// cross-origin log filter at it. Otherwise it keeps keying on the original
	// target host and suppresses every adopted-host line from stderr — the run
	// looks silent even though records are being written.
	if c.adoptedHost != "" {
		capture.SetTargetHost(c.adoptedHost)
	}

	// Seed the frontier from the host's own route declarations before the loop
	// starts. This belongs here rather than in index-state initialization: every
	// step there operates on the landing page, whereas this navigates to other
	// locations and folds each into the graph — a frontier-level operation, and a
	// sibling of the follow-up/retry passes below. Running it after
	// initializeIndexState also means scope adoption is already decided, so seeds
	// filter against the final boundary and land under the retargeted capture.
	if page := br.CurrentPage(); page != nil {
		c.seedFrontier(ctx, page)
	}

	// Main crawl loop
	if err := c.crawlLoop(ctx); err != nil {
		zap.L().Debug("Crawl loop ended", zap.Error(err))
	}

	// Popups the crawl opened (window.open, target=_blank) were closed after
	// their traffic was captured; their in-scope URLs are frontier seeds:
	// browse them into the graph and explore what they offer.
	// Bounded rounds: exploring a popup's page can open more popups.
	for round := 0; round < maxPopupSeedRounds; round++ {
		page := br.CurrentPage()
		if page == nil || c.crawlPopupSeeds(ctx, page) == 0 {
			break
		}
		if err := c.crawlLoop(ctx); err != nil {
			zap.L().Debug("Popup-seed crawl loop ended", zap.Error(err))
		}
	}

	// Re-walk for actions that only became available partway through the pass
	// (an authenticated menu, a section unlocked by an earlier action), then
	// re-attempt the actions that failed on transient page conditions. Both are
	// no-ops when the crawl stopped on its budget rather than by draining.
	c.runFollowUpPasses(ctx)
	c.retryFailedActions(ctx)
	c.closeExtraTabs()

	// The map of what was reached and how is written by the caller
	// (WriteGraphDump) once the capture has drained, so the graph's manifest can
	// carry the final capture receipt.

	// Log final MAB summary
	c.logMABFinalSummary()

	return c.buildResult(ctx), nil
}

// logMABFinalSummary logs comprehensive MAB policy state at end of crawl.
func (c *Crawler) logMABFinalSummary() {
	if c.mabPolicy == nil {
		return
	}

	k, r, gThr, eta, globalR := c.mabPolicy.GetGlobalParams()
	stateCount := c.mabPolicy.GetStateCount()
	actionCount := c.mabPolicy.GetActionCount()

	zap.L().Debug("=== MAB FINAL SUMMARY ===",
		zap.Int("K", k),
		zap.Int("round", r),
		zap.Float64("G_thr", gThr),
		zap.Float64("eta", eta),
		zap.Float64("global_R", globalR),
		zap.Int("total_states", stateCount),
		zap.Int("total_actions", actionCount))
}

// logMABSummary logs a summary of MAB policy state for debugging.
func (c *Crawler) logMABSummary() {
	if c.mabPolicy == nil {
		return
	}

	k, r, gThr, eta, globalR := c.mabPolicy.GetGlobalParams()
	stateCount := c.mabPolicy.GetStateCount()
	actionCount := c.mabPolicy.GetActionCount()

	zap.L().Debug("MAB Summary",
		zap.Int("K", k),
		zap.Int("round", r),
		zap.Float64("G_thr", gThr),
		zap.Float64("eta", eta),
		zap.Float64("global_R", globalR),
		zap.Int("states_tracked", stateCount),
		zap.Int("actions_tracked", actionCount))
}

// buildResult builds the crawl result.
func (c *Crawler) buildResult(ctx context.Context) *Result {
	// The extra tabs handed their paths over when they closed.
	c.recordCrawlPath(c.primary)
	if c.session != nil {
		c.session.MarkEnd()
	}

	res := &Result{
		Config:    c.config,
		Graph:     c.graph,
		Fragments: c.fragManager.GetStats(),
		Session:   c.session,
	}

	// Harvest the browser session (cookies + UA) while the browser is still
	// alive — buildResult runs before the deferred pool.Close() in Run. Failures
	// are non-fatal: the crawl already succeeded, we just can't carry the session.
	if c.browser != nil {
		res.BrowserUserAgent = c.browser.UserAgent()
		if cookies, err := c.browser.HarvestCookies(); err != nil {
			zap.L().Debug("Failed to harvest browser cookies for session carry-forward", zap.Error(err))
		} else {
			res.HarvestedCookies = cookies
		}
	}
	// Carry a token-auth session credential harvested during a confirmed login spray.
	c.mu.Lock()
	res.HarvestedAuthorization = c.harvestedAuth
	c.mu.Unlock()

	// Confirm DOM-based XSS on reflected client routes the crawl visited. Runs last
	// (it navigates the browser) and only after a cheap no-navigation prefilter finds
	// a reflected parameter, so it never spins up navigations blindly. Skips entirely
	// when ctx is already cancelled and budgets itself from the remaining parent
	// deadline, so it can't keep hitting the target after the operator stops the scan.
	res.DOMXssFindings = c.probeDOMXSS(ctx)

	// Stamp the end time only now, after every post-pass, and copy stats into the
	// immutable Result under the lock. The outer Run/RunOnBrowser defer also sets
	// EndTime, but it runs after this Result is built and copies c.stats by value,
	// so without stamping here Result.Stats.EndTime stays zero and Result.Duration()
	// underflows to a huge negative value.
	c.mu.Lock()
	c.stats.EndTime = time.Now()
	res.Stats = c.stats
	c.mu.Unlock()
	res.Stats.ConsecutiveFailures = int(c.consecutiveFails.Load())
	if c.extractor != nil {
		res.Stats.SkippedDestructive = c.extractor.SkippedDestructive()
		res.Stats.SkippedControls = c.extractor.SkippedControls()
	}

	return res
}

// Stats returns current statistics.
func (c *Crawler) GetStats() Stats {
	c.mu.Lock()
	st := c.stats
	c.mu.Unlock()
	st.ConsecutiveFailures = int(c.consecutiveFails.Load())
	return st
}

// IsRunning returns true if crawler is running.
func (c *Crawler) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// Graph returns the state graph.
func (c *Crawler) Graph() *state.Graph {
	return c.graph
}
