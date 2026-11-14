package config

import (
	"fmt"
	"github.com/vigolium/vigolium/pkg/safety"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// FormFillMode determines how forms are filled during crawling.
type FormFillMode string

const (
	FormFillNormal FormFillMode = "normal" // Use configured values only
	FormFillRandom FormFillMode = "random" // Generate random values
)

// FragmentationMode determines how page fragments are extracted.
type FragmentationMode string

// CrawlScope is a function that determines if a URL should be crawled.
type CrawlScope func(url string) bool

const (
	FragmentationLandmark FragmentationMode = "landmark" // Fast, semantic landmark-based (default)
	FragmentationVIPS     FragmentationMode = "vips"
)

// CrawlStrategy determines both state selection order and action selection mode.
type CrawlStrategy string

const (
	// CrawlStrategyNormal uses BFS state selection + FIFO action selection (default)
	CrawlStrategyNormal CrawlStrategy = "normal"
	// CrawlStrategyRandom uses random state selection + FIFO action selection
	CrawlStrategyRandom CrawlStrategy = "random"
	// CrawlStrategyOldestFirst uses DFS-like state selection + FIFO action selection
	CrawlStrategyOldestFirst CrawlStrategy = "oldest_first"
	// CrawlStrategyShallowFirst prioritizes states with lower depth + FIFO action selection
	CrawlStrategyShallowFirst CrawlStrategy = "shallow_first"
	// CrawlStrategyAdaptive uses BFS state selection + adaptive MAB action selection (Exp3.1 algorithm).
	// Reference: "Less is More: Boosting Coverage of Web Crawling through Adversarial Multi-Armed Bandit"
	CrawlStrategyAdaptive CrawlStrategy = "adaptive"
)

// ConditionType defines the type of condition check.
type ConditionType string

const (
	CondURLContains    ConditionType = "url_contains"
	CondURLMatches     ConditionType = "url_matches" // regex
	CondElementExists  ConditionType = "element_exists"
	CondElementVisible ConditionType = "element_visible"
	CondJavaScript     ConditionType = "js"
	// MEDIUM PRIORITY: Additional condition types
	CondXPathExists ConditionType = "xpath_exists" // Check if XPath matches any element
	CondDOMRegex    ConditionType = "dom_regex"    // Regex match on DOM content
	CondCountLimit  ConditionType = "count_limit"  // Limit based on occurrence count
)

// ConditionConfig defines a crawl condition.
type ConditionConfig struct {
	Type   ConditionType
	Value  string // URL pattern, selector, or JS expression
	Negate bool   // Invert condition
	// For count_limit condition
	MaxCount int // Maximum allowed occurrences (for CondCountLimit)
	// For preconditions (conditions that must be true before this condition is checked)
	Preconditions []ConditionConfig
}

// Wait-condition URL matchers (WaitConditionConfig.Matcher).
const (
	URLMatchSubstring = "substring" // case-insensitive substring of the page URL (default)
	URLMatchRegex     = "regex"     // Go regular expression matched against the page URL
)

// WaitConditionConfig defines a wait condition for specific URLs.
type WaitConditionConfig struct {
	// URLMatch limits the condition to pages whose URL matches it under
	// Matcher; empty applies it to every page.
	URLMatch string
	// URLPattern is the old name of URLMatch, read only when URLMatch is
	// empty (EffectiveURLMatch is the one place the two are reconciled).
	// Despite the name it was always a case-insensitive substring.
	//
	// Deprecated: use URLMatch.
	URLPattern string
	// Matcher is URLMatchSubstring (the default, also "") or URLMatchRegex.
	Matcher  string
	Selector string        // Wait for this element
	Visible  bool          // Wait for visibility (not just existence)
	Timeout  time.Duration // Max wait time
}

// EffectiveURLMatch is URLMatch, falling back to the deprecated URLPattern.
func (w WaitConditionConfig) EffectiveURLMatch() string {
	if w.URLMatch != "" {
		return w.URLMatch
	}
	return w.URLPattern
}

// Validate rejects an unknown matcher and a regex that does not compile, so a
// typo is a config error instead of a condition that silently never matches.
func (w WaitConditionConfig) Validate() error {
	switch w.Matcher {
	case "", URLMatchSubstring:
	case URLMatchRegex:
		if _, err := regexp.Compile(w.EffectiveURLMatch()); err != nil {
			return fmt.Errorf("invalid URL regex %q: %w", w.EffectiveURLMatch(), err)
		}
	default:
		return fmt.Errorf("matcher must be %q or %q, got: %q", URLMatchSubstring, URLMatchRegex, w.Matcher)
	}
	return nil
}

// FormInputConfig defines how to fill a specific form input.
type FormInputConfig struct {
	How    string   // "id", "name", "xpath"
	Value  string   // The identification value (raw ID, name, or xpath)
	Type   string   // text, checkbox, radio, select
	Values []string // Possible values (rotate through)
}

// Config holds all crawler configuration.
type Config struct {
	// Target
	URL                 *url.URL
	MaxDepth            int           // 0 = unlimited
	MaxStates           int           // 0 = unlimited
	MaxDuration         time.Duration // 0 = unlimited
	DrainGrace          time.Duration // stop scheduling new states this long before the deadline (shouldTerminate); 0 = off
	MaxConsecutiveFails int           // 0 = disabled (unlimited)

	// Browser
	Headless      bool
	BrowserCount  int
	BrowserEngine string // "chromium" (default), "ungoogled", or "fingerprint"
	BrowserPath   string // explicit path to browser binary (overrides auto-detection)

	// Tabs is how many tabs of the one browser crawl the shared state graph at
	// once (0 or 1 = one tab, the single-threaded crawl). Each extra tab is a
	// consumer of the same frontier: it claims a state, reaches it and fires its
	// actions while the others do the same elsewhere. See TabsCount.
	Tabs int

	// TabIsolation is TabIsolationShared ("" too): every tab shares the
	// browser's default context — one cookie jar, so a logout in one tab logs
	// the others out — or TabIsolationContext: each extra tab gets a browser
	// context of its own, seeded with the configured auth and the cookies the
	// first tab holds when it opens.
	TabIsolation string

	// Stealth is the stealth mode: StealthAuto (or ""), StealthOn or StealthOff.
	// See StealthEnabled for what auto resolves to.
	Stealth string

	// BrowserCompat is the set of browser security exceptions in force; see
	// DefaultBrowserCompat for the defaults.
	BrowserCompat BrowserCompat

	// Auth & Network
	BasicAuthUser string
	BasicAuthPass string
	ProxyURL      string
	// ProxyAllowLoopback removes Chrome's implicit proxy bypass for
	// localhost/127.0.0.1 so an intercepting proxy also sees traffic to a
	// target on the loopback. Off by default — only opt in when the proxy is
	// meant to capture everything (e.g. browser replay through Burp).
	ProxyAllowLoopback bool
	InitialCookies     []*http.Cookie // Cookies to set before crawling (from auth bootstrap)

	// ExtraHeaders are non-cookie authentication/custom headers (Authorization,
	// X-Api-Key, operator -H headers, …) applied to every request the browser
	// makes via CDP. Populated from the same session/header set the HTTP scan
	// phases use, so the browser explores authenticated instead of only the
	// unauthenticated shell. Cookie headers are split out into InitialCookies.
	// They are installed only while the crawl stays on an origin the operator
	// scope admits (see crawler.applyPageAuth).
	ExtraHeaders map[string]string

	// RequireAuth fails the crawl, instead of continuing anonymously, when
	// authentication was configured (InitialCookies/ExtraHeaders) but could
	// not be applied to the start page.
	RequireAuth bool

	// Wait times
	WaitAfterReload time.Duration
	WaitAfterEvent  time.Duration
	PageLoadTimeout time.Duration
	DOMStableTime   time.Duration
	ElementTimeout  time.Duration // Default timeout for finding elements (prevents infinite wait)

	// Clickable Detection
	ClickSelectors   []string // CSS selectors for clickables
	ExcludeSelectors []string // CSS selectors to exclude
	// DenyClickPattern is a case-insensitive regex; a click candidate whose
	// text, href, aria-label, title or value matches it is never clicked
	// (SAFE-9). Hover candidates are exempt. Empty disables the guard. The
	// default is pkg/safety's destructive pattern (log out, delete, remove,
	// deactivate, unsubscribe, close account, …).
	DenyClickPattern string
	// MethodAllowed, when set, is the scan's traffic policy (SAFE-8): the
	// browser fails any request whose method it refuses (BlockedByClient).
	MethodAllowed                func(method string) bool
	DontClickSelectors           []string
	DontClickChildrenOfSelectors []string
	UseCDPDetection              bool     // Enable CDP event listener detection
	ClickOnce                    bool     // Click each element only once
	CrawlFrames                  bool     // Crawl iframes
	ExcludeFrames                []string // Frame names/patterns to exclude from crawling
	CrawlHiddenAnchors           bool     // Crawl hidden anchor elements
	RandomizeElements            bool     // Randomize order of extracted elements

	// MaxListenerProbeNodes caps the listener-bearing nodes the CDP listener
	// pass turns into click candidates per state (0 = 2000, negative = no cap).
	MaxListenerProbeNodes int

	// Policy is what the crawl is permitted to change. Install it with
	// ApplyPolicy, which also sets the derived switches below
	// (FormFillEnabled, SubmitGetForms, SubmitPostForms, SelfRegister,
	// LoginCredentialAttempts) — those still gate their own mechanisms, and
	// gates with no legacy switch read Policy directly.
	Policy InteractionPolicy

	// Form Handling
	FormFillEnabled bool
	FormFillMode    FormFillMode
	FormInputs      []FormInputConfig

	// IdentityEmailDomain is the domain of every generated email address
	// (signup, login and plain email fields), never one derived from the
	// target: a target-domain address is plausible real mail at the customer's
	// own domain. Default DefaultIdentityEmailDomain; a page-provided example
	// address is still preferred.
	IdentityEmailDomain string

	// SubmitGetForms makes the crawler, after filling a page's forms, synthesize
	// and fetch the submit URL of each GET form (its resolved action plus the
	// filled field values, e.g. a "/catalog" search box → /catalog?searchTerm=a)
	// so the resulting request is captured. The interaction crawl only submits a
	// form when its submit control happens to be clicked as an ordinary clickable,
	// which the bounded action budget frequently never selects; this makes GET
	// form submission deterministic. Default on; bounded by SubmitFormMaxVariants.
	SubmitGetForms bool
	// SubmitFormMaxVariants caps how many distinct GET-form submit URLs are fetched
	// over the whole crawl (0 = default). Guards a page that programmatically wires
	// up many forms from flooding the target. Shared budget with SubmitPostForms.
	SubmitFormMaxVariants int

	// SubmitPostForms makes the crawler, after filling a page's forms, trigger each
	// same-origin POST form so its endpoint is exercised and captured. POST forms are
	// frequently JS-driven (the page intercepts the submit and fires the real request
	// through its own handler with a specific content type — e.g. a stock check that
	// posts XML, a newsletter that posts JSON on button click), so this dispatches the
	// page's submit/click handlers under a navigation guard and, for forms with no JS
	// handler, synthesizes a plain urlencoded/multipart POST. Without it the endpoints
	// behind JS-driven POST forms (a common home for XXE and body/cookie SQLi) are only
	// reached if the bounded interaction crawl happens to click their submit control.
	// Default on; deduped by (action + field-name) signature and bounded by
	// SubmitFormMaxVariants (shared with the GET-form budget).
	SubmitPostForms bool

	// FormHandlerGrace is how long a triggered POST form waits for the page's own
	// handler to send a request attributable to it before the outcome is decided
	// (0 = DefaultFormHandlerGrace). Long enough for a handler that awaits a
	// token fetch or debounces; a handler slower than this is not attributed.
	FormHandlerGrace time.Duration

	// Conditions
	CrawlConditions []ConditionConfig
	WaitConditions  []WaitConditionConfig

	// DOM Comparison
	DOMStripTags  []string // Tags to remove before comparison
	DOMStripAttrs []string // Attributes to remove before comparison

	AvoidUnrelatedBacktracking bool // Skip backtracking through unrelated fragments
	AvoidDifferentBacktracking bool // Skip backtracking through completely different states

	FragmentationMode FragmentationMode // "landmark" (default) or "vips"
	VIPSPDoC          int               // VIPS Permitted Degree of Coherence (1-11), default 11
	VIPSIterations    int               // VIPS iteration count, default 10

	// Output (traffic is written to vigolium's HTTPRecord table via Writer)
	IncludeResponseBody    bool // Include response body in HTTP traffic capture
	IncludeResponseHeaders bool // Include response headers in HTTP traffic capture

	// MaxCaptureBodyBytes caps the encoded size of a dynamic (HTML/JS/JSON/API)
	// response body the capture pulls over CDP. 0 keeps the capture's default
	// (network.DefaultMaxDynamicBodyBytes, above the API-spec ingest window);
	// a negative value removes the ceiling. A skipped body is recorded as
	// too-large with its size, never as an empty body.
	MaxCaptureBodyBytes int64

	// MaxParamValueVariants controls how many DISTINCT query-value variants of the
	// same endpoint shape (same method, path, param-name set and response shape)
	// the capture keeps. The dedup key is otherwise value-blind, so /catalog?
	// category=Books, ?category=Gin, ?category=Juice … all collapse to one record;
	// with N>1, up to N distinct value combinations survive, so filter/category/
	// tab links and search results are not all hidden behind a single arbitrary
	// representative. Bounded so an id sweep (?productId=1..1000) cannot explode
	// the record count. 0 or 1 restores the original value-blind behavior.
	MaxParamValueVariants int

	// Service-worker asset priming. After the index page loads, the crawler
	// discovers service-worker scripts + the web-app/ngsw manifest and fetches
	// the assets the service worker would pre-cache (e.g. Angular's lazy webpack
	// chunks listed in ngsw.json). The browser captures these in-page fetches so
	// they become spidering records — otherwise they are only loaded when the
	// service-worker runtime runs, which a short headless visit does not trigger.
	ServiceWorkerPriming   bool // Enable service-worker asset priming (default on)
	ServiceWorkerMaxAssets int  // Cap on primed asset fetches (0 = default)

	// Iframe-source priming. After a page (the index and every newly discovered
	// state) settles, the crawler enumerates the <iframe>/<frame> src URLs in the
	// live, post-render DOM — including frames a framework injects after first
	// paint (Aura/Lightning, Angular, etc.) that never appear in the served HTML —
	// and fetches the same-origin ones so the browser's network capture records
	// them. A short headless visit that does not exercise the exact flow which
	// mounts a dynamic iframe would otherwise never request its URL, so the page
	// (and any reflected query parameters on it) is never scanned.
	IframePriming   bool // Enable iframe-source priming (default on)
	IframeMaxAssets int  // Cap on primed iframe fetches per crawl (0 = default)

	// NetworkIdleTimeout bounds the extra "wait for the network to go idle" settle
	// performed before harvesting iframe sources, so subframe loads a framework
	// kicks off after first paint complete before the DOM is read (0 = default).
	NetworkIdleTimeout time.Duration

	// AnchorLinkPriming makes the crawler, on each settled page, fetch the same-
	// origin <a href> links that carry a query string directly from the live DOM,
	// so parameterized links a framework renders client-side (e.g. ginandjuice's
	// React category filter → /catalog?category=Books) are captured even when the
	// bounded interaction budget never happens to click them. Distinct value-
	// variants per endpoint shape are kept up to MaxParamValueVariants (so an id
	// sweep stays bounded); deduped and capped across the crawl by
	// AnchorLinkMaxAssets (default on).
	AnchorLinkPriming   bool
	AnchorLinkMaxAssets int // Cap on primed anchor-link fetches per crawl (0 = default)

	// SPASettleTimeout bounds an extra "wait for the network to go idle" settle on
	// the index/seed page before its state is captured and its clickables are
	// extracted. A heavy enterprise SPA (Angular, Salesforce Lightning, …) renders
	// its real UI — including the login CTA — only after a chain of sequential
	// bootstrap XHRs (config → region → i18n → feature flags → content) lands; the
	// short DOMStableTime wait fires while it is still a half-rendered shell, so the
	// CTA and most data calls are missed. This longer settle lets the bootstrap
	// quiesce first (0 = disabled).
	SPASettleTimeout time.Duration

	// WaitDOMQuiescence makes the settle wait for the DOM to stop mutating (not
	// just for the network to go idle) before a page's state is captured and its
	// clickables extracted. A client-rendered page (React/Vue/Angular) mounts its
	// real anchors from an inline script AFTER the framework bundle loads — e.g.
	// ginandjuice's /catalog builds its category-filter <a href="/catalog?
	// category=…"> links via ReactDOM.render — so a snapshot taken at network-idle
	// can miss them. This extra settle lets that render land. Bounded by
	// DOMQuiescenceMax so a page with a perpetual animation/spinner cannot stall
	// the crawl (default on).
	WaitDOMQuiescence bool
	// DOMQuiescenceMax bounds the WaitDOMQuiescence settle. A page whose DOM never
	// fully stops mutating (carousels, live clocks) returns at this bound rather
	// than blocking (0 = default).
	DOMQuiescenceMax time.Duration

	// DismissConsent makes the crawler click cookie-consent "accept" controls
	// (OneTrust et al., piercing shadow DOM) on the index page before capture, so a
	// consent overlay neither blocks the app from rendering its real content nor
	// masks the elements that get extracted/clicked (default on).
	DismissConsent bool

	// AutoScroll makes the crawler scroll the index page through its full height
	// before capture so content and assets that load lazily on scroll
	// (IntersectionObserver-gated sections, infinite-scroll data fetches, deferred
	// hero/bundled-media images) are actually requested and recorded. A content-
	// heavy SPA landing fetches much of its data and imagery only as each section
	// enters the viewport, so a static headless visit that never scrolls misses it
	// (default on).
	AutoScroll bool

	// LoginCTAPriming makes the crawler find and click a login call-to-action
	// ("Log on"/"Sign in"/…) on the landing page to drive the OAuth/SAML/SSO
	// navigation chain it kicks off. An unauthenticated visit to many enterprise
	// apps bounces to a portal landing whose login button starts a cross-origin
	// flow (… /oauth2/authorize → /idp/login → SAML → vendor login); the normal
	// state machine may never click it, so the whole flow — and every URL it
	// touches — is missed. Done once per crawl; the network capture records the
	// chain and the destination page's own XHRs (default on).
	LoginCTAPriming bool

	// LoginCredentialAttempts makes the crawler, ONLY after it has confirmed a
	// local login form (a single password field + an identity field + a submit,
	// posting to an in-scope host — never an external IdP), try a small, documented
	// list of common default credentials (admin:admin, admin:123456, …) plus any
	// identity it registered earlier in the crawl. The goal is discovery: if a pair
	// authenticates, the browser session stays logged in so the crawl reaches the
	// now-unlocked area. It is single-flighted per host, negative-control gated (a
	// random pair must be rejected first, or the whole spray is abandoned), and
	// never a brute-force wordlist, so it cannot lock accounts. Off by default; the
	// runner defaults it on at balanced AND deep intensity unless the operator's
	// interaction policy says otherwise (see LoginCredentialFullList for the list
	// size). Derived from Policy.LoginAttempts by ApplyPolicy. No finding is emitted — the
	// attempts are captured as ordinary traffic.
	LoginCredentialAttempts bool

	// LoginCredentialFullList selects how many default pairs the login-credential
	// pass tries. false (balanced) → a minimal set (admin:admin, admin:123456);
	// true (deep) → the full documented list. Ignored when LoginCredentialAttempts
	// is off. The reused registered identity is always tried regardless.
	LoginCredentialFullList bool

	// Frontier seeding from the host's own route declarations — see seedFrontier
	// for what each file contributes. Both default on.
	SeedFromRobots  bool
	SeedFromSitemap bool
	// SeedMaxURLs caps how many declared locations are recorded; SeedMaxCrawlURLs
	// how many are additionally browsed into states. The second is much smaller:
	// a request is cheap, a navigation plus settle is not.
	SeedMaxURLs      int
	SeedMaxCrawlURLs int

	// ExtraSeeds are caller-supplied entry points (client routes from the
	// target's JavaScript) browsed into the frontier alongside the robots and
	// sitemap seeds; see seedFrontier. MaxExtraSeeds caps how many survive
	// scope, dedup and priority ordering (0 = DefaultMaxExtraSeeds).
	ExtraSeeds    []ExtraSeed
	MaxExtraSeeds int

	// SpeculativeLinks makes the crawler scrape URL-like strings out of HTML
	// comments and inline script in the LIVE document and fetch the same-origin
	// ones — see harvestSpeculativeLinks. Default on.
	SpeculativeLinks    bool
	SpeculativeMaxLinks int

	// SelfRegister makes the crawler look for a public signup form, complete it
	// with a generated identity, and reuse that identity to log in. On an app
	// with open registration the entire authenticated surface is otherwise
	// invisible to an unauthenticated crawl. Off by default — creating an
	// account is a write, so it stays an explicit opt-in at every intensity.
	// Derived from Policy.RegisterAccount by ApplyPolicy.
	SelfRegister bool

	// FollowUpPasses is how many extra sweeps to run after the action queue
	// drains with budget left, re-walking for actions that only became available
	// partway through the first pass — see runFollowUpPasses. 0 disables.
	FollowUpPasses int

	// RetryFailedActions re-attempts actions that failed mid-crawl once the queue
	// drains, bounded by RetryMaxActions — see retryFailedActions. Default on.
	RetryFailedActions bool
	RetryMaxActions    int

	CrawlScope CrawlScope // Custom URL scope filter (nil = default same-domain check)

	// ScopeFilter is the operator's scope boundary in its native (host, path)
	// form. CrawlScope above is the same boundary shaped for a whole URL; callers
	// that have both should set both. Kept alongside rather than derived because
	// the derivation only runs one way: rebuilding a URL from host and path has to
	// invent a scheme and drops the query, so asking the URL-shaped filter a
	// host/path question gives a different answer than asking this one.
	//
	// Used for the traffic capture's log filter, which already has host and path
	// split out and would otherwise pay two URL parses to get back what it had.
	ScopeFilter func(host, path string) bool

	// Crawl strategy - determines both state selection and action selection
	CrawlStrategy CrawlStrategy // Crawl strategy (default: normal)

	// Silent mode - suppress all output including banner
	Silent bool

	// Verbose mode - show all traffic including static files and cross-origin
	Verbose bool

	// NoColor mode - disable colored output
	NoColor bool
}

// DefaultIdentityEmailDomain is the default generated-email domain: reserved by
// RFC 2606 and published with a null MX (RFC 7505), so mail to it is never
// delivered, while form validators that check the TLD or resolve the domain
// still accept it (".invalid" fails both).
const DefaultIdentityEmailDomain = "example.com"

// DefaultClickSelectors returns the default CSS selectors for clickable elements.
func DefaultClickSelectors() []string {
	return []string{
		"a",
		"button",
		"[onclick]",
		"[role=button]",
		"input[type=submit]",
		"input[type=button]",
		"[ng-click]",
		"[data-click]",
		"[v-on\\:click]",
		"[\\@click]",
	}
}

// DefaultStripTags returns the default tags to strip from DOM before comparison.
func DefaultStripTags() []string {
	return []string{
		"script",
		"style",
		"noscript",
		"meta",
		"link",
	}
}

// DefaultStripAttrs returns the default attributes to strip from DOM before comparison.
func DefaultStripAttrs() []string {
	return []string{
		"id",
		"class",
		"style",
		"data-*",
	}
}

// New creates a new Config with the given target URL and default values.
func New(targetURL string) (*Config, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	if u.Scheme == "" {
		u.Scheme = "https"
	}

	if u.Host == "" {
		return nil, fmt.Errorf("target URL must have a host")
	}

	return &Config{
		URL:         u,
		MaxDepth:    0,
		MaxStates:   0,
		MaxDuration: 0,

		Headless:      true,
		BrowserCount:  1,
		BrowserEngine: "chromium", // Default to standard chromium
		BrowserCompat: DefaultBrowserCompat(),

		BasicAuthUser: "",
		BasicAuthPass: "",
		ProxyURL:      "",

		// CRITICAL FIX: (200ms instead of 500ms)
		WaitAfterReload: 200 * time.Millisecond,
		WaitAfterEvent:  200 * time.Millisecond,
		PageLoadTimeout: 30 * time.Second,
		DOMStableTime:   500 * time.Millisecond,
		ElementTimeout:  5 * time.Second, // Safe timeout to prevent infinite waits

		ClickSelectors:               DefaultClickSelectors(),
		ExcludeSelectors:             []string{},
		DenyClickPattern:             safety.DestructivePattern,
		DontClickSelectors:           []string{},
		DontClickChildrenOfSelectors: []string{},
		// On by default, matching the product runs (spidering.no_cdp: false):
		// library and test callers that build a Config directly detect elements
		// whose only clue is a JS click listener, too.
		UseCDPDetection: true,
		ClickOnce:       true,
		// CRITICAL FIX: (true instead of false)
		CrawlFrames:        true,
		ExcludeFrames:      []string{},
		CrawlHiddenAnchors: true,
		RandomizeElements:  false,

		MaxListenerProbeNodes: 2000, // browser.DefaultMaxListenerProbeNodes

		FormFillEnabled: true,
		FormFillMode:    FormFillNormal,
		FormInputs:      []FormInputConfig{},

		IdentityEmailDomain: DefaultIdentityEmailDomain,

		// GET- and POST-form submission on by default (tied to form filling by the
		// caller); bounded per crawl so a form-heavy page cannot flood the target.
		SubmitGetForms:        true,
		SubmitPostForms:       true,
		SubmitFormMaxVariants: defaultSubmitFormMaxVariants,
		FormHandlerGrace:      DefaultFormHandlerGrace,

		// Keep a handful of distinct query-value variants per endpoint shape so
		// category/filter/tab/search links are not all collapsed into one record.
		MaxParamValueVariants: defaultMaxParamValueVariants,

		CrawlConditions: []ConditionConfig{},
		WaitConditions:  []WaitConditionConfig{},

		DOMStripTags:  DefaultStripTags(),
		DOMStripAttrs: DefaultStripAttrs(),

		AvoidUnrelatedBacktracking: false,
		AvoidDifferentBacktracking: false,

		FragmentationMode: FragmentationLandmark, // Default to fast landmark-based
		VIPSPDoC:          11,                    // Fine granularity
		VIPSIterations:    10,

		// Crawl strategy default
		CrawlStrategy: CrawlStrategyNormal, // BFS state + FIFO action (default)

		// Service-worker asset priming on by default; bounded to keep a
		// precache-everything manifest from ballooning the crawl.
		ServiceWorkerPriming:   true,
		ServiceWorkerMaxAssets: defaultServiceWorkerMaxAssets,

		// Iframe-source priming on by default; bounded per crawl so a page that
		// mounts many frames cannot flood the target.
		IframePriming:      true,
		IframeMaxAssets:    defaultIframeMaxAssets,
		NetworkIdleTimeout: defaultNetworkIdleTimeout,

		// Anchor-link priming on by default; bounded per crawl so a link-dense page
		// cannot flood the target.
		AnchorLinkPriming:   true,
		AnchorLinkMaxAssets: defaultAnchorLinkMaxAssets,

		// SPA bootstrap settle + consent dismissal + login-CTA priming on by
		// default: together they get a heavy enterprise SPA to fully render its
		// landing, clear a consent overlay, and enter the OAuth/SAML login flow so
		// the deep login URLs are actually requested and captured.
		SPASettleTimeout:  defaultSPASettleTimeout,
		WaitDOMQuiescence: true,
		DOMQuiescenceMax:  defaultDOMQuiescenceMax,
		DismissConsent:    true,
		LoginCTAPriming:   true,
		AutoScroll:        true,

		// Seed the frontier from the host's own route declarations, and scrape
		// URL-like strings out of the rendered document. Both surface locations
		// an interaction crawl cannot reach by clicking.
		SeedFromRobots:      true,
		SeedFromSitemap:     true,
		SeedMaxURLs:         defaultSeedMaxURLs,
		SeedMaxCrawlURLs:    defaultSeedMaxCrawlURLs,
		SpeculativeLinks:    true,
		SpeculativeMaxLinks: defaultSpeculativeMaxLinks,

		// One extra sweep for states unlocked out of order, and a retry sweep for
		// actions that failed for transient reasons.
		FollowUpPasses:     1,
		RetryFailedActions: true,
		RetryMaxActions:    defaultRetryMaxActions,

		// Registering an account is a write, so it stays opt-in.
		SelfRegister: false,

		// Common-credential login attempts are off by default; the runner turns
		// them on at balanced (minimal list) and deep (full list). They only ever
		// run against a confirmed local login form, so leaving this off for an
		// ordinary crawl keeps active login attempts explicit.
		LoginCredentialAttempts: false,
		LoginCredentialFullList: false,

		// Matches the derived switches above (forms filled and submitted, no
		// account actions); see DefaultInteractionPolicy.
		Policy: DefaultInteractionPolicy(),
	}, nil
}

// defaultSubmitFormMaxVariants bounds how many distinct GET-form submit URLs the
// crawler synthesizes and fetches over the whole crawl. A handful of search/
// filter forms is the common case; the cap guards a page that wires up many
// forms without truncating real-world apps.
const defaultSubmitFormMaxVariants = 50

// DefaultFormHandlerGrace is the default FormHandlerGrace.
const DefaultFormHandlerGrace = 750 * time.Millisecond

// defaultMaxParamValueVariants is how many distinct query-value variants of one
// endpoint shape the capture keeps by default. Big enough to surface a typical
// category/filter/tab set (ginandjuice has 5 catalog categories) yet small
// enough that an id sweep (?productId=1..N) is still collapsed to a few
// representatives rather than N records.
const defaultMaxParamValueVariants = 6

// defaultDOMQuiescenceMax bounds the DOM-mutation-stability settle. Kept short:
// it only needs to absorb a client-render commit (React/Vue mounting the real
// DOM after its bundle loads), not a long data-fetch chain (SPASettleTimeout
// already covers that), and must return promptly on a perpetually animating page.
const defaultDOMQuiescenceMax = 2 * time.Second

// defaultSPASettleTimeout bounds the extra network-idle settle on the index page
// before capture. Long enough to absorb a multi-step SPA bootstrap (several
// sequential config/i18n/content round-trips) but capped so a long-poll/SSE app
// cannot stall the crawl — WaitNetworkIdle returns at this bound regardless.
const defaultSPASettleTimeout = 12 * time.Second

// defaultIframeMaxAssets bounds how many distinct same-origin iframe sources the
// priming step fetches over the whole crawl. Most apps embed a handful of
// same-origin frames; the cap guards against a pathological page wiring up
// hundreds without truncating real-world apps.
const defaultIframeMaxAssets = 200

// defaultAnchorLinkMaxAssets bounds how many distinct parameterized anchor links
// the priming step fetches over the whole crawl. Big enough for a shop's
// category/filter/pagination links plus a bounded slice of any id-indexed link
// set, capped so a link-dense catalog cannot flood the target.
const defaultAnchorLinkMaxAssets = 300

// defaultNetworkIdleTimeout caps the network-idle settle performed before iframe
// harvesting. Kept short so it only absorbs the tail of a framework's
// after-paint subframe loads rather than blocking on long-poll/XHR-heavy pages.
const defaultNetworkIdleTimeout = 3 * time.Second

// defaultSeedMaxURLs bounds how many robots/sitemap-declared locations are
// recorded. Large enough to absorb an ordinary site's whole sitemap, small
// enough that a catalogue exporting tens of thousands of product pages does not
// turn one crawl into a bulk download.
const defaultSeedMaxURLs = 1000

// defaultSeedMaxCrawlURLs bounds how many of those locations get a real browser
// visit. Two orders of magnitude below the record cap: the point is to reach a
// few structurally distinct sections the seed page never linked, not to render
// the sitemap.
const defaultSeedMaxCrawlURLs = 25

// defaultSpeculativeMaxLinks bounds how many URL-like strings scraped from
// comments and inline script are fetched over the whole crawl. Inline script is
// noisy — a bundle's string table can yield hundreds of path-shaped fragments —
// so the cap is what keeps a speculative source from outweighing observed links.
const defaultSpeculativeMaxLinks = 300

// defaultRetryMaxActions bounds the end-of-crawl retry sweep. Transient failures
// come in small numbers; a run failing more actions than this has a systemic
// problem (the app is down, the browser is wedged) that retrying will not fix.
const defaultRetryMaxActions = 50

// defaultServiceWorkerMaxAssets bounds how many service-worker-listed assets the
// priming step fetches. Angular ngsw.json manifests routinely list a few dozen
// chunks; the cap guards against a pathological manifest without truncating
// real-world apps.
const defaultServiceWorkerMaxAssets = 600

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if c.URL == nil {
		return fmt.Errorf("URL is required")
	}

	if c.URL.Scheme != "http" && c.URL.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https, got: %s", c.URL.Scheme)
	}

	if c.MaxDepth < 0 {
		return fmt.Errorf("MaxDepth must be >= 0, got: %d", c.MaxDepth)
	}

	if c.MaxStates < 0 {
		return fmt.Errorf("MaxStates must be >= 0, got: %d", c.MaxStates)
	}

	if c.MaxConsecutiveFails < 0 {
		return fmt.Errorf("MaxConsecutiveFails must be >= 0, got: %d", c.MaxConsecutiveFails)
	}

	if c.BrowserCount < 1 {
		return fmt.Errorf("BrowserCount must be >= 1, got: %d", c.BrowserCount)
	}

	if c.Tabs < 0 || c.Tabs > MaxTabs {
		return fmt.Errorf("Tabs must be 0-%d, got: %d", MaxTabs, c.Tabs) //nolint:staticcheck // ST1005: leads with the Config.Tabs field name, like its siblings
	}
	if err := ValidateTabIsolation(c.TabIsolation); err != nil {
		return err
	}

	if c.FormFillMode != FormFillNormal && c.FormFillMode != FormFillRandom {
		return fmt.Errorf("FormFillMode must be 'normal' or 'random', got: %s", c.FormFillMode)
	}

	// Validate fragmentation config
	if c.FragmentationMode != "" && c.FragmentationMode != FragmentationLandmark && c.FragmentationMode != FragmentationVIPS {
		return fmt.Errorf("FragmentationMode must be 'landmark' or 'vips', got: %s", c.FragmentationMode)
	}

	if c.VIPSPDoC != 0 && (c.VIPSPDoC < 1 || c.VIPSPDoC > 11) {
		return fmt.Errorf("VIPSPDoC must be 1-11, got: %d", c.VIPSPDoC)
	}

	if c.VIPSIterations != 0 && c.VIPSIterations < 1 {
		return fmt.Errorf("VIPSIterations must be >= 1, got: %d", c.VIPSIterations)
	}

	// Validate crawl strategy
	validStrategies := map[CrawlStrategy]bool{
		CrawlStrategyNormal: true, CrawlStrategyRandom: true,
		CrawlStrategyOldestFirst: true, CrawlStrategyShallowFirst: true,
		CrawlStrategyAdaptive: true,
	}
	if c.CrawlStrategy != "" && !validStrategies[c.CrawlStrategy] {
		return fmt.Errorf("CrawlStrategy must be normal/random/oldest_first/shallow_first/adaptive, got: %s", c.CrawlStrategy)
	}

	for i, wc := range c.WaitConditions {
		if err := wc.Validate(); err != nil {
			return fmt.Errorf("WaitConditions[%d]: %w", i, err)
		}
	}

	switch c.Policy.DialogResponse {
	case "", DialogRecordDismiss, DialogAcceptAll:
	default:
		return fmt.Errorf("Policy.DialogResponse must be %q or %q, got: %s", DialogRecordDismiss, DialogAcceptAll, c.Policy.DialogResponse)
	}

	// Validate browser engine
	validEngines := map[string]bool{"": true, "chromium": true, "ungoogled": true, "fingerprint": true}
	if !validEngines[c.BrowserEngine] {
		return fmt.Errorf("BrowserEngine must be 'chromium', 'ungoogled', or 'fingerprint', got: %s", c.BrowserEngine)
	}
	if err := ValidateStealth(c.Stealth); err != nil {
		return err
	}

	return nil
}

// MaxTabs caps Config.Tabs. Each tab costs roughly 80-150 MB of browser memory
// and shares one renderer budget, so past a handful they add contention, not
// coverage.
const MaxTabs = 16

// Tab isolation modes (Config.TabIsolation).
const (
	TabIsolationShared  = "shared"
	TabIsolationContext = "context"
)

// TabIsolationModes lists the accepted Config.TabIsolation values, default first.
var TabIsolationModes = []string{TabIsolationShared, TabIsolationContext}

// ValidateTabIsolation rejects a mode outside TabIsolationModes ("" is shared).
func ValidateTabIsolation(mode string) error {
	if mode != "" && !slices.Contains(TabIsolationModes, mode) {
		return fmt.Errorf("TabIsolation must be one of %s, got: %s", strings.Join(TabIsolationModes, ", "), mode)
	}
	return nil
}

// TabsCount returns the number of crawl tabs, at least 1.
func (c *Config) TabsCount() int {
	if c.Tabs < 1 {
		return 1
	}
	return c.Tabs
}

// Stealth modes (Config.Stealth). The default, auto, applies the stealth
// patches to the default chromium engine and leaves the ungoogled/fingerprint
// engines alone: those carry their own --fingerprint* identity, which the
// patches would contradict.
const (
	StealthAuto = "auto"
	StealthOn   = "on"
	StealthOff  = "off"
)

// StealthModes lists the accepted Config.Stealth values, default first.
var StealthModes = []string{StealthAuto, StealthOn, StealthOff}

// ValidateStealth rejects a stealth mode outside StealthModes ("" is auto).
func ValidateStealth(mode string) error {
	if mode != "" && !slices.Contains(StealthModes, mode) {
		return fmt.Errorf("Stealth must be one of %s, got: %s", strings.Join(StealthModes, ", "), mode) //nolint:staticcheck // ST1005: leads with the Config.Stealth field name, like its siblings
	}
	return nil
}

// StealthEnabled reports whether the browser should drop its automation
// markers (launcher flags, init script, User-Agent client hints). It reduces
// false negatives from trivial bot walls; it is not an evasion feature.
func (c *Config) StealthEnabled() bool {
	switch c.Stealth {
	case StealthOn:
		return true
	case StealthOff:
		return false
	default:
		return c.BrowserEngine != "ungoogled" && c.BrowserEngine != "fingerprint"
	}
}

// GetBasicAuthURL returns the URL with basic auth credentials embedded.
func (c *Config) GetBasicAuthURL() string {
	if c.BasicAuthUser == "" {
		return c.URL.String()
	}

	u := *c.URL
	u.User = url.UserPassword(c.BasicAuthUser, c.BasicAuthPass)
	return u.String()
}

// SetMaxDepth sets the maximum crawl depth. Use 0 for unlimited.
func (c *Config) SetMaxDepth(depth int) *Config {
	c.MaxDepth = depth
	return c
}

// SetMaxStates sets the maximum number of states to crawl. Use 0 for unlimited.
func (c *Config) SetMaxStates(states int) *Config {
	c.MaxStates = states
	return c
}

// SetMaxDuration sets the maximum duration. Use 0 for unlimited.
func (c *Config) SetMaxDuration(d time.Duration) *Config {
	c.MaxDuration = d
	return c
}

// SetMaxConsecutiveFails sets the maximum consecutive action failures before termination.
// Use 0 to disable (unlimited failures allowed).
func (c *Config) SetMaxConsecutiveFails(n int) *Config {
	c.MaxConsecutiveFails = n
	return c
}

// SetHeadless sets whether to run browser in headless mode.
func (c *Config) SetHeadless(headless bool) *Config {
	c.Headless = headless
	return c
}

// SetBasicAuth sets basic authentication credentials.
func (c *Config) SetBasicAuth(user, pass string) *Config {
	c.BasicAuthUser = user
	c.BasicAuthPass = pass
	return c
}

// SetProxy sets the proxy URL.
func (c *Config) SetProxy(proxyURL string) *Config {
	c.ProxyURL = proxyURL
	return c
}

// AddClickSelector adds a CSS selector for clickable elements.
func (c *Config) AddClickSelector(selector string) *Config {
	c.ClickSelectors = append(c.ClickSelectors, selector)
	return c
}

// AddExcludeSelector adds a CSS selector to exclude from clicking.
func (c *Config) AddExcludeSelector(selector string) *Config {
	c.ExcludeSelectors = append(c.ExcludeSelectors, selector)
	return c
}

// AddFormInput adds a form input configuration.
// how: "id", "name", "xpath"
// value: raw identification value (e.g., "input" NOT "#input")
func (c *Config) AddFormInput(how, value, inputType string, values ...string) *Config {
	c.FormInputs = append(c.FormInputs, FormInputConfig{
		How:    how,
		Value:  value,
		Type:   inputType,
		Values: values,
	})
	return c
}

// AddCrawlCondition adds a crawl condition.
func (c *Config) AddCrawlCondition(condType ConditionType, value string, negate bool) *Config {
	c.CrawlConditions = append(c.CrawlConditions, ConditionConfig{
		Type:   condType,
		Value:  value,
		Negate: negate,
	})
	return c
}

// AddWaitCondition adds a wait condition applied to pages whose URL contains
// urlSubstring (case-insensitive; empty = every page).
func (c *Config) AddWaitCondition(urlSubstring, selector string, visible bool, timeout time.Duration) *Config {
	c.WaitConditions = append(c.WaitConditions, WaitConditionConfig{
		URLMatch: urlSubstring,
		Selector: selector,
		Visible:  visible,
		Timeout:  timeout,
	})
	return c
}

// SetIncludeResponseBody sets whether to include response body in HTTP traffic capture.
func (c *Config) SetIncludeResponseBody(include bool) *Config {
	c.IncludeResponseBody = include
	return c
}

// SetIncludeResponseHeaders sets whether to include response headers in HTTP traffic capture.
func (c *Config) SetIncludeResponseHeaders(include bool) *Config {
	c.IncludeResponseHeaders = include
	return c
}

// EnableCDPDetection enables or disables CDP event listener detection.
func (c *Config) EnableCDPDetection(enabled bool) *Config {
	c.UseCDPDetection = enabled
	return c
}

// EnableFormFill enables or disables form filling.
func (c *Config) EnableFormFill(enabled bool) *Config {
	c.FormFillEnabled = enabled
	c.Policy.EditFields = enabled
	return c
}

// SetFormFillMode sets the form fill mode.
func (c *Config) SetFormFillMode(mode FormFillMode) *Config {
	c.FormFillMode = mode
	return c
}

// SetRandomizeElements enables or disables random element order.
func (c *Config) SetRandomizeElements(randomize bool) *Config {
	c.RandomizeElements = randomize
	return c
}

// SetAvoidUnrelatedBacktracking enables skipping backtracking through unrelated fragments.
func (c *Config) SetAvoidUnrelatedBacktracking(avoid bool) *Config {
	c.AvoidUnrelatedBacktracking = avoid
	return c
}

// SetAvoidDifferentBacktracking enables skipping backtracking through completely different states.
func (c *Config) SetAvoidDifferentBacktracking(avoid bool) *Config {
	c.AvoidDifferentBacktracking = avoid
	return c
}

// SetFragmentationMode sets the fragmentation mode (landmark or vips).
// Landmark is faster and uses semantic HTML elements.
// VIPS provides visual page segmentation.
func (c *Config) SetFragmentationMode(mode FragmentationMode) *Config {
	c.FragmentationMode = mode
	return c
}

// SetVIPSConfig sets VIPS algorithm parameters.
// pDoC: Permitted Degree of Coherence (1-11), higher = finer granularity.
// iterations: Number of segmentation iterations (more = finer detail).
func (c *Config) SetVIPSConfig(pDoC, iterations int) *Config {
	c.VIPSPDoC = pDoC
	c.VIPSIterations = iterations
	return c
}

// SetCrawlScope sets a custom URL scope filter.
// The filter function receives a URL string and returns true if the URL should be crawled.
// When nil (default), same-domain check is used.
func (c *Config) SetCrawlScope(scope CrawlScope) *Config {
	c.CrawlScope = scope
	return c
}

// SetCrawlStrategy sets the crawl strategy for both state and action selection.
func (c *Config) SetCrawlStrategy(strategy CrawlStrategy) *Config {
	c.CrawlStrategy = strategy
	return c
}

// SetSilent sets silent mode (no output at all including banner).
func (c *Config) SetSilent(silent bool) *Config {
	c.Silent = silent
	return c
}

// SetNoColor sets no-color mode (disable colored output).
func (c *Config) SetNoColor(noColor bool) *Config {
	c.NoColor = noColor
	return c
}

// SetBrowserEngine sets the browser engine to use.
// Valid values: "chromium" (default), "ungoogled" (Linux only).
func (c *Config) SetBrowserEngine(engine string) *Config {
	c.BrowserEngine = engine
	return c
}

// SetLoginCredentialAttempts enables or disables common-credential login
// attempts on confirmed local login forms (see the field doc). fullList selects
// the full documented list (deep) versus the minimal set (balanced).
func (c *Config) SetLoginCredentialAttempts(enabled, fullList bool) *Config {
	c.LoginCredentialAttempts = enabled
	c.Policy.LoginAttempts = enabled
	c.LoginCredentialFullList = fullList
	return c
}
