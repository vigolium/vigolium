package config

import (
	"fmt"
	"net/http"
	"net/url"
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

// WaitConditionConfig defines a wait condition for specific URLs.
type WaitConditionConfig struct {
	URLPattern string        // Apply to URLs matching this pattern
	Selector   string        // Wait for this element
	Visible    bool          // Wait for visibility (not just existence)
	Timeout    time.Duration // Max wait time
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
	MaxConsecutiveFails int           // 0 = disabled (unlimited)

	// Browser
	Headless      bool
	BrowserCount  int
	BrowserEngine string // "chromium" (default), "ungoogled", or "fingerprint"
	BrowserPath   string // explicit path to browser binary (overrides auto-detection)

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

	// Wait times
	WaitAfterReload time.Duration
	WaitAfterEvent  time.Duration
	PageLoadTimeout time.Duration
	DOMStableTime   time.Duration
	ElementTimeout  time.Duration // Default timeout for finding elements (prevents infinite wait)

	// Clickable Detection
	ClickSelectors               []string // CSS selectors for clickables
	ExcludeSelectors             []string // CSS selectors to exclude
	DontClickSelectors           []string
	DontClickChildrenOfSelectors []string
	UseCDPDetection              bool     // Enable CDP event listener detection
	ClickOnce                    bool     // Click each element only once
	CrawlFrames                  bool     // Crawl iframes
	ExcludeFrames                []string // Frame names/patterns to exclude from crawling
	CrawlHiddenAnchors           bool     // Crawl hidden anchor elements
	RandomizeElements            bool     // Randomize order of extracted elements

	// Form Handling
	FormFillEnabled bool
	FormFillMode    FormFillMode
	FormInputs      []FormInputConfig

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

	// SPASettleTimeout bounds an extra "wait for the network to go idle" settle on
	// the index/seed page before its state is captured and its clickables are
	// extracted. A heavy enterprise SPA (Angular, Salesforce Lightning, …) renders
	// its real UI — including the login CTA — only after a chain of sequential
	// bootstrap XHRs (config → region → i18n → feature flags → content) lands; the
	// short DOMStableTime wait fires while it is still a half-rendered shell, so the
	// CTA and most data calls are missed. This longer settle lets the bootstrap
	// quiesce first (0 = disabled).
	SPASettleTimeout time.Duration

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

	CrawlScope CrawlScope // Custom URL scope filter (nil = default same-domain check)

	// Crawl strategy - determines both state selection and action selection
	CrawlStrategy CrawlStrategy // Crawl strategy (default: normal)

	// Silent mode - suppress all output including banner
	Silent bool

	// Verbose mode - show all traffic including static files and cross-origin
	Verbose bool

	// NoColor mode - disable colored output
	NoColor bool
}

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
		DontClickSelectors:           []string{},
		DontClickChildrenOfSelectors: []string{},
		// WebDriverBackedEmbeddedBrowser.USE_CDP defaults to false
		// Must be explicitly enabled via BrowserOptions.setUSE_CDP(true) or
		// crawlRules().clickElementsWithClickEventHandler()
		UseCDPDetection: false,
		ClickOnce:       true,
		// CRITICAL FIX: (true instead of false)
		CrawlFrames:        true,
		ExcludeFrames:      []string{},
		CrawlHiddenAnchors: true,
		RandomizeElements:  false,

		FormFillEnabled: true,
		FormFillMode:    FormFillNormal,
		FormInputs:      []FormInputConfig{},

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

		// SPA bootstrap settle + consent dismissal + login-CTA priming on by
		// default: together they get a heavy enterprise SPA to fully render its
		// landing, clear a consent overlay, and enter the OAuth/SAML login flow so
		// the deep login URLs are actually requested and captured.
		SPASettleTimeout: defaultSPASettleTimeout,
		DismissConsent:   true,
		LoginCTAPriming:  true,
		AutoScroll:       true,
	}, nil
}

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

// defaultNetworkIdleTimeout caps the network-idle settle performed before iframe
// harvesting. Kept short so it only absorbs the tail of a framework's
// after-paint subframe loads rather than blocking on long-poll/XHR-heavy pages.
const defaultNetworkIdleTimeout = 3 * time.Second

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

	// Validate browser engine
	validEngines := map[string]bool{"": true, "chromium": true, "ungoogled": true, "fingerprint": true}
	if !validEngines[c.BrowserEngine] {
		return fmt.Errorf("BrowserEngine must be 'chromium', 'ungoogled', or 'fingerprint', got: %s", c.BrowserEngine)
	}

	return nil
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

// AddWaitCondition adds a wait condition.
func (c *Config) AddWaitCondition(urlPattern, selector string, visible bool, timeout time.Duration) *Config {
	c.WaitConditions = append(c.WaitConditions, WaitConditionConfig{
		URLPattern: urlPattern,
		Selector:   selector,
		Visible:    visible,
		Timeout:    timeout,
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
