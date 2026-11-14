package config

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// SpideringConfig configures the browser-based spidering phase.
type SpideringConfig struct {
	MaxDepth            int    `yaml:"max_depth"`             // default: 6 (0 = unlimited)
	MaxStates           int    `yaml:"max_states"`            // default: 1500 (0 = unlimited)
	MaxDuration         string `yaml:"max_duration"`          // default: "30m"
	MaxConsecutiveFails int    `yaml:"max_consecutive_fails"` // default: 100
	Headless            bool   `yaml:"headless"`              // default: true
	BrowserCount        int    `yaml:"browser_count"`         // default: 1 (>1 is clamped; parallelism comes from tabs)
	Tabs                int    `yaml:"tabs"`                  // default: 1; tabs of the one browser crawling a shared state graph (max SpideringMaxTabs)
	TabIsolation        string `yaml:"tab_isolation"`         // default: "shared"; "context" gives each extra tab its own cookie jar
	Strategy            string `yaml:"strategy"`              // default: "adaptive"
	IncludeResponseBody bool   `yaml:"include_response_body"` // default: true
	BrowserEngine       string `yaml:"browser_engine"`        // "chromium" (default), "ungoogled", or "fingerprint"
	BrowserPath         string `yaml:"browser_path"`          // explicit path to browser binary (overrides auto-detection)
	NoCDP               bool   `yaml:"no_cdp"`                // disable CDP event listener detection
	NoForms             bool   `yaml:"no_forms"`              // disable automatic form filling
	// ExcludeSelectors are CSS selectors the crawl never clicks (an element
	// matching one, or inside one, is dropped from the candidates).
	ExcludeSelectors []string `yaml:"exclude_selectors,omitempty"`

	// MaxListenerProbeNodes caps, per crawl state, the listener-bearing nodes
	// the CDP listener pass turns into click candidates (each costs several CDP
	// round trips to build). 0 means the default (2000); -1 removes the cap.
	MaxListenerProbeNodes int `yaml:"max_listener_probe_nodes"`

	// Stealth drops the browser's automation markers (enable-automation,
	// navigator.webdriver, the HeadlessChrome client-hint brand, an empty plugin
	// list) so a trivial bot wall does not hand the crawl a challenge page. Not
	// an evasion feature. "auto" (default, also "") is on for the chromium
	// engine and off for ungoogled/fingerprint, which carry their own
	// fingerprint flags; "on" and "off" force it.
	Stealth string `yaml:"stealth,omitempty"`

	// SelfRegister lets the crawl complete a public signup form and continue as
	// the account it creates. On an app with open registration this is the
	// difference between crawling the marketing shell and crawling the product.
	// Off by default because registering is a write, and no intensity turns it
	// on. Legacy alias of interaction.register_account, which wins if both are
	// set.
	SelfRegister bool `yaml:"self_register"`

	// Interaction is the explicit browser interaction policy. Every key is
	// optional: an omitted key keeps its default (and survives a profile or
	// project overlay that does not name it), so only what an operator actually
	// wrote overrides the default, the legacy no_forms/self_register keys, or the
	// intensity default for login attempts.
	Interaction SpideringInteractionConfig `yaml:"interaction"`

	// BrowserCompat relaxes individual browser security boundaries. Every key
	// is optional; unset keys keep the defaults (sandbox on, TLS errors ignored
	// like the scanner's HTTP transport, mixed content blocked, same-origin
	// policy on). --browser-insecure sets all four.
	BrowserCompat SpideringBrowserCompatConfig `yaml:"browser_compat"`

	// MaxCaptureBodyBytes caps the encoded size of a dynamic (HTML/JS/JSON/API)
	// response body the browser capture keeps. 0 means the default (16 MiB,
	// above the API-spec ingest window); -1 removes the ceiling. A response over
	// it is still recorded, without its body.
	MaxCaptureBodyBytes int64 `yaml:"max_capture_body_bytes"`

	// IdentityEmailDomain is the domain of every email address the crawl
	// generates for signup/login/email fields. Empty means example.com
	// (RFC 2606 reserved, null MX — mail is never delivered). Never derived from
	// the target, whose own domain would make the address plausible real mail.
	IdentityEmailDomain string `yaml:"identity_email_domain"`

	// GraphOutputDir, when set, is a directory the crawl graph is written into
	// (one file per crawl, crawl-graph-<host>-<run>-<seq>.json, mode 0600). The
	// graph records which action on which state led where, so a run can be
	// reproduced and a specific state re-reached without rediscovering the path
	// to it. Empty disables.
	GraphOutputDir string `yaml:"graph_output_dir"`

	// RequireAuth fails a target's crawl instead of letting it run anonymously
	// when authentication was configured for it (session cookies or auth
	// headers) but could not be applied to the browser. Off by default: the
	// crawl continues and reports auth_state=failed. --require-auth sets it.
	RequireAuth bool `yaml:"require_auth"`

	// GraphIncludeValues keeps credential-bearing values in the crawl graph
	// (password/hidden field values, sensitive URL parameters, value/data-*
	// attributes). Off by default: the graph is redacted and records that it is.
	GraphIncludeValues bool `yaml:"graph_include_values"`

	// RouteSeeds feeds client-side routes from the target's JavaScript (the
	// jstangle route facts discovery stores) to the browser as crawl entry
	// points: the initial crawl takes routes earlier runs of the project
	// stored, and the targeted re-spider takes the ones this scan's discovery
	// found. nil = default (true).
	RouteSeeds *bool `yaml:"route_seeds,omitempty"`

	// MaxExtraSeeds caps the route seeds one target's crawl browses, after
	// scope filtering and dedup. 0 = default (50).
	MaxExtraSeeds int `yaml:"max_extra_seeds"`
}

// DefaultMaxExtraSeeds is spidering.max_extra_seeds when unset.
const DefaultMaxExtraSeeds = 50

// RouteSeedsEnabled reports whether client routes seed the browser crawl
// (default on).
func (c *SpideringConfig) RouteSeedsEnabled() bool {
	return c.RouteSeeds == nil || *c.RouteSeeds
}

// ExtraSeedsCap returns max_extra_seeds with the default applied.
func (c *SpideringConfig) ExtraSeedsCap() int {
	if c.MaxExtraSeeds <= 0 {
		return DefaultMaxExtraSeeds
	}
	return c.MaxExtraSeeds
}

// SpideringInteractionConfig is what the browser crawl is permitted to change.
// Pointer-valued so "unset" is distinguishable from "false": unset falls back to
// the default (or a legacy key), an explicit value always wins. The keys match
// spitolas.PolicyCategories.
type SpideringInteractionConfig struct {
	EditFields      *bool  `yaml:"edit_fields,omitempty"`      // type into / toggle / select controls (default: true)
	SubmitForms     *bool  `yaml:"submit_forms,omitempty"`     // dispatch a submit through any mechanism (default: true)
	UploadFiles     *bool  `yaml:"upload_files,omitempty"`     // attach generated fixtures to file inputs (default: true)
	DownloadFiles   *bool  `yaml:"download_files,omitempty"`   // let the browser save downloads (default: false)
	RegisterAccount *bool  `yaml:"register_account,omitempty"` // complete a signup form (default: false at every intensity)
	LoginAttempts   *bool  `yaml:"login_attempts,omitempty"`   // try default credentials on a confirmed login form (default: by intensity)
	Dialogs         string `yaml:"dialogs,omitempty"`          // "" or "record-dismiss" (default), "accept-all"
	// DenyClickPattern is a case-insensitive regex; a click candidate whose
	// text, href, aria-label, title or value matches it is never clicked.
	// Unset = the built-in destructive pattern (log out, sign out,
	// delete, remove, deactivate, unsubscribe, close/cancel account); "" turns
	// the guard off. Not a permission category, so it is not in the policy
	// report.
	DenyClickPattern *string `yaml:"deny_click_pattern,omitempty"`
}

// SpideringBrowserCompatConfig is the browser security-exception section.
// Pointer-valued for the same reason as SpideringInteractionConfig: an omitted
// key must keep its default under the key-preserving overlay.
type SpideringBrowserCompatConfig struct {
	NoSandbox            *bool `yaml:"no_sandbox,omitempty"`             // default: false (forced on only where the host cannot sandbox)
	IgnoreTLSErrors      *bool `yaml:"ignore_tls_errors,omitempty"`      // default: true (matches the scanner's HTTP transport)
	AllowInsecureContent *bool `yaml:"allow_insecure_content,omitempty"` // default: false
	DisableWebSecurity   *bool `yaml:"disable_web_security,omitempty"`   // default: false
}

// SetAll sets every exception to v — the --browser-insecure switch.
func (c *SpideringBrowserCompatConfig) SetAll(v bool) {
	c.NoSandbox, c.IgnoreTLSErrors, c.AllowInsecureContent, c.DisableWebSecurity = &v, &v, &v, &v
}

// SpideringDialogPolicies lists the accepted spidering.interaction.dialogs
// values, default first. Mirrors spitolas.DialogPolicies (a runner test pins
// the two together; config cannot import the browser package).
var SpideringDialogPolicies = []string{"record-dismiss", "accept-all"}

// SpideringStealthModes lists the accepted spidering.stealth values, default
// first. Mirrors spitolas.StealthModes (pinned by a spitolas test; config
// cannot import the browser package).
var SpideringStealthModes = []string{"auto", "on", "off"}

// SpideringTabIsolationModes lists the accepted spidering.tab_isolation
// values, default first. Mirrors spitolas.TabIsolationModes (pinned by a
// spitolas test; config cannot import the browser package).
var SpideringTabIsolationModes = []string{"shared", "context"}

// SpideringMaxTabs caps spidering.tabs. Mirrors spitolas.MaxTabs.
const SpideringMaxTabs = 16

// DefaultSpideringConfig returns sensible defaults for spidering.
func DefaultSpideringConfig() *SpideringConfig {
	return &SpideringConfig{
		// Bound how the crawl spends its clock. Unbounded, a link-dense site can
		// sink the whole max_duration into one deep branch and never revisit the
		// breadth near the seed; and a template that mints a state per row (a
		// paginated table, a calendar) can spend it on near-identical pages. Both
		// are generous enough that a normal application finishes well inside them.
		MaxDepth:            6,
		MaxStates:           1500,
		MaxDuration:         "30m",
		MaxConsecutiveFails: 100,
		Headless:            true,
		BrowserCount:        1,
		// One tab at every intensity until a multi-tab soak has passed.
		Tabs:                1,
		TabIsolation:        "shared",
		Strategy:            "adaptive",
		IncludeResponseBody: true,
		BrowserEngine:       "chromium",
		Stealth:             "auto",
		NoCDP:               false,
		NoForms:             false,

		MaxListenerProbeNodes: 2000,
	}
}

// MaxDurationParsed parses the max_duration string into time.Duration, falling
// back to the 30 m default when the setting is unset, unparseable, or <= 0.
//
// The zero case is not cosmetic. The phase ceiling reads 0 as "unlimited", but
// each target still runs under context.WithTimeout(phaseCtx, maxDuration) — so a
// configured `max_duration: 0s` started every crawl with an already-expired
// deadline and silently disabled spidering. There is no way to express "crawl
// forever" here, and the default is the only sane reading of an unusable value.
func (c *SpideringConfig) MaxDurationParsed() time.Duration {
	d, err := time.ParseDuration(c.MaxDuration)
	if c.MaxDuration == "" || err != nil || d <= 0 {
		return 30 * time.Minute
	}
	return d
}

// Validate checks spidering configuration for errors.
func (c *SpideringConfig) Validate() error {
	if c.MaxDepth < 0 {
		return fmt.Errorf("spidering.max_depth must be >= 0")
	}
	if c.MaxStates < 0 {
		return fmt.Errorf("spidering.max_states must be >= 0")
	}
	if c.MaxListenerProbeNodes < -1 {
		return fmt.Errorf("spidering.max_listener_probe_nodes must be >= -1 (-1 = no cap)")
	}
	if c.MaxConsecutiveFails < 0 {
		return fmt.Errorf("spidering.max_consecutive_fails must be >= 0")
	}
	if c.BrowserCount < 0 {
		return fmt.Errorf("spidering.browser_count must be >= 0")
	}
	if c.Tabs < 0 || c.Tabs > SpideringMaxTabs {
		return fmt.Errorf("spidering.tabs must be 0-%d (0 = 1), got: %d", SpideringMaxTabs, c.Tabs)
	}
	if c.TabIsolation != "" && !slices.Contains(SpideringTabIsolationModes, c.TabIsolation) {
		return fmt.Errorf("spidering.tab_isolation must be one of %s, got: %s", strings.Join(SpideringTabIsolationModes, ", "), c.TabIsolation)
	}
	if err := validateNonNegDuration("spidering.max_duration", c.MaxDuration); err != nil {
		return err
	}
	validStrategies := map[string]bool{
		"normal": true, "random": true, "oldest_first": true, "shallow_first": true, "adaptive": true,
	}
	if c.Strategy != "" && !validStrategies[c.Strategy] {
		return fmt.Errorf("spidering.strategy must be normal/random/oldest_first/shallow_first/adaptive, got: %s", c.Strategy)
	}
	validEngines := map[string]bool{
		"": true, "chromium": true, "ungoogled": true, "fingerprint": true,
	}
	if !validEngines[c.BrowserEngine] {
		return fmt.Errorf("spidering.browser_engine must be 'chromium', 'ungoogled', or 'fingerprint', got: %s", c.BrowserEngine)
	}
	if c.Stealth != "" && !slices.Contains(SpideringStealthModes, c.Stealth) {
		return fmt.Errorf("spidering.stealth must be one of %s, got: %s", strings.Join(SpideringStealthModes, ", "), c.Stealth)
	}
	if c.MaxExtraSeeds < 0 {
		return fmt.Errorf("spidering.max_extra_seeds must be >= 0 (0 = default %d), got: %d", DefaultMaxExtraSeeds, c.MaxExtraSeeds)
	}
	if c.MaxCaptureBodyBytes < -1 {
		return fmt.Errorf("spidering.max_capture_body_bytes must be 0 (default), -1 (no ceiling) or a positive byte count, got: %d", c.MaxCaptureBodyBytes)
	}
	if d := c.IdentityEmailDomain; d != "" && (strings.ContainsAny(d, "@/: \t") || !strings.Contains(d, ".")) {
		return fmt.Errorf("spidering.identity_email_domain must be a bare domain such as example.com, got: %q", d)
	}
	if d := c.Interaction.Dialogs; d != "" && !slices.Contains(SpideringDialogPolicies, d) {
		return fmt.Errorf("spidering.interaction.dialogs must be one of %s, got: %s", strings.Join(SpideringDialogPolicies, ", "), d)
	}
	return nil
}
