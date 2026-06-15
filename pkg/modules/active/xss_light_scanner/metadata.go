package xss_light_scanner

import "github.com/vigolium/vigolium/pkg/types/severity"

// Main XSS Light Scanner
const (
	ModuleID    = "xss-light"
	ModuleName  = "XSS Light Scanner"
	ModuleShort = "Detects reflected XSS via character transformation analysis"
)

var (
	ModuleDesc = `**What it means:** A request parameter is reflected into the HTML response without context-aware encoding, allowing reflected cross-site scripting (XSS). An attacker can inject HTML or JavaScript that the victim's browser runs as trusted.

**How it's exploited:** A victim who clicks a link carrying a malicious value runs the reflected payload in their session, enabling cookie theft or account takeover. The module probes body, query, and JSON insertion points, checking how quotes, brackets, and escapes survive to confirm an executable context.

**Fix:** Apply context-correct output encoding when reflecting user input (HTML, attribute, JavaScript, or URL) and enforce a restrictive Content-Security-Policy.`

	ModuleConfirmation = "Confirmed when injected probe characters are reflected without sanitization, indicating exploitable XSS context"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "xss", "light"}
)

// XSS Light - URL Parameters
const (
	URLParamsModuleID    = "xss-light-url-params"
	URLParamsModuleName  = "XSS Light - URL Parameters"
	URLParamsModuleShort = "Detects XSS in URL parameters (POST→GET conversion when applicable)"
)

var (
	URLParamsModuleDesc = `**What it means:** A URL query-string parameter is reflected into the response without context-aware encoding, allowing reflected XSS. Because the payload lives entirely in the URL, the page can be weaponized as a single shareable link.

**How it's exploited:** A victim who opens an attacker's URL runs the reflected script payload in their browser, enabling session hijacking or token theft. The module tests query parameters and, for non-GET requests, converts POST parameters to GET to catch handlers that reflect either way.

**Fix:** Apply context-correct output encoding when reflecting query parameters into the response and enforce a restrictive Content-Security-Policy.`

	URLParamsModuleConfirmation = "Confirmed when URL query parameter values are reflected in the response with exploitable character handling"
	URLParamsModuleSeverity     = severity.High
	URLParamsModuleConfidence   = severity.Firm
)

// XSS Light - Path Injection
const (
	PathModuleID    = "xss-light-path"
	PathModuleName  = "XSS Light - Path Injection"
	PathModuleShort = "Detects XSS via path manipulation (recursive, cut, append)"
)

var (
	PathModuleDesc = `**What it means:** A URL path segment is reflected into the HTML response without context-aware encoding, allowing reflected XSS. The input is part of the path rather than a query parameter, so it often slips past parameter-only filtering.

**How it's exploited:** A victim who opens an attacker's URL runs the reflected script in their session, enabling token theft or account takeover. The module manipulates path segments (recursive, cut, append) and checks how breakout characters survive to confirm an executable context.

**Fix:** Apply context-correct output encoding to any path component echoed into responses and enforce a restrictive Content-Security-Policy.`

	PathModuleConfirmation = "Confirmed when injected path segment characters are reflected in the response without sanitization"
	PathModuleSeverity     = severity.High
	PathModuleConfidence   = severity.Firm
)

// XSS Light - Parameter Discovery
const (
	ParamDiscoveryModuleID    = "xss-light-param-discovery"
	ParamDiscoveryModuleName  = "XSS Light - Parameter Discovery"
	ParamDiscoveryModuleShort = "Detects XSS via echo parameter discovery"
)

var (
	ParamDiscoveryModuleDesc = `**What it means:** A hidden, undocumented request parameter - absent from the original request - is reflected into the response, creating reflected XSS. They are invisible in normal traffic, yet an attacker can supply them directly.

**How it's exploited:** A victim who opens an attacker's link runs the reflected payload, enabling token theft or takeover. The module brute-forces parameter names, keeps those that echo back, and re-confirms each - Low when the breakout survives unescaped, High when a headless browser fires an alert().

**Fix:** Apply context-correct output encoding to all reflected input, including unexpected parameters, and enforce a restrictive Content-Security-Policy.`

	// Per-finding severity/confidence are set by the confirmation step
	// (buildConfirmedResultEvent); these module defaults are the fallback only.
	ParamDiscoveryModuleConfirmation = "Confirmed when a discovered parameter's executable XSS payload breaks out unescaped (Low) and fires a JavaScript dialog in a headless browser (High)"
	ParamDiscoveryModuleSeverity     = severity.High
	ParamDiscoveryModuleConfidence   = severity.Firm
)

// XSS Light - Pre-encoded Injection
const (
	EncodedModuleID    = "xss-light-encoded"
	EncodedModuleName  = "XSS Light - Pre-encoded Injection"
	EncodedModuleShort = "Detects XSS where the app decodes a parameter (base64 / double-URL) before reflecting"
)

var (
	EncodedModuleDesc = `**What it means:** A parameter the app decodes (base64 or double-URL) before reflecting it is vulnerable to reflected XSS. Filters checking the raw value miss the dangerous characters, which appear only after decoding.

**How it's exploited:** An encoded payload passes the filter as harmless text, then is decoded and reflected as live script that runs in the victim's browser, enabling token theft or takeover. The module wraps its canary in the same encoding and reports only when the decoded probe executes.

**Fix:** Validate and encode input after every decoding step, not just the raw value, and enforce a restrictive Content-Security-Policy.`

	EncodedModuleConfirmation = "Confirmed when an encoded parameter value is decoded by the application and reflected in an exploitable context"
	EncodedModuleSeverity     = severity.High
	EncodedModuleConfidence   = severity.Firm
)
