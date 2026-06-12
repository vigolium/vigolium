package xss_light_scanner

import "github.com/vigolium/vigolium/pkg/types/severity"

// Main XSS Light Scanner
const (
	ModuleID    = "xss-light"
	ModuleName  = "XSS Light Scanner"
	ModuleShort = "Detects reflected XSS via character transformation analysis"
)

var (
	ModuleDesc = `**What it means:** A request parameter is reflected into the HTML response without proper context-aware encoding, allowing reflected cross-site scripting (XSS). An attacker can inject HTML or JavaScript that the victim's browser executes as if it came from the trusted site.

**How it's exploited:** The attacker crafts a link with a malicious value in the vulnerable parameter and lures a victim into clicking it. When the page reflects the payload, attacker-controlled script runs in the victim's session, enabling session/cookie theft, credential harvesting, account takeover, or actions performed as the victim. This module injects probe characters across body, query, and JSON insertion points and analyzes how quotes, brackets, and escape sequences survive to confirm the reflection lands in an executable context.

**Fix:** Apply context-correct output encoding when reflecting user input (HTML-entity, attribute, JavaScript, or URL encoding for the matching context) and enforce a restrictive Content-Security-Policy.`

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
	URLParamsModuleDesc = `**What it means:** A URL query-string parameter is reflected into the response without proper context-aware encoding, allowing reflected cross-site scripting (XSS). Because the payload lives entirely in the URL, the vulnerable page can be weaponized as a single shareable link.

**How it's exploited:** The attacker embeds a script payload in a query parameter and delivers the URL via email, message, or ad. When the victim opens it, the reflected payload executes in their browser, enabling session hijacking, cookie or token theft, credential phishing, or actions taken as the victim. This module tests existing query parameters and, for non-GET requests, also converts POST parameters to GET to expose handlers that reflect either way.

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
	PathModuleDesc = `**What it means:** A URL path segment is reflected into the HTML response without proper context-aware encoding, allowing reflected cross-site scripting (XSS). The vulnerable input is part of the path itself rather than a query parameter, which often slips past parameter-only input filtering.

**How it's exploited:** The attacker builds a URL whose path segment carries a script payload and lures a victim into opening it. When the application echoes that path component into the page, attacker-controlled JavaScript runs in the victim's session, enabling cookie or token theft, account takeover, or actions performed as the victim. This module manipulates path segments using recursive, cut, and append strategies and analyzes how breakout characters survive to confirm the reflection reaches an executable context.

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
	ParamDiscoveryModuleDesc = `**What it means:** A hidden, undocumented request parameter that is not present in the original request is reflected into the response, creating reflected cross-site scripting (XSS). Such parameters are easy to overlook because they are invisible in normal traffic, yet an attacker can supply them directly.

**How it's exploited:** The attacker adds the discovered parameter with a script payload to a crafted link and lures a victim into opening it; the reflected payload then executes in the victim's browser, enabling cookie or token theft, account takeover, or actions performed as the victim. This module brute-forces common parameter names, keeps those whose values echo back, and re-confirms each candidate with a real context-shaped payload. Findings are dropped unless the breakout survives unescaped, reported Low/Tentative when it survives but no dialog fires (likely CSP or a non-executing context), and raised to High/Certain only when a headless browser actually triggers an alert() dialog.

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
	EncodedModuleDesc = `**What it means:** A parameter that the application decodes (base64 or an extra URL-decode pass) before reflecting it is vulnerable to reflected cross-site scripting (XSS). Input filters that inspect the raw, still-encoded value are bypassed because the dangerous characters only appear after the application decodes the payload.

**How it's exploited:** The attacker submits an encoded payload that passes the filter as harmless text; the application decodes it and reflects the live script into the page, so when a victim opens the crafted link the payload executes in their browser, enabling cookie or token theft, account takeover, or actions performed as the victim. This module wraps the same survival-probe canary in base64 or extra URL encoding and only reports when the decoded probe lands in an executable context, so the encoding layer cannot produce false positives.

**Fix:** Validate and context-correctly encode input after every decoding step, not just the raw received value, and enforce a restrictive Content-Security-Policy.`

	EncodedModuleConfirmation = "Confirmed when an encoded parameter value is decoded by the application and reflected in an exploitable context"
	EncodedModuleSeverity     = severity.High
	EncodedModuleConfidence   = severity.Firm
)
