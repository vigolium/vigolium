package xss_light_scanner

import "github.com/vigolium/vigolium/pkg/types/severity"

// Main XSS Light Scanner
const (
	ModuleID    = "xss-light"
	ModuleName  = "XSS Light Scanner"
	ModuleShort = "Detects reflected XSS via character transformation analysis"
)

var (
	ModuleDesc = `## Description
Character-based Reflected XSS detection with transform analysis. Injects probe characters
and analyzes how they are reflected to determine exploitability.

## Notes
- Uses two-phase detection: character probing then transform analysis
- Tries multiple bypass prefixes sequentially
- Operates per-request with internal insertion point iteration

## References
- https://portswigger.net/burp/documentation/scanner/xss`

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
	URLParamsModuleDesc = `## Description
Character-based Reflected XSS detection for URL query parameters. Applies POST-to-GET
conversion when applicable and tests URL parameters for reflection-based XSS.

## Notes
- Focuses specifically on URL query string parameters
- Converts POST parameters to GET for broader coverage when applicable

## References
- https://portswigger.net/burp/documentation/scanner/xss`

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
	PathModuleDesc = `## Description
Character-based Reflected XSS detection in URL path segments. Tests path components
for reflection using recursive, cut, and append injection strategies.

## Notes
- Targets URL path segments rather than query parameters
- Uses multiple path manipulation strategies for thorough coverage

## References
- https://portswigger.net/burp/documentation/scanner/xss`

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
	ParamDiscoveryModuleDesc = `## Description
Discovers and tests hidden parameters that reflect in the response. Brute-forces common
parameter names and checks if values are echoed back, then tests for XSS.

## Notes
- Runs per-request to discover parameters not visible in the original request
- Combines parameter discovery with XSS Light transform analysis

## References
- https://portswigger.net/burp/documentation/scanner/xss`

	ParamDiscoveryModuleConfirmation = "Confirmed when a discovered hidden parameter reflects injected characters without proper encoding"
	ParamDiscoveryModuleSeverity     = severity.High
	ParamDiscoveryModuleConfidence   = severity.Firm
)
