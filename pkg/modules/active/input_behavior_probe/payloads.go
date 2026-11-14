package input_behavior_probe

// probeHeaderNames are HTTP headers to inject probe values into. Kept to routing /
// forwarding / SSRF-adjacent headers whose values a server may actually act on
// (fetch, route, trust as client IP). Standard navigation/identity headers —
// Referer, Origin, Via, From — were removed: fuzzing them with values like
// localhost / null / %0d%0a perturbs the app's CSRF/CORS/redirect logic, producing a
// deterministic body/status differential that confirmChange still reports as a
// "behavior change" even though nothing was injected into a sink (the ssrf_detection
// Referer false-positive class). Origin-driven CORS is covered by cors_misconfiguration.
var probeHeaderNames = []string{
	"X-Original-URL", "Profile", "X-Arbitrary",
	"X-HTTP-DestinationURL", "X-Forwarded-Proto",
	"X-Forwarded-Host", "X-Forwarded-Server", "X-Host",
	"Proxy-Host", "Destination", "Proxy", "Host",
	"True-Client-IP", "X-Real-IP", "X-Originating-IP",
	"CF-Connecting_IP", "Forwarded",
}

// probeHeaderValues are values injected into each probe header.
var probeHeaderValues = []string{
	"localhost", "127.0.0.1", "true", "null", "%00", "%0d%0a", "%ff",
}

// weirdHeaderNames are unusual header names that may trigger parser errors.
var weirdHeaderNames = []string{"%00", "%ff"}

// pathManipulations are applied as prefix and postfix to each path segment.
var pathManipulations = []string{
	"..%3B", "%2e%2e", "%252e", "%252e%252e",
	"..;/", "..%3B/", "%0A../", "%0D../", "%00../", "../",
	"/////////////////////////////",
	"'", "\"", "`", "-", "%00", "\\0", "\\u000",
	"..;", "..", "%20", "%09", "%0A", "%0D", "%ff",
	"..%2f", "..;/", "../", "..%00/", "..%0d/", "..%5c",
	"..\\", "..%ff/", "%2e%2e%2f", ".%2e/",
	"%3f", "%26", "%23", "\u00b0", "/////////",
}

// debugParamNames are parameter names associated with debug/admin modes.
var debugParamNames = []string{"debug", "_debug", "admin", "internal", "is_admin", "_layout"}

// debugParamValues are values to inject for each debug parameter.
var debugParamValues = []string{"true", "null", "1"}

// paramFuzzChars are characters appended to param values for behavior detection.
// The whole table is pre-encoded: each entry is sent exactly as written
// (built through httpmsg.BuildPreEncoded), so "%00" is a NUL, not "%2500".
var paramFuzzChars = []string{
	"%00", "\\0", "\\u000", "..;", "..", "%20", "%09", "%0A", "%0D", "%ff",
	"..%2f", "..;/", "../", "..%00/", "..%0d/", "..%5c", "..\\", "..%ff/",
	"%2e%2e%2f", ".%2e/", "%3f", "%26", "%23", "\u00b0",
}
