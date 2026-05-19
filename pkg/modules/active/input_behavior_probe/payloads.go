package input_behavior_probe

// probeHeaderNames are HTTP headers to inject probe values into.
var probeHeaderNames = []string{
	"Referer", "X-Original-URL", "Profile", "X-Arbitrary",
	"X-HTTP-DestinationURL", "X-Forwarded-Proto", "Origin",
	"X-Forwarded-Host", "X-Forwarded-Server", "X-Host",
	"Proxy-Host", "Destination", "Proxy", "Via", "Host",
	"From", "True-Client-IP", "X-Real-IP", "X-Originating-IP",
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
var paramFuzzChars = []string{
	"%00", "\\0", "\\u000", "..;", "..", "%20", "%09", "%0A", "%0D", "%ff",
	"..%2f", "..;/", "../", "..%00/", "..%0d/", "..%5c", "..\\", "..%ff/",
	"%2e%2e%2f", ".%2e/", "%3f", "%26", "%23", "\u00b0",
}
