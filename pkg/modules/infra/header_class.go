package infra

import "strings"

// HeaderClass sorts request headers by what injecting into them can reach
// (ECON-1). Header insertion points are the largest single source of active
// requests on browser-captured traffic; the class decides which vulnerability
// classes test a header at all and whether once per host is enough.
type HeaderClass int

const (
	// HeaderClassApp: any header the application may read as data (custom
	// X-* headers, API keys, tenant ids). Tested per path like a parameter.
	HeaderClassApp HeaderClass = iota
	// HeaderClassNoise: browser/protocol plumbing no application reads as data
	// (sec-fetch-*, sec-ch-*, priority, cache validators, range…). Never tested.
	HeaderClassNoise
	// HeaderClassNegotiation: content negotiation (Accept, Accept-Language),
	// sometimes used to pick a template or locale file.
	HeaderClassNegotiation
	// HeaderClassLogged: headers commonly written to logs or analytics tables
	// (User-Agent, Referer, X-Forwarded-For, …) — second-order SQLi/cmdi sinks.
	HeaderClassLogged
	// HeaderClassRouting: headers proxies and frameworks route on
	// (X-Forwarded-Host, X-Original-URL, Forwarded, Origin, …) — SSRF and
	// routing-confusion sinks.
	HeaderClassRouting
)

func (c HeaderClass) String() string {
	switch c {
	case HeaderClassNoise:
		return "noise"
	case HeaderClassNegotiation:
		return "negotiation"
	case HeaderClassLogged:
		return "logged"
	case HeaderClassRouting:
		return "routing"
	default:
		return "app"
	}
}

var headerClassByName = map[string]HeaderClass{
	"priority":                  HeaderClassNoise,
	"upgrade-insecure-requests": HeaderClassNoise,
	"dnt":                       HeaderClassNoise,
	"cache-control":             HeaderClassNoise,
	"pragma":                    HeaderClassNoise,
	"range":                     HeaderClassNoise,
	"max-forwards":              HeaderClassNoise,
	"accept-charset":            HeaderClassNoise,

	"accept":          HeaderClassNegotiation,
	"accept-language": HeaderClassNegotiation,

	"user-agent":      HeaderClassLogged,
	"referer":         HeaderClassLogged,
	"x-forwarded-for": HeaderClassLogged,
	"x-real-ip":       HeaderClassLogged,
	"true-client-ip":  HeaderClassLogged,
	"x-client-ip":     HeaderClassLogged,
	"from":            HeaderClassLogged,
	"via":             HeaderClassLogged,

	"x-forwarded-host":   HeaderClassRouting,
	"x-original-url":     HeaderClassRouting,
	"x-rewrite-url":      HeaderClassRouting,
	"forwarded":          HeaderClassRouting,
	"x-forwarded-proto":  HeaderClassRouting,
	"x-forwarded-prefix": HeaderClassRouting,
	"origin":             HeaderClassRouting,
}

// ClassifyHeader returns name's HeaderClass (case-insensitive). sec-fetch-*,
// sec-ch-* and If-* conditional headers are noise; unknown names are App.
func ClassifyHeader(name string) HeaderClass {
	n := strings.ToLower(strings.TrimSpace(name))
	if c, ok := headerClassByName[n]; ok {
		return c
	}
	switch {
	case strings.HasPrefix(n, "sec-fetch-"), strings.HasPrefix(n, "sec-ch-"), strings.HasPrefix(n, "if-"):
		return HeaderClassNoise
	}
	return HeaderClassApp
}
