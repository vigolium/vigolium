package runner

import (
	"net/http"
	"strings"
)

// browserAuthFromHeaders splits the runner's merged request-header set (operator
// -H headers plus, when use_in_discovery is enabled, primary-session auth
// headers) into the two forms the browser crawler consumes:
//
//   - cookies:  parsed from any Cookie header, seeded into the browser cookie jar
//     so the browser resends them domain-scoped like a real session.
//   - extra:    every other header (Authorization, X-Api-Key, custom -H headers),
//     applied to each browser request via CDP.
//
// Connection-scoped / hop-by-hop headers are dropped — forcing them onto the
// browser via CDP extra headers would corrupt requests (e.g. a stale
// Content-Length) or is simply meaningless for the browser (Host is set by
// navigation). This is why the same session that authenticates the HTTP scan
// phases now also authenticates the spider.
func browserAuthFromHeaders(headers []string) (cookies []*http.Cookie, extra map[string]string) {
	for _, h := range headers {
		idx := strings.IndexByte(h, ':')
		if idx <= 0 {
			continue
		}
		name := strings.TrimSpace(h[:idx])
		value := strings.TrimSpace(h[idx+1:])
		if name == "" || value == "" {
			continue
		}
		switch strings.ToLower(name) {
		case "cookie":
			// Reuse net/http's cookie parser to split "a=b; c=d" reliably.
			req := http.Request{Header: http.Header{"Cookie": []string{value}}}
			cookies = append(cookies, req.Cookies()...)
		case "host", "content-length", "connection", "transfer-encoding",
			"proxy-connection", "keep-alive", "upgrade", "te", "trailer":
			// hop-by-hop / connection-scoped — never bridge to the browser.
		default:
			if extra == nil {
				extra = make(map[string]string)
			}
			extra[name] = value
		}
	}
	return cookies, extra
}
