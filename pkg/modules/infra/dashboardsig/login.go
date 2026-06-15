package dashboardsig

import "strings"

// LoginProbe describes a vendor-default-credential check for a product. It is run
// by active/dashboard_exposure ONLY after the product has already been actively
// confirmed present, and ONLY the small set of documented default credential
// pairs is tried (never a brute-force wordlist), so it cannot trigger account
// lockout. The active prober additionally runs a negative control — a random
// credential pair must be rejected by Success — before trusting any hit, so a
// login form that "succeeds" on anything cannot produce a false positive. A
// confirmed working pair is reported Critical/Certain.
//
// Each LoginProbe is the in-house equivalent of a nuclei default-login template:
// a login request (path + method + body), the documented credential pairs, and a
// success matcher. Mirror the upstream template's matcher faithfully — it is what
// keeps the check discriminating.
type LoginProbe struct {
	// Paths are login endpoints relative to the confirmed base (each tried in
	// order until a credential pair succeeds), e.g. ["/login"], ["/oauth/token"].
	Paths []string

	Method      string // HTTP method, default "POST"
	ContentType string // Content-Type for Body (e.g. "application/json")

	// Body is the request-body template; the {{user}} / {{pass}} placeholders are
	// substituted with each credential pair. Empty when BasicAuth is set.
	Body string

	// BasicAuth sends the pair as "Authorization: Basic base64(user:pass)" with no
	// body instead (e.g. RabbitMQ GET /api/whoami).
	BasicAuth bool

	// Creds are the documented default {username, password} pairs to try, in
	// order. Keep this to vendor defaults only — never a brute-force list.
	Creds [][2]string

	// Success is the matcher proving a pair authenticated.
	Success LoginSuccess
}

// LoginSuccess is the matcher proving a credential pair authenticated. Every set
// condition must hold (AND), mirroring the upstream nuclei matchers. BodyContains
// substrings MUST be lowercase (the body is lowercased once before matching).
type LoginSuccess struct {
	Status       []int       // acceptable status codes (empty → any)
	Headers      []HeaderSig // response headers that must be present / contain (e.g. Set-Cookie: grafana_session)
	BodyContains []string    // substrings that must ALL appear (lowercased)
	EmptyBody    bool        // body must be empty / whitespace (e.g. SonarQube's JWT-cookie flow)
}

// HTTPMethod returns the configured method, defaulting to POST.
func (p *LoginProbe) HTTPMethod() string {
	if p.Method == "" {
		return "POST"
	}
	return p.Method
}

// Match reports whether a login response satisfies the success matcher. header
// returns a response header value (Set-Cookie values joined when there are
// several); bodyLower must be strings.ToLower(body).
func (s *LoginSuccess) Match(status int, header func(name string) string, body, bodyLower string) bool {
	if len(s.Status) > 0 {
		ok := false
		for _, st := range s.Status {
			if st == status {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if s.EmptyBody && strings.TrimSpace(body) != "" {
		return false
	}
	for _, h := range s.Headers {
		v := header(h.Name)
		if v == "" {
			return false
		}
		if h.Contains != "" && !strings.Contains(strings.ToLower(v), h.Contains) {
			return false
		}
	}
	for _, sub := range s.BodyContains {
		if !strings.Contains(bodyLower, sub) {
			return false
		}
	}
	// A matcher that asserts nothing is meaningless — never confirm on it.
	return len(s.Status) > 0 || len(s.Headers) > 0 || len(s.BodyContains) > 0 || s.EmptyBody
}
