package agent

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/vigolium/vigolium/pkg/input/formats/curl"
)

// SynthesizeAuthConfig builds a single-session AgentSessionConfig from
// operator-supplied cookies, headers, and/or a login-curl. Returns
// (nil, nil) when all inputs are empty so callers can fall through to
// browser-auth or no-auth.
func SynthesizeAuthConfig(cookies []string, headers []string, loginCurl string) (*AgentSessionConfig, error) {
	if len(cookies) == 0 && len(headers) == 0 && strings.TrimSpace(loginCurl) == "" {
		return nil, nil
	}

	entry := AgentSessionEntry{
		Name:    "cli-injected",
		Role:    "primary",
		Headers: map[string]string{},
	}

	// Headers go first so --cookie values get appended onto any
	// pre-existing Cookie: ... header instead of overwriting it.
	for _, h := range headers {
		name, value, ok := splitHeader(h)
		if !ok {
			return nil, fmt.Errorf("invalid --header %q (expected 'Name: value')", h)
		}
		// Canonicalise case so duplicates merge sensibly.
		canon := http.CanonicalHeaderKey(name)
		if prev, exists := entry.Headers[canon]; exists {
			entry.Headers[canon] = prev + ", " + value
		} else {
			entry.Headers[canon] = value
		}
	}

	if len(cookies) > 0 {
		joined := joinCookieValues(cookies)
		existing := entry.Headers["Cookie"]
		if existing != "" {
			joined = strings.TrimSuffix(existing, ";") + "; " + joined
		}
		entry.Headers["Cookie"] = joined
	}

	if loginCurl != "" {
		login, err := loginFlowFromCurl(loginCurl)
		if err != nil {
			return nil, fmt.Errorf("parsing --login-curl: %w", err)
		}
		entry.Login = login
	}

	return &AgentSessionConfig{Sessions: []AgentSessionEntry{entry}}, nil
}

func splitHeader(h string) (name, value string, ok bool) {
	idx := strings.IndexByte(h, ':')
	if idx <= 0 {
		return "", "", false
	}
	name = strings.TrimSpace(h[:idx])
	value = strings.TrimSpace(h[idx+1:])
	if name == "" {
		return "", "", false
	}
	return name, value, true
}

// joinCookieValues flattens inputs that may themselves contain
// semicolon-separated cookies into a single "k=v; k2=v2" string.
func joinCookieValues(in []string) string {
	parts := make([]string, 0, len(in))
	for _, item := range in {
		for _, piece := range strings.Split(item, ";") {
			piece = strings.TrimSpace(piece)
			if piece != "" {
				parts = append(parts, piece)
			}
		}
	}
	return strings.Join(parts, "; ")
}

// loginFlowFromCurl converts a pasted curl command into an AgentLoginFlow.
// Extract rules are left empty — the operator must fill them in if a
// non-cookie token is involved.
func loginFlowFromCurl(cmd string) (*AgentLoginFlow, error) {
	rr, err := curl.ParseSingleCommand(cmd)
	if err != nil {
		return nil, err
	}
	if rr == nil || rr.Request() == nil {
		return nil, fmt.Errorf("curl produced no request")
	}
	req := rr.Request()
	u, err := rr.URL()
	if err != nil {
		return nil, fmt.Errorf("curl missing absolute URL: %w", err)
	}
	body := string(req.Body())
	ct := req.Header("Content-Type")
	return &AgentLoginFlow{
		URL:         u.String(),
		Method:      strings.ToUpper(req.Method()),
		ContentType: ct,
		Body:        body,
	}, nil
}

// ExtraHeadersFromAuth returns the primary session's static headers as
// a map. Login entries are ignored — replaying logins is the auth
// phase's job, not recon's.
func ExtraHeadersFromAuth(cfg *AgentSessionConfig) map[string]string {
	if cfg == nil || len(cfg.Sessions) == 0 {
		return nil
	}
	pick := -1
	for i, s := range cfg.Sessions {
		if strings.EqualFold(s.Role, "primary") {
			pick = i
			break
		}
	}
	if pick < 0 {
		pick = 0
	}
	out := make(map[string]string, len(cfg.Sessions[pick].Headers))
	for k, v := range cfg.Sessions[pick].Headers {
		out[k] = v
	}
	return out
}
