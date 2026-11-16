package browsercookie

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/reconsig"
)

// Scope decides how a requested domain is matched against a cookie's domain
// attribute.
//
// The distinction exists because a cookie's domain is not a string to compare
// but a scope rule: `.example.com` serves every host under example.com, while
// `example.com` with no leading dot serves that host alone. Comparing the two
// as strings is the single most common way a cookie export comes out either
// short or full of cookies the target would never receive.
type Scope int

const (
	// ScopeHost keeps the cookies a browser would actually send to the
	// requested hostname, per RFC 6265 domain-matching: its own host-only
	// cookies, plus the domain cookies of every parent domain. This is the
	// default because it answers the question a caller is really asking —
	// "what does a request to this host carry?"
	ScopeHost Scope = iota
	// ScopeSubdomains additionally keeps cookies belonging to hosts *below*
	// the requested domain, so asking for example.com also returns the cookies
	// scoped to app.example.com. Use it to collect a whole site's sessions.
	ScopeSubdomains
	// ScopeApex widens each requested domain to its registrable domain
	// (eTLD+1) and then applies ScopeSubdomains, so any host in the
	// organization's domain matches. "a.b.example.co.uk" becomes
	// "example.co.uk" — which needs the public suffix list, not a label count.
	ScopeApex
)

// String renders the scope as its CLI spelling.
func (s Scope) String() string {
	switch s {
	case ScopeSubdomains:
		return "subdomains"
	case ScopeApex:
		return "apex"
	default:
		return "host"
	}
}

// ParseScope maps a CLI spelling to a Scope.
func ParseScope(s string) (Scope, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "host", "exact":
		return ScopeHost, nil
	case "subdomains", "sub", "subdomain":
		return ScopeSubdomains, nil
	case "apex", "etld+1", "registrable":
		return ScopeApex, nil
	default:
		return ScopeHost, SelectorError{Err: fmt.Errorf("unknown scope %q (want host, subdomains, or apex)", s)}
	}
}

// Matcher decides whether a cookie's domain attribute is in scope.
type Matcher struct {
	targets []target
	all     bool
}

// target is one requested domain, resolved to the host it names and whether
// that host's subtree was requested too.
type target struct {
	host string
	// dotHost is "." + host, precomputed. Match is the package's hot path — it
	// runs per cookie row, per storage key and per IndexedDB directory — and
	// building this suffix inside the loop allocated once or twice per row per
	// target for nothing.
	dotHost string
	// subtree is true when cookies belonging to hosts below host should match,
	// either because the scope says so or because the caller wrote the domain
	// with a leading dot or a `*.` wildcard.
	subtree bool
}

// NewMatcher builds a matcher for the requested domains. An empty domain list
// matches every cookie.
//
// A domain may be written as a bare hostname, a URL, a host:port, `.example.com`,
// or `*.example.com`; the last two request the subtree regardless of scope,
// because that is unambiguously what the operator wrote.
func NewMatcher(domains []string, scope Scope) (*Matcher, error) {
	m := &Matcher{}
	if len(domains) == 0 {
		m.all = true
		return m, nil
	}
	seen := make(map[target]bool, len(domains))
	for _, raw := range domains {
		host, explicitSubtree := normalizeTarget(raw)
		if host == "" {
			return nil, SelectorError{Err: fmt.Errorf("not a usable domain: %q", raw)}
		}
		subtree := explicitSubtree || scope == ScopeSubdomains || scope == ScopeApex
		if scope == ScopeApex {
			// reconsig.RegistrableDomain is the repo's one public-suffix entry
			// point; it already guards the single-label and IP cases that
			// publicsuffix answers unhelpfully (it maps every IPv4 to "0.1").
			// It returns "" for a host with no registrable domain — a single
			// label like "localhost" — and falling back to the host as written
			// keeps --apex usable against a local app rather than refusing the
			// query over a domain with no apex to find.
			if apex := reconsig.RegistrableDomain(host); apex != "" {
				host = apex
			}
		}
		t := target{host: host, dotHost: "." + host, subtree: subtree}
		if seen[t] {
			continue
		}
		seen[t] = true
		m.targets = append(m.targets, t)
	}
	return m, nil
}

// Targets returns the hostnames the matcher resolved to, for display. Useful
// with ScopeApex, where what was asked for is not what is matched.
func (m *Matcher) Targets() []string {
	if m == nil || m.all {
		return nil
	}
	out := make([]string, 0, len(m.targets))
	for _, t := range m.targets {
		if t.subtree {
			out = append(out, "."+t.host)
			continue
		}
		out = append(out, t.host)
	}
	return out
}

// Match reports whether a cookie whose domain attribute is hostKey is in scope.
//
// hostKey is the stored form: a leading dot means the cookie is a domain cookie
// serving the whole subtree, and no leading dot means it is host-only.
func (m *Matcher) Match(hostKey string) bool {
	if m == nil {
		return false
	}
	if m.all {
		return true
	}
	host, servesSubtree := splitHostKey(hostKey)
	if host == "" {
		return false
	}
	// Hoisted out of the loop for the same reason target.dotHost exists.
	dotHost := "." + host
	for _, t := range m.targets {
		// The cookie's own scope reaches the target: either the same host, or
		// a domain cookie on one of the target's ancestors.
		if host == t.host || (servesSubtree && isUnderDotted(t.host, host, dotHost)) {
			return true
		}
		// The caller asked for the target's subtree, and this cookie belongs
		// to a host inside it.
		if t.subtree && isUnderDotted(host, t.host, t.dotHost) {
			return true
		}
	}
	return false
}

// splitHostKey separates a stored cookie domain into the host it names and
// whether it serves that host's subtree.
func splitHostKey(hostKey string) (host string, servesSubtree bool) {
	host = strings.ToLower(strings.TrimSpace(hostKey))
	if strings.HasPrefix(host, ".") {
		return strings.TrimPrefix(host, "."), true
	}
	return host, false
}

// isUnderDotted reports whether host sits strictly below parent in the DNS
// tree, given parent's precomputed "."+parent form.
//
// The dotted suffix is passed in rather than built here because the only
// callers are inside Match's per-row loop.
func isUnderDotted(host, parent, dotParent string) bool {
	return host != parent && strings.HasSuffix(host, dotParent)
}

// normalizeTarget reduces a caller-written domain to a lowercase hostname,
// reporting whether the subtree was requested explicitly with a leading dot or
// a `*.` wildcard.
func normalizeTarget(raw string) (host string, subtree bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", false
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname()), false
		}
	}
	// Drop any path, then any port.
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	// Only strip a port when what follows is plausibly one; an IPv6 literal
	// has colons of its own.
	if h, port, ok := strings.Cut(s, ":"); ok && !strings.Contains(h, ":") && isDigits(port) {
		s = h
	}
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".") // a fully-qualified trailing dot
	switch {
	case strings.HasPrefix(s, "*."):
		return strings.TrimPrefix(s, "*."), true
	case strings.HasPrefix(s, "."):
		return strings.TrimPrefix(s, "."), true
	}
	return s, false
}

// isDigits reports whether s is a non-empty run of ASCII digits.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
