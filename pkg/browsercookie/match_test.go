package browsercookie

import (
	"slices"
	"strings"
	"testing"
)

func TestMatcherHostScope(t *testing.T) {
	// A browser sends a cookie to app.acme.test when the cookie is host-only
	// for that name, or a domain cookie on one of its ancestors. Nothing else.
	m, err := NewMatcher([]string{"app.acme.test"}, ScopeHost)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	cases := map[string]bool{
		"app.acme.test":       true,  // host-only, exact
		".app.acme.test":      true,  // domain cookie on the host itself
		".acme.test":          true,  // domain cookie on the parent
		".test":               true,  // domain cookie on a broader parent
		"acme.test":           false, // host-only on the parent: never sent to the child
		"other.acme.test":     false, // host-only on a sibling
		".other.acme.test":    false, // domain cookie on a sibling subtree
		"app.acme.test.evil":  false, // suffix lookalike
		"xapp.acme.test":      false, // label-boundary lookalike
		".xapp.acme.test":     false,
		"deep.app.acme.test":  false, // host-only below the target
		".deep.app.acme.test": false, // subtree below the target, not asked for
	}
	for hostKey, want := range cases {
		if got := m.Match(hostKey); got != want {
			t.Errorf("Match(%q) = %v, want %v", hostKey, got, want)
		}
	}
}

func TestMatcherSubdomainsScope(t *testing.T) {
	m, err := NewMatcher([]string{"acme.test"}, ScopeSubdomains)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	cases := map[string]bool{
		"acme.test":           true,
		".acme.test":          true,
		"app.acme.test":       true, // host-only below the target now counts
		".deep.app.acme.test": true,
		".test":               true, // still reaches the target
		"acme.test.evil":      false,
		"notacme.test":        false,
		"example.test":        false,
	}
	for hostKey, want := range cases {
		if got := m.Match(hostKey); got != want {
			t.Errorf("Match(%q) = %v, want %v", hostKey, got, want)
		}
	}
}

func TestMatcherApexScopeUsesPublicSuffixList(t *testing.T) {
	// The point of the public suffix list: example.co.uk is the registrable
	// domain, co.uk is not. A label count would widen this to ".co.uk" and
	// match every unrelated British site in the profile.
	m, err := NewMatcher([]string{"a.b.example.co.uk"}, ScopeApex)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if want := []string{".example.co.uk"}; !slices.Equal(m.Targets(), want) {
		t.Fatalf("Targets() = %v, want %v", m.Targets(), want)
	}
	if !m.Match("app.example.co.uk") {
		t.Error("apex scope should match a sibling host in the registrable domain")
	}
	if m.Match("other.co.uk") {
		t.Error("apex scope must not widen to the public suffix itself")
	}
}

func TestMatcherApexFallsBackForHostWithNoRegistrableDomain(t *testing.T) {
	// localhost has no eTLD+1. Refusing the query would make --apex unusable
	// against a local app for no benefit.
	m, err := NewMatcher([]string{"localhost"}, ScopeApex)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if !m.Match("localhost") {
		t.Error("apex scope should still match the host it was given")
	}
}

func TestMatcherExplicitSubtreeBeatsHostScope(t *testing.T) {
	// Writing the domain with a leading dot or a wildcard is an unambiguous
	// request for the subtree, whatever --scope says.
	for _, spelling := range []string{".acme.test", "*.acme.test"} {
		m, err := NewMatcher([]string{spelling}, ScopeHost)
		if err != nil {
			t.Fatalf("NewMatcher(%q): %v", spelling, err)
		}
		if !m.Match("app.acme.test") {
			t.Errorf("%q should request the subtree even under --scope host", spelling)
		}
	}
}

func TestMatcherEmptyDomainsMatchesEverything(t *testing.T) {
	m, err := NewMatcher(nil, ScopeHost)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if !m.Match("anything.test") {
		t.Error("an empty domain list should match every cookie")
	}
	if m.Targets() != nil {
		t.Errorf("Targets() = %v, want nil for a match-all matcher", m.Targets())
	}
}

func TestMatcherRejectsUnusableDomain(t *testing.T) {
	if _, err := NewMatcher([]string{"   "}, ScopeHost); err == nil {
		t.Error("a blank domain should be rejected rather than silently matching everything")
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := []struct {
		in          string
		wantHost    string
		wantSubtree bool
	}{
		{"ACME.test", "acme.test", false},
		{"https://app.acme.test/login?a=b", "app.acme.test", false},
		{"app.acme.test:8443", "app.acme.test", false},
		{"app.acme.test/path", "app.acme.test", false},
		{"acme.test.", "acme.test", false},
		{".acme.test", "acme.test", true},
		{"*.acme.test", "acme.test", true},
		{"[::1]", "[::1]", false}, // an IPv6 literal keeps its colons
		{"# comment", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		host, subtree := normalizeTarget(c.in)
		if host != c.wantHost || subtree != c.wantSubtree {
			t.Errorf("normalizeTarget(%q) = (%q, %v), want (%q, %v)", c.in, host, subtree, c.wantHost, c.wantSubtree)
		}
	}
}

func TestParseScope(t *testing.T) {
	for _, in := range []string{"", "host", "HOST", "exact"} {
		if got, err := ParseScope(in); err != nil || got != ScopeHost {
			t.Errorf("ParseScope(%q) = (%v, %v), want host", in, got, err)
		}
	}
	if got, _ := ParseScope("subdomains"); got != ScopeSubdomains {
		t.Errorf("ParseScope(subdomains) = %v", got)
	}
	if got, _ := ParseScope("apex"); got != ScopeApex {
		t.Errorf("ParseScope(apex) = %v", got)
	}
	err := func() error { _, err := ParseScope("sideways"); return err }()
	if err == nil || !strings.Contains(err.Error(), "host, subdomains, or apex") {
		t.Errorf("ParseScope(sideways) error = %v, want it to name the valid values", err)
	}
}

func TestScopeString(t *testing.T) {
	for scope, want := range map[Scope]string{
		ScopeHost:       "host",
		ScopeSubdomains: "subdomains",
		ScopeApex:       "apex",
	} {
		if got := scope.String(); got != want {
			t.Errorf("Scope(%d).String() = %q, want %q", scope, got, want)
		}
	}
}
