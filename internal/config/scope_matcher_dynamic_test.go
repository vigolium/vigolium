package config

import "testing"

// restrictiveMatcher returns a matcher whose Host rule admits only allowHost.
func restrictiveMatcher(allowHost string) *ScopeMatcher {
	cfg := *DefaultScopeConfig()
	cfg.Host = ScopeRule{Include: []string{allowHost}}
	return NewScopeMatcher(cfg)
}

func TestAllowHost_AdmitsExactHost(t *testing.T) {
	m := restrictiveMatcher("app.example.com")

	if m.InScopeRequest("api.example.com", "/", "", "") {
		t.Fatal("api.example.com should be out of scope before AllowHost")
	}
	m.AllowHost("api.example.com")
	if !m.InScopeRequest("api.example.com", "/", "", "") {
		t.Fatal("api.example.com should be in scope after AllowHost")
	}
	// The apex is NOT wildcarded: a sibling that was never allowed stays out.
	if m.InScopeRequest("other.example.com", "/", "", "") {
		t.Fatal("other.example.com must remain out of scope (no apex wildcard)")
	}
}

// TestAllowHost_OverridesCachedNegative guards the ordering bug where a host
// checked (and cached false) before AllowHost would stay rejected.
func TestAllowHost_OverridesCachedNegative(t *testing.T) {
	m := restrictiveMatcher("app.example.com")

	if m.InScopeRequest("late.example.com", "/", "", "") {
		t.Fatal("precondition: late.example.com out of scope")
	}
	m.AllowHost("late.example.com")
	if !m.InScopeRequest("late.example.com", "/", "", "") {
		t.Fatal("AllowHost must override the cached negative result")
	}
}

func TestAllowHost_CaseInsensitiveAndEmptySafe(t *testing.T) {
	m := restrictiveMatcher("app.example.com")
	m.AllowHost("") // no-op, must not panic
	m.AllowHost("API.Example.COM")
	if !m.InScopeRequest("api.example.com", "/", "", "") {
		t.Fatal("AllowHost should match host case-insensitively")
	}
}
