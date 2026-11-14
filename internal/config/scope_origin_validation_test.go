package config

import "testing"

// An unknown origin mode no longer admits every host.
func TestScopeOrigin_UnknownModeRejectsForeignHost(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.CLIOriginMode = "bogus"
	m := NewScopeMatcher(cfg, "https://app.example.com")
	if m.HostInScope("evil.com") {
		t.Error("unknown mode admitted evil.com")
	}
	if !m.HostInScope("api.example.com") {
		t.Error("unknown mode should run as the default (balanced) and admit same-apex hosts")
	}
	if got := ResolveCLIOriginMode("bogus"); got != DefaultCLIOriginMode {
		t.Errorf("ResolveCLIOriginMode(bogus) = %q, want %q", got, DefaultCLIOriginMode)
	}
	// A hand-built matcher with an unknown mode fails closed too.
	hm := &ScopeMatcher{originMode: "bogus", originIndex: buildOriginIndex(parseOriginTargets([]string{"app.example.com"}), "bogus")}
	if hm.hostMatchesOrigin("evil.com") {
		t.Error("hand-built matcher with an unknown mode admitted evil.com")
	}
}

// Relaxed mode skips keywords shorter than four characters.
func TestScopeOrigin_RelaxedShortKeyword(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.CLIOriginMode = "relaxed"
	m := NewScopeMatcher(cfg, "https://a.io")
	if m.HostInScope("banana.com") {
		t.Error("relaxed a.io admitted banana.com")
	}
	if !m.HostInScope("a.io") {
		t.Error("relaxed a.io must still admit its exact host")
	}
	long := NewScopeMatcher(cfg, "https://acme.io")
	if !long.HostInScope("acmegroup.com") {
		t.Error("relaxed acme.io should admit acmegroup.com")
	}
}

func TestValidCLIOriginMode(t *testing.T) {
	for _, m := range []string{"all", "relaxed", "Balanced", " strict "} {
		if !ValidCLIOriginMode(m) {
			t.Errorf("%q should be valid", m)
		}
	}
	for _, m := range []string{"bogus", "any", ""} {
		if ValidCLIOriginMode(m) {
			t.Errorf("%q should be invalid", m)
		}
	}
}
