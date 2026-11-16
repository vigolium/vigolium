package config

import "testing"

func TestRestrictsHostsAndInScopeTarget(t *testing.T) {
	var nilMatcher *ScopeMatcher
	if nilMatcher.RestrictsHosts() || !nilMatcher.InScopeTarget("a.example", "/x") {
		t.Error("a nil matcher restricts nothing and admits every path")
	}

	cfg := *DefaultScopeConfig()
	if NewScopeMatcher(cfg).RestrictsHosts() {
		t.Error("the default scope names no hosts")
	}
	cfg.Host = ScopeRule{Include: []string{"a.example"}}
	if !NewScopeMatcher(cfg).RestrictsHosts() {
		t.Error("a host include names hosts")
	}
	cfg.Host = ScopeRule{Include: []string{"a.example", "*"}}
	if NewScopeMatcher(cfg).RestrictsHosts() {
		t.Error(`"*" admits every host`)
	}
	cfg.Host = ScopeRule{}
	cfg.CLIOriginMode = "strict"
	if !NewScopeMatcher(cfg, "https://a.example").RestrictsHosts() {
		t.Error("CLI targets under strict origin mode name hosts")
	}

	cfg = *DefaultScopeConfig()
	cfg.Path = ScopeRule{Include: []string{"/api/*"}, Exclude: []string{"/api/admin*"}}
	m := NewScopeMatcher(cfg)
	if !m.InScopeTarget("a.example", "/api/users?id=1") || m.InScopeTarget("a.example", "/static/a.js") || m.InScopeTarget("a.example", "/api/admin/x") {
		t.Error("InScopeTarget does not follow the path rule")
	}
	if rule, pattern := m.RejectDetail("a.example", "/api/admin/x"); rule != ScopeRulePathExclude || pattern != "/api/admin*" {
		t.Errorf("rule = %q %q, want %q /api/admin*", rule, pattern, ScopeRulePathExclude)
	}
	if rule, _ := m.RejectDetail("a.example", "/static/a.js"); rule != ScopeRulePathInclude {
		t.Errorf("rule = %q, want %q", rule, ScopeRulePathInclude)
	}
}
