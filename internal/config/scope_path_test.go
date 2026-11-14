package config

import "testing"

// Path rules see the path only, and "*" crosses "/".
func TestScopePath_QueryAndGlobSemantics(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.Path = ScopeRule{Include: []string{"*"}, Exclude: []string{"/logout", "/admin/*"}}
	cfg.IgnoreStaticFile = true
	cfg.IgnoreStaticContentType = map[string][]string{"image": {"png"}}
	m := NewScopeMatcher(cfg)

	if m.InScopeRequest("a.test", "/logout?next=/", "", "") {
		t.Error("exclude /logout must block /logout?next=/")
	}
	if !m.ExplicitlyExcluded("a.test", "/logout?next=/") {
		t.Error("ExplicitlyExcluded must see /logout?next=/ as excluded")
	}
	if m.InScopeTarget("a.test", "/admin/users/1") {
		t.Error("exclude /admin/* must block /admin/users/1")
	}
	if got := m.RejectReason("a.test", "/admin/users/1?x=1"); got != ScopeRulePathExclude {
		t.Errorf("RejectReason = %q, want %q", got, ScopeRulePathExclude)
	}
	if m.IsStaticFile("/download?file=a.png") {
		t.Error("/download?file=a.png is not a static file")
	}
	if !m.IsStaticFile("/img/a.png?v=2") {
		t.Error("/img/a.png?v=2 is a static file")
	}

	inc := *DefaultScopeConfig()
	inc.Path = ScopeRule{Include: []string{"/api/*"}}
	mi := NewScopeMatcher(inc)
	if !mi.InScopeTarget("a.test", "/api/users/1") {
		t.Error("include /api/* must admit /api/users/1")
	}
	if mi.InScopeTarget("a.test", "/web/x?p=/api/1") {
		t.Error("include /api/* must not admit a path whose query mentions /api/")
	}
	dbl := *DefaultScopeConfig()
	dbl.Path = ScopeRule{Include: []string{"/api/**"}}
	if !NewScopeMatcher(dbl).InScopeTarget("a.test", "/api/v1/x") {
		t.Error("** must behave as *")
	}
}
