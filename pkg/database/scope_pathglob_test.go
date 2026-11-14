package database

import "testing"

// Database scope path rules ignore the query and "*" crosses "/".
func TestScopeEvaluator_PathGlob(t *testing.T) {
	e := NewScopeEvaluator([]*Scope{
		{Enabled: true, RuleType: "exclude", PathPattern: "/logout"},
		{Enabled: true, RuleType: "include", PathPattern: "/api/*"},
	})
	if e.IsInScope("https", "a.test", 443, "GET", "/logout?next=/") {
		t.Error("exclude /logout must match /logout?next=/")
	}
	if !e.IsInScope("https", "a.test", 443, "GET", "/api/users/1") {
		t.Error("include /api/* must admit /api/users/1")
	}
}
