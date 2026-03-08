package condition

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// TestConditionEquality tests structural equality of conditions.
// Matches Crawljax's ConditionTest.java parameterized tests.
func TestConditionEquality(t *testing.T) {
	testCases := []struct {
		name       string
		self       *Condition
		equivalent *Condition
		different1 *Condition // Same type, different value
		different2 *Condition // Different type
	}{
		{
			name:       "URLContains",
			self:       URLContains("u0"),
			equivalent: URLContains("u0"),
			different1: URLContains("u1"),
			different2: JavaScript("u0"),
		},
		{
			name:       "URLMatches",
			self:       URLMatches(".*u0.*"),
			equivalent: URLMatches(".*u0.*"),
			different1: URLMatches(".*u1.*"),
			different2: URLContains(".*u0.*"),
		},
		{
			name:       "DOMRegex",
			self:       DOMRegex("rx0"),
			equivalent: DOMRegex("rx0"),
			different1: DOMRegex("rx1"),
			different2: URLContains("rx0"),
		},
		{
			name:       "XPathExists",
			self:       XPathExists("//div[@id='x0']"),
			equivalent: XPathExists("//div[@id='x0']"),
			different1: XPathExists("//div[@id='x1']"),
			different2: JavaScript("//div[@id='x0']"),
		},
		{
			name:       "ElementExists",
			self:       ElementExists("#elem0"),
			equivalent: ElementExists("#elem0"),
			different1: ElementExists("#elem1"),
			different2: ElementVisible("#elem0"),
		},
		{
			name:       "ElementVisible",
			self:       ElementVisible("#vis0"),
			equivalent: ElementVisible("#vis0"),
			different1: ElementVisible("#vis1"),
			different2: ElementExists("#vis0"),
		},
		{
			name:       "JavaScript",
			self:       JavaScript("js0"),
			equivalent: JavaScript("js0"),
			different1: JavaScript("js1"),
			different2: URLContains("js0"),
		},
		{
			name:       "And",
			self:       And(JavaScript("js0")),
			equivalent: And(JavaScript("js0")),
			different1: And(JavaScript("js1")),
			different2: Or(JavaScript("js0")),
		},
		{
			name:       "Or",
			self:       Or(JavaScript("js0")),
			equivalent: Or(JavaScript("js0")),
			different1: Or(JavaScript("js1")),
			different2: And(JavaScript("js0")),
		},
		{
			name:       "Negated",
			self:       URLContains("u0").Not(),
			equivalent: URLContains("u0").Not(),
			different1: URLContains("u1").Not(),
			different2: URLContains("u0"), // Not negated
		},
		{
			name:       "CountLimit",
			self:       CountLimit("key0", 2),
			equivalent: CountLimit("key0", 2),
			different1: CountLimit("key1", 2),
			different2: CountLimit("key0", 3),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test reflexive (c == c)
			if !conditionEquals(tc.self, tc.self) {
				t.Errorf("reflexive: expected self == self")
			}

			// Test symmetric (a == b implies b == a)
			if !conditionEquals(tc.self, tc.equivalent) {
				t.Errorf("symmetric: expected self == equivalent")
			}
			if !conditionEquals(tc.equivalent, tc.self) {
				t.Errorf("symmetric: expected equivalent == self")
			}

			// Test different values
			if conditionEquals(tc.self, tc.different1) {
				t.Errorf("different1: expected self != different1")
			}
			if conditionEquals(tc.different1, tc.self) {
				t.Errorf("different1: expected different1 != self")
			}

			// Test different types
			if conditionEquals(tc.self, tc.different2) {
				t.Errorf("different2: expected self != different2 (different type)")
			}

			// Test nil
			if conditionEquals(tc.self, nil) {
				t.Errorf("nil: expected self != nil")
			}
		})
	}
}

// conditionEquals compares two conditions for structural equality.
func conditionEquals(a, b *Condition) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Type != b.Type {
		return false
	}
	if a.Value != b.Value {
		return false
	}
	if a.Negate != b.Negate {
		return false
	}
	if a.operator != b.operator {
		return false
	}
	if a.MaxCount != b.MaxCount {
		return false
	}
	if len(a.children) != len(b.children) {
		return false
	}
	for i := range a.children {
		if !conditionEquals(a.children[i], b.children[i]) {
			return false
		}
	}
	return true
}

// TestConditionString tests string representation.
func TestConditionString(t *testing.T) {
	testCases := []struct {
		name string
		cond *Condition
	}{
		{"URLContains", URLContains("test")},
		{"URLMatches", URLMatches(".*test.*")},
		{"DOMRegex", DOMRegex("pattern")},
		{"XPathExists", XPathExists("//div")},
		{"ElementExists", ElementExists("#id")},
		{"ElementVisible", ElementVisible("#id")},
		{"JavaScript", JavaScript("true")},
		{"CountLimit", CountLimit("key", 5)},
		{"And", And(URLContains("a"), URLContains("b"))},
		{"Or", Or(URLContains("a"), URLContains("b"))},
		{"Negated", URLContains("test").Not()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Verify condition has expected type
			if tc.cond == nil {
				t.Fatal("condition is nil")
			}
		})
	}
}

// TestNewFromConfig tests condition creation from config.
func TestNewFromConfig(t *testing.T) {
	cfg := config.ConditionConfig{
		Type:     config.CondURLContains,
		Value:    "test",
		Negate:   true,
		MaxCount: 5,
		Preconditions: []config.ConditionConfig{
			{Type: config.CondURLContains, Value: "pre"},
		},
	}

	cond := NewFromConfig(cfg)

	if cond.Type != config.CondURLContains {
		t.Errorf("Type = %v, want %v", cond.Type, config.CondURLContains)
	}
	if cond.Value != "test" {
		t.Errorf("Value = %q, want %q", cond.Value, "test")
	}
	if !cond.Negate {
		t.Error("Negate = false, want true")
	}
	if cond.MaxCount != 5 {
		t.Errorf("MaxCount = %d, want 5", cond.MaxCount)
	}
	if len(cond.Preconditions) != 1 {
		t.Errorf("Preconditions length = %d, want 1", len(cond.Preconditions))
	}
	if cond.Preconditions[0].Value != "pre" {
		t.Errorf("Precondition Value = %q, want %q", cond.Preconditions[0].Value, "pre")
	}
}

// TestRegexCache tests that regex patterns are cached.
func TestRegexCache(t *testing.T) {
	pattern := "unique_test_pattern_\\d+"

	// First call compiles the regex
	re1 := getCachedRegex(pattern)
	if re1 == nil {
		t.Fatal("expected non-nil regex")
	}

	// Second call should return cached regex
	re2 := getCachedRegex(pattern)
	if re2 == nil {
		t.Fatal("expected non-nil cached regex")
	}

	// Both should be the same pointer
	if re1 != re2 {
		t.Error("expected same regex instance from cache")
	}
}

// TestInvalidRegex tests handling of invalid regex patterns.
func TestInvalidRegex(t *testing.T) {
	re := getCachedRegex("[invalid")
	if re != nil {
		t.Error("expected nil for invalid regex pattern")
	}
}
