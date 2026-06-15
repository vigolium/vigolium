package xssbreakout

import (
	"strings"
	"testing"
)

func TestJSStringPayloads_SingleQuote(t *testing.T) {
	alert := "alert(`vigx1234`)"
	got := JSStringPayloads('\'', alert)

	if len(got) != 3 {
		t.Fatalf("expected 3 payloads, got %d: %v", len(got), got)
	}

	// The operator-chaining variants are what let this confirm an expression-context
	// reflection where a statement terminator would SyntaxError.
	wantOps := []string{
		"'^" + alert + "^'",
		"'-" + alert + "-'",
	}
	for _, w := range wantOps {
		if !containsExact(got, w) {
			t.Errorf("missing operator-chaining payload %q in %v", w, got)
		}
	}

	// Operator chaining must come before the terminator fallback (most-general first).
	if !strings.HasPrefix(got[0], "'^") {
		t.Errorf("expected XOR chaining first, got %q", got[0])
	}
	if got[len(got)-1] != "';"+alert+"//" {
		t.Errorf("expected terminator last, got %q", got[len(got)-1])
	}

	// Every payload must carry the alert expression verbatim so the body check and
	// the browser dialog can both attribute it.
	for _, p := range got {
		if !strings.Contains(p, alert) {
			t.Errorf("payload %q dropped the alert expression", p)
		}
	}
}

func TestJSStringPayloads_DoubleQuote(t *testing.T) {
	alert := "alert(`c`)"
	got := JSStringPayloads('"', alert)
	for _, p := range got {
		if !strings.HasPrefix(p, `"`) {
			t.Errorf("double-quote context payload must open with \", got %q", p)
		}
	}
	if !containsExact(got, `"^`+alert+`^"`) {
		t.Errorf("missing double-quote XOR chaining payload in %v", got)
	}
}

func containsExact(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
