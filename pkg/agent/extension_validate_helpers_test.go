package agent

import (
	"testing"
)

func TestIsSimpleJSIdentifier(t *testing.T) {
	valid := []string{"foo", "agent-generated", "scan_per_request", "$id", "a1b2", "x-y-z", ""}
	for _, s := range valid {
		if !isSimpleJSIdentifier(s) {
			t.Errorf("isSimpleJSIdentifier(%q) = false, want true", s)
		}
	}
	invalid := []string{"has space", "a.b", "a/b", "a;b", "café", "a(b)"}
	for _, s := range invalid {
		if isSimpleJSIdentifier(s) {
			t.Errorf("isSimpleJSIdentifier(%q) = true, want false", s)
		}
	}
}

func TestCountUnquotedColons(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"id: x", 1},
		{`url: "http://x"`, 1}, // the :// is inside the quoted string
		{`a: 1, b: 2`, 2},
		{`"only:inside:quotes"`, 0},
		{`severity:'high'`, 1},
		{"", 0},
		{`a: "x:y", b: "z:w"`, 2}, // only the two structural colons count
	}
	for _, tc := range cases {
		if got := countUnquotedColons(tc.in); got != tc.want {
			t.Errorf("countUnquotedColons(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestExtractCodeFromResponse(t *testing.T) {
	t.Run("extracts fenced block", func(t *testing.T) {
		resp := "Here is the code:\n```javascript\nmodule.exports = {};\n```\nDone."
		got := extractCodeFromResponse(resp)
		if got != "module.exports = {};" {
			t.Errorf("got %q, want fenced block content", got)
		}
	})

	t.Run("falls back to trimmed raw output", func(t *testing.T) {
		got := extractCodeFromResponse("   bare code no fences   ")
		if got != "bare code no fences" {
			t.Errorf("got %q, want trimmed bare code", got)
		}
	})

	t.Run("skips empty fenced blocks", func(t *testing.T) {
		resp := "```\n\n```\n```js\nreal();\n```"
		got := extractCodeFromResponse(resp)
		if got != "real();" {
			t.Errorf("got %q, want first non-empty block", got)
		}
	})
}

func TestExtractGarbledField_TruncatedValue(t *testing.T) {
	// No closing quote: should still return a best-effort string marked garbled.
	code := `id: "agent-truncated-no-end`
	got := extractGarbledField(code, "id")
	if got == "" {
		t.Error("truncated value should return a best-effort string")
	}
	if !containsAny(got, "garbled") {
		t.Errorf("truncated value should be marked garbled, got %q", got)
	}
}
