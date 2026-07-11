package secret_detect

import (
	"testing"
)

// bs is a single literal backslash byte. Building escape sequences by
// concatenating it (rather than writing "ɵ" directly) guarantees the test
// body holds the six literal characters backslash-u-0-2-7-5 — exactly what a
// minified JS bundle ships — instead of Go interpreting it into the ɵ rune.
const bs = "\\"

func TestIsJSEscapeArtifactMatch(t *testing.T) {
	// A real ZeroTier-shaped token (32 alphanumerics) — a genuine credential
	// must never be dropped by this guard.
	const token = "6CINUdsL0U48ehlj0m7GpyUAeQX5qGWa"

	// The actual false positive: Angular emits its private "ɵ" exports as the
	// six-character escape backslash-u-0-2-7-5, and the ZeroTier
	// [A-Za-z0-9]{32} rule matches starting at the 'u', clipping out a 32-char
	// identifier.
	const angularSnippet = "u0275setUnknownElementStrictMode"

	// "ɵsetUnknownElementStrictMode:()=>Pl,ɵstore:()=>T_,"
	angularBody := "," + bs + "u0275setUnknownElementStrictMode:()=>Pl," + bs + "u0275store:()=>T_,"

	// A clean identifier sitting immediately after a complete ɵ escape.
	cleanAfterEscape := "," + bs + "u0275publishDefaultGlobalUtilsForTheBundle:()=>Iw,"

	// A \xNN hex escape variant.
	hexEscapeBody := `a="` + bs + `x41setUnknownElementStrictModeXyz";`

	tests := []struct {
		name    string
		body    string
		snippet string
		want    bool
	}{
		{
			name:    "match clipped out of an Angular unicode escape is an artifact",
			body:    angularBody,
			snippet: angularSnippet,
			want:    true,
		},
		{
			name:    "clean identifier immediately after a full unicode escape is an artifact",
			body:    cleanAfterEscape,
			snippet: "publishDefaultGlobalUtilsForTheBundle",
			want:    true,
		},
		{
			name:    "hex escape artifact is dropped",
			body:    hexEscapeBody,
			snippet: "x41setUnknownElementStrictModeXyz",
			want:    true,
		},
		{
			name:    "delimited JSON credential is NOT an artifact",
			body:    `{"api_token":"` + token + `"}`,
			snippet: token,
			want:    false,
		},
		{
			name:    "delimited JS assignment credential is NOT an artifact",
			body:    `const apiKey = "` + token + `";`,
			snippet: token,
			want:    false,
		},
		{
			name:    "token following a quote (not a backslash) is NOT an artifact",
			body:    `"` + token + `"`,
			snippet: token,
			want:    false,
		},
		{
			name:    "backslash before a non-escape (not u/x + hex) is NOT an artifact",
			body:    `path` + bs + token,
			snippet: token,
			want:    false,
		},
		{
			name:    "snippet absent from body is kept (cannot verify)",
			body:    "," + bs + "u0275something",
			snippet: angularSnippet,
			want:    false,
		},
		{
			name:    "snippet at the very start of the body is kept (no preceding byte)",
			body:    token,
			snippet: token,
			want:    false,
		},
		{
			name:    "empty snippet is kept",
			body:    "," + bs + "u0275foo",
			snippet: "",
			want:    false,
		},
		{
			name:    "empty body is kept",
			body:    "",
			snippet: token,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsJSEscapeArtifactMatch([]byte(tt.body), tt.snippet, -1, -1); got != tt.want {
				t.Errorf("IsJSEscapeArtifactMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStartsWithEscapeBody(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"u0275rest", true},
		{"U0275rest", true},
		{"x41rest", true},
		{"X41rest", true},
		{"u027", false},      // only 3 hex after u
		{"uZZZZrest", false}, // non-hex
		{"setUnknown", false},
		{"", false},
	}
	for _, c := range cases {
		if got := startsWithEscapeBody(c.in); got != c.want {
			t.Errorf("startsWithEscapeBody(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestEndsWithEscape(t *testing.T) {
	if !endsWithEscape([]byte("prefix" + bs + "u0275")) {
		t.Errorf("expected a complete unicode escape suffix to be detected")
	}
	if !endsWithEscape([]byte("prefix" + bs + "x41")) {
		t.Errorf("expected a complete hex escape suffix to be detected")
	}
	if endsWithEscape([]byte("prefix" + bs + "u027")) {
		t.Errorf("incomplete unicode escape must not count")
	}
	if endsWithEscape([]byte("plaintext")) {
		t.Errorf("plain text must not count as an escape")
	}
	if endsWithEscape([]byte("ab")) {
		t.Errorf("too-short prefix must not count as an escape")
	}
}
