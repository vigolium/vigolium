package secret_detect

import (
	"strings"
	"testing"
)

func TestIsBinaryBlobMatch(t *testing.T) {
	// A real ZeroTier-shaped token (32 alphanumerics) — the value that triggered
	// the original false positive.
	const token = "6CINUdsL0U48ehlj0m7GpyUAeQX5qGWa"

	// base64 padding of varying lengths.
	pad := func(n int) string { return strings.Repeat("QXz9bRf2", n/8+1)[:n] }

	tests := []struct {
		name    string
		body    string
		snippet string
		want    bool
	}{
		{
			name:    "embedded mid-stream in a long base64 blob is a blob match",
			body:    `<img src="data:image/png;base64,` + pad(400) + token + pad(400) + `">`,
			snippet: token,
			want:    true,
		},
		{
			name:    "at the very end of a long base64 blob is a blob match",
			body:    pad(400) + token + `"`,
			snippet: token,
			want:    true,
		},
		{
			name:    "at the very start of a long base64 blob is a blob match",
			body:    `,` + token + pad(400),
			snippet: token,
			want:    true,
		},
		{
			name:    "delimited JSON value is NOT a blob match",
			body:    `{"api_token":"` + token + `","note":"prod key"}`,
			snippet: token,
			want:    false,
		},
		{
			name:    "delimited JS assignment is NOT a blob match",
			body:    `const apiKey = "` + token + `";`,
			snippet: token,
			want:    false,
		},
		{
			name:    "token on its own line is NOT a blob match",
			body:    "API_TOKEN=" + token + "\nNEXT_LINE=value",
			snippet: token,
			want:    false,
		},
		{
			name:    "standalone base64 secret delimited by quotes is NOT a blob match",
			body:    `"secret":"` + pad(88) + `"`,
			snippet: pad(88),
			want:    false,
		},
		{
			name:    "newline-separated secret dump is NOT collapsed into one blob",
			body:    "sk_live_" + pad(24) + "\nsk_live_" + pad(24) + "\nsk_live_" + pad(24),
			snippet: "sk_live_" + pad(24),
			want:    false,
		},
		{
			name:    "snippet absent from body is kept (cannot verify)",
			body:    pad(400),
			snippet: token,
			want:    false,
		},
		{
			name:    "empty snippet is kept",
			body:    pad(400),
			snippet: "",
			want:    false,
		},
		{
			name:    "empty body is kept",
			body:    "",
			snippet: token,
			want:    false,
		},
		{
			name:    "space delimiter stops the run even with base64 nearby",
			body:    pad(400) + " " + token + " " + pad(400),
			snippet: token,
			want:    false,
		},
		{
			name:    "contiguous run just under threshold is kept",
			body:    pad(79) + token + pad(79), // before+after = 158 < 160
			snippet: token,
			want:    false,
		},
		{
			name:    "contiguous run at threshold is a blob match",
			body:    pad(80) + token + pad(80), // before+after = 160
			snippet: token,
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsBinaryBlobMatch([]byte(tt.body), tt.snippet, -1, -1)
			if got != tt.want {
				t.Errorf("IsBinaryBlobMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}
