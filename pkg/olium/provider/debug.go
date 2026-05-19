package provider

import (
	"fmt"
	"io"
	"os"
	"regexp"
)

// secretPatterns matches the credential shapes most likely to leak through
// a provider's debug dump — operator-gated by VIGOLIUM_OLIUM_DEBUG. The
// patterns are intentionally over-broad: a false positive prints
// `<redacted-secret>` where a benign string used to be, which is far
// cheaper than letting an API key drift into a log.
//
// Patterns covered:
//
//   - `sk-ant-…` Anthropic API keys and Claude Code OAuth tokens
//     (`sk-ant-oat01-…`)
//   - `sk-…`     OpenAI / OpenRouter-style API keys (≥ 32 char tail)
//   - `Bearer …` generic OAuth bearer values
//   - `AIzaSy…`  Google API keys
//   - `ghp_…`    GitHub PATs
//
// Bearer is matched case-insensitively because callers may emit raw
// header dumps. The other patterns are case-sensitive on their prefix
// (vendors hand out lowercase).
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{8,}`),
	regexp.MustCompile(`sk-[A-Za-z0-9_\-]{32,}`),
	regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._\-+/=]{20,}`),
	regexp.MustCompile(`AIza[A-Za-z0-9_\-]{20,}`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{30,}`),
}

// secretPlaceholder is what scrubSecrets substitutes for a match. Distinct
// from the server-side `<redacted>` so a reader can tell which layer
// caught the leak.
const secretPlaceholder = "<redacted-secret>"

// scrubSecrets returns s with any matched credential shape replaced by
// secretPlaceholder. O(n·patterns) over the input; called from debug
// paths only.
func scrubSecrets(s string) string {
	for _, pat := range secretPatterns {
		s = pat.ReplaceAllString(s, secretPlaceholder)
	}
	return s
}

// debugFprintf writes a debug line to stderr with credential-shaped
// substrings scrubbed. Drop-in for `fmt.Fprintf(os.Stderr, ...)` at the
// VIGOLIUM_OLIUM_DEBUG print sites so each call site doesn't have to
// remember to pre-scrub the format args.
func debugFprintf(w io.Writer, format string, args ...any) {
	if w == nil {
		w = os.Stderr
	}
	_, _ = fmt.Fprintln(w, scrubSecrets(fmt.Sprintf(format, args...)))
}
