package secret_detect

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestPatternLabel(t *testing.T) {
	// A structurally-valid JWT (header.payload.signature, header decodes to JSON
	// with alg/typ). Kept short but well-formed so ClassifyJWTSnippet recognises it.
	const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

	cases := []struct {
		name     string
		ruleName string
		snippet  string
		want     string
	}{
		{"recaptcha site key", "Google reCAPTCHA Key", "6LdZcXkpAAAAAJk7PVSqHC3DiV9F7U1ooUQdX1AZ", "reCAPTCHA site key"},
		{"google oauth client id", "Google OAuth Credentials", "1234567890-abcdefg.apps.googleusercontent.com", "Google OAuth client ID"},
		{"google api key by prefix", "Google Gemini API Key", "AIzaSyD-EXAMPLEEXAMPLEEXAMPLEEXAMPLE123", "Google API key"},
		{"google api key by rule name", "Google API Key", "someothervalue", "Google API key"},
		{"jwt normalised", "Some JWT-ish Rule", jwt, "JWT"},
		// A named vendor rule is surfaced verbatim — the ruleset already classifies it.
		{"vendor rule surfaced verbatim", "RazorPay API Key", "rzp_test_2N5KOJaU7vGghW", "RazorPay API Key"},
		{"slack rule surfaced verbatim", "Slack Token", "xoxb-1111-2222-abcdef", "Slack Token"},
		// Blank rule name falls back to structural recognition, then "secret".
		{"hex fallback when rule blank", "", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "hex token"},
		{"secret last resort", "  ", "not-hex-and-no-rule!", "secret"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PatternLabel(tc.ruleName, tc.snippet); got != tc.want {
				t.Fatalf("PatternLabel(%q, %q) = %q, want %q", tc.ruleName, tc.snippet, got, tc.want)
			}
		})
	}
}

func TestIsGenericSecretRule(t *testing.T) {
	cases := []struct {
		name     string
		ruleID   string
		ruleName string
		want     bool
	}{
		{"generic secret", "kingfisher.generic.1", "Generic Secret", true},
		{"generic api key", "kingfisher.generic.2", "Generic API Key", true},
		{"weak password (generic namespace, non-Generic name)", "kingfisher.generic.6", "Weak Password Pattern", true},
		{"nameless match", "", "", true},
		// Named provider families are NOT generic — they stay their own finding.
		{"google gemini", "kingfisher.google.7", "Google Gemini API Key", false},
		{"storyblok", "kingfisher.storyblok.1", "Storyblok API Token", false},
		{"stripe high-confidence", "kingfisher.stripe.1", "Stripe Secret Key", false},
		// A named low-confidence rule is still a family, not generic noise.
		{"bitfinex low-confidence but named", "kingfisher.bitfinex.1", "Bitfinex API Key", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsGenericSecretRule(tc.ruleID, tc.ruleName); got != tc.want {
				t.Fatalf("IsGenericSecretRule(%q, %q) = %v, want %v", tc.ruleID, tc.ruleName, got, tc.want)
			}
		})
	}
}

// TestNewSecretFindingBundleTag verifies only generic-namespace rules carry
// output.SuspectBundleTag, so the storage grouping pass bundles generic noise but
// keeps named provider families as their own per-host finding.
func TestNewSecretFindingBundleTag(t *testing.T) {
	hasBundleTag := func(tags []string) bool {
		for _, tag := range tags {
			if tag == output.SuspectBundleTag {
				return true
			}
		}
		return false
	}

	generic := NewSecretFinding("kingfisher.generic.2", "Generic API Key", "k3yZZabcdef012345678", "",
		severity.Suspect, severity.Tentative, "app.x.net", "https://app.x.net/a", "", "")
	if !hasBundleTag(generic.Info.Tags) {
		t.Errorf("generic rule finding tags = %v, want it to carry %q", generic.Info.Tags, output.SuspectBundleTag)
	}

	named := NewSecretFinding("kingfisher.google.7", "Google Gemini API Key", "AIzaSyA9ww" + "U3OfBHTOWZ" + "s_jrPLr6la" + "HG6YQwvnc", "",
		severity.Suspect, severity.Tentative, "app.x.net", "https://app.x.net/config.js", "", "")
	if hasBundleTag(named.Info.Tags) {
		t.Errorf("named provider finding tags = %v, must NOT carry %q", named.Info.Tags, output.SuspectBundleTag)
	}
}

// TestNewSecretFindingPatternInDescription verifies the rule's RE2 pattern is
// surfaced in the finding description so a reviewer sees exactly what was grepped.
func TestNewSecretFindingPatternInDescription(t *testing.T) {
	const pattern = `(?i)\bstoryblok(?:.|[\n\r]){0,32}?\b([A-Za-z0-9]{22}tt)\b`
	ev := NewSecretFinding("kingfisher.storyblok.1", "Storyblok API Token", "r2AnYNCfmH4V9Wo1EqvnSQtt", pattern,
		severity.High, severity.Tentative, "app.x.net", "https://app.x.net/app.js", "", "")
	if !strings.Contains(ev.Info.Description, "**Detection pattern:** `"+pattern+"`") {
		t.Errorf("description missing detection pattern; got:\n%s", ev.Info.Description)
	}
	// A blank pattern must not emit the line.
	noPat := NewSecretFinding("kingfisher.storyblok.1", "Storyblok API Token", "r2AnYNCfmH4V9Wo1EqvnSQtt", "",
		severity.High, severity.Tentative, "app.x.net", "https://app.x.net/app.js", "", "")
	if strings.Contains(noPat.Info.Description, "Detection pattern:") {
		t.Errorf("blank pattern should not emit a detection-pattern line; got:\n%s", noPat.Info.Description)
	}
}

func TestIsHexToken(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"9f86d081884c7d659a2feaa0c55ad015", true},  // 32 lowercase hex (MD5)
		{"DEADBEEFDEADBEEFDEADBEEFDEADBEEF", true},  // uppercase hex, 32
		{"9f86d081", false},                         // too short
		{"9f86d081884c7d659a2feaa0c55ad01z", false}, // 'z' is not hex
		{"", false},
	}
	for _, tc := range cases {
		if got := isHexToken(tc.in); got != tc.want {
			t.Errorf("isHexToken(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
