package secret_detect

import (
	"strings"
	"testing"
)

func TestIsReCaptchaSiteKey(t *testing.T) {
	cases := []struct {
		ruleName string
		want     bool
	}{
		{"reCAPTCHA API Key", true},
		{"Google reCAPTCHA Key", true},
		{"RECAPTCHA SITE KEY", true},
		{"Google API Key", false},
		{"Google Gemini API Key", false},
		{"AWS Access Key", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsReCaptchaSiteKey(c.ruleName); got != c.want {
			t.Errorf("IsReCaptchaSiteKey(%q) = %v, want %v", c.ruleName, got, c.want)
		}
	}
}

func TestIsGoogleAPIKey(t *testing.T) {
	// The AIza prefix is the strongest signal — it identifies the family even
	// when the rule mislabels a Maps key as "Google Gemini API Key".
	const mapsKey = "AIzaSyCgRrs0DnYlw1GOmr5iuZu5CCnM69hqZCQ"

	cases := []struct {
		name     string
		ruleName string
		snippet  string
		want     bool
	}{
		{"AIza snippet under Gemini label", "Google Gemini API Key", mapsKey, true},
		{"AIza snippet with whitespace", "Generic Secret", "  " + mapsKey + "  ", true},
		{"Google Maps rule name", "Google Maps API Key", "", true},
		{"generic Google API Key rule", "Google API Key", "", true},
		// A Google OAuth client secret / service account is a real credential, not
		// the billing-abuse AIza family — must not be downgraded here.
		{"Google OAuth client secret stays out", "Google OAuth Client Secret", "GOCSPX-abc123", false},
		{"reCAPTCHA stays out", "reCAPTCHA API Key", "6Le3PjIUAAAAAA6qH0HYORp6HKJhdxxH3f5iuA1e", false},
		{"AWS key stays out", "AWS Access Key", "AKIAIOSFODNN7EXAMPLE", false},
	}
	for _, c := range cases {
		if got := IsGoogleAPIKey(c.ruleName, c.snippet); got != c.want {
			t.Errorf("%s: IsGoogleAPIKey(%q, %q) = %v, want %v", c.name, c.ruleName, c.snippet, got, c.want)
		}
	}
}

func TestIsGoogleOAuthClientID(t *testing.T) {
	cases := []struct {
		name    string
		snippet string
		want    bool
	}{
		{"real client ID", "384916164796-8rgnoe66fd9992r0oi4pvuq7c086brk8.apps.googleusercontent.com", true},
		{"client ID with surrounding whitespace", "  12345-abc.apps.googleusercontent.com  ", true},
		// The sensitive half of the pair must NOT be classified as the public ID.
		{"client secret stays out", "VfJASjhImoB6IErdcHR0DLt9", false},
		{"access token stays out", "ya29.GlskBNk6_nqhfOcJHvyoIAQoAkw95ulaGbENUBYy5", false},
		{"AIza API key stays out", "AIzaSyCgRrs0DnYlw1GOmr5iuZu5CCnM69hqZCQ", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		if got := IsGoogleOAuthClientID(c.snippet); got != c.want {
			t.Errorf("%s: IsGoogleOAuthClientID(%q) = %v, want %v", c.name, c.snippet, got, c.want)
		}
	}
}

func TestSecretFindingDescription(t *testing.T) {
	// Every description keeps its base text and ends with the matched value so
	// the leaked credential is visible in the finding body itself.
	if got := secretFindingDescription("reCAPTCHA API Key", "6Le3...", ""); !strings.HasPrefix(got, recaptchaSiteKeyDescription) || !strings.Contains(got, "**Matched value:** `6Le3...`") {
		t.Errorf("reCAPTCHA description = %q, want reCAPTCHA site-key text + matched value", got)
	}
	const aizaKey = "AIzaSyCgRrs0DnYlw1GOmr5iuZu5CCnM69hqZCQ"
	if got := secretFindingDescription("Google Gemini API Key", aizaKey, ""); !strings.HasPrefix(got, googleAPIKeyDescription) || !strings.Contains(got, "**Matched value:** `"+aizaKey+"`") {
		t.Errorf("Google AIza description = %q, want Google API-key text + matched value", got)
	}
	// The "Google OAuth Credentials" rule matches the public client ID: it gets
	// the client-ID explainer plus the matched value, not the generic line.
	const clientID = "384916164796-8rgnoe66fd9992r0oi4pvuq7c086brk8.apps.googleusercontent.com"
	if got := secretFindingDescription("Google OAuth Credentials", clientID, ""); !strings.HasPrefix(got, googleOAuthClientIDDescription) || !strings.Contains(got, "**Matched value:** `"+clientID+"`") {
		t.Errorf("OAuth client ID description = %q, want client-ID text + matched value", got)
	}
	// The paired client secret keeps the generic leaked-secret line (it is the
	// sensitive half and must not be reclassified as the public client ID).
	if got := secretFindingDescription("Google OAuth Client Secret", "VfJASjhImoB6IErdcHR0DLt9", ""); !strings.HasPrefix(got, "Leaked secret detected: Google OAuth Client Secret") || !strings.Contains(got, "**Matched value:** `VfJASjhImoB6IErdcHR0DLt9`") {
		t.Errorf("OAuth client secret description = %q, want generic line + matched value", got)
	}
	if got, want := secretFindingDescription("AWS Access Key", "AKIAIOSFODNN7EXAMPLE", ""),
		"Leaked secret detected: AWS Access Key\n\n**Matched value:** `AKIAIOSFODNN7EXAMPLE`"; got != want {
		t.Errorf("default description = %q, want %q", got, want)
	}
	// A blank snippet leaves the description unchanged (no trailing line).
	if got, want := secretFindingDescription("AWS Access Key", "", ""), "Leaked secret detected: AWS Access Key"; got != want {
		t.Errorf("blank-snippet description = %q, want %q", got, want)
	}
	// The detection pattern is appended after the matched value when present.
	if got := secretFindingDescription("AWS Access Key", "AKIAIOSFODNN7EXAMPLE", `AKIA[0-9A-Z]{16}`); !strings.HasSuffix(got, "\n\n**Detection pattern:** `AKIA[0-9A-Z]{16}`") {
		t.Errorf("description should end with the detection pattern; got %q", got)
	}
}

func TestAppendMatchedValueTruncatesLongValues(t *testing.T) {
	long := strings.Repeat("a", matchedValueMaxLen+50)
	got := appendMatchedValue("base", long)
	if !strings.Contains(got, "…") {
		t.Errorf("long value should be truncated with an ellipsis: %q", got)
	}
	if strings.Contains(got, long) {
		t.Errorf("full long value should not be inlined verbatim")
	}
}
