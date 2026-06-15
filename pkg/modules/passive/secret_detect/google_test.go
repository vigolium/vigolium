package secret_detect

import "testing"

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
	// when Kingfisher mislabels a Maps key as "Google Gemini API Key".
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

func TestSecretFindingDescription(t *testing.T) {
	if got := secretFindingDescription("reCAPTCHA API Key", "6Le3..."); got != recaptchaSiteKeyDescription {
		t.Errorf("reCAPTCHA description = %q, want the reCAPTCHA site-key description", got)
	}
	if got := secretFindingDescription("Google Gemini API Key", "AIzaSyCgRrs0DnYlw1GOmr5iuZu5CCnM69hqZCQ"); got != googleAPIKeyDescription {
		t.Errorf("Google AIza description = %q, want the Google API-key description", got)
	}
	if got, want := secretFindingDescription("AWS Access Key", "AKIA..."), "Leaked secret detected: AWS Access Key"; got != want {
		t.Errorf("default description = %q, want %q", got, want)
	}
}
