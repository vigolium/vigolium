package secret_detect

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestSecretFindingSeverity(t *testing.T) {
	tests := []struct {
		name             string
		validated        bool
		redirect         bool
		inHeader         bool
		lowValueJWT      bool
		recaptchaSiteKey bool
		googleAPIKey     bool
		wantSev          severity.Severity
		wantConf         severity.Confidence
	}{
		{
			name:     "plain body match is High/Firm",
			wantSev:  severity.High,
			wantConf: severity.Firm,
		},
		{
			name:     "redirect downgrades to Low/Tentative",
			redirect: true,
			wantSev:  severity.Low,
			wantConf: severity.Tentative,
		},
		{
			name:     "header reflection downgrades to Low/Tentative",
			inHeader: true,
			wantSev:  severity.Low,
			wantConf: severity.Tentative,
		},
		{
			name:        "low-value JWT downgrades to Medium/Tentative",
			lowValueJWT: true,
			wantSev:     severity.Medium,
			wantConf:    severity.Tentative,
		},
		{
			name:         "Google API key downgrades to Medium/Firm",
			googleAPIKey: true,
			wantSev:      severity.Medium,
			wantConf:     severity.Firm,
		},
		{
			name:             "reCAPTCHA site key downgrades to Info/Tentative",
			recaptchaSiteKey: true,
			wantSev:          severity.Info,
			wantConf:         severity.Tentative,
		},
		{
			name:             "reCAPTCHA site key outranks validation (stays Info)",
			recaptchaSiteKey: true,
			validated:        true,
			wantSev:          severity.Info,
			wantConf:         severity.Tentative,
		},
		{
			name:         "validation outranks Google API key (stays Critical)",
			googleAPIKey: true,
			validated:    true,
			wantSev:      severity.Critical,
			wantConf:     severity.Certain,
		},
		{
			name:         "redirect outranks Google API key (stays Low)",
			googleAPIKey: true,
			redirect:     true,
			wantSev:      severity.Low,
			wantConf:     severity.Tentative,
		},
		{
			name:        "redirect outranks low-value JWT (stays Low/Tentative)",
			redirect:    true,
			lowValueJWT: true,
			wantSev:     severity.Low,
			wantConf:    severity.Tentative,
		},
		{
			name:      "validated live secret stays Critical even on a redirect",
			validated: true,
			redirect:  true,
			inHeader:  true,
			wantSev:   severity.Critical,
			wantConf:  severity.Certain,
		},
		{
			name:      "validated live secret in body is Critical",
			validated: true,
			wantSev:   severity.Critical,
			wantConf:  severity.Certain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSev, gotConf := SecretFindingSeverity(tt.validated, tt.redirect, tt.inHeader, tt.lowValueJWT, tt.recaptchaSiteKey, tt.googleAPIKey)
			if gotSev != tt.wantSev {
				t.Errorf("severity = %v, want %v", gotSev, tt.wantSev)
			}
			if gotConf != tt.wantConf {
				t.Errorf("confidence = %v, want %v", gotConf, tt.wantConf)
			}
		})
	}
}

func TestIsRedirectStatus(t *testing.T) {
	redirects := []int{300, 301, 302, 303, 307, 308, 399}
	for _, code := range redirects {
		if !IsRedirectStatus(code) {
			t.Errorf("IsRedirectStatus(%d) = false, want true", code)
		}
	}
	nonRedirects := []int{0, 199, 200, 204, 299, 400, 401, 403, 404, 500, 502}
	for _, code := range nonRedirects {
		if IsRedirectStatus(code) {
			t.Errorf("IsRedirectStatus(%d) = true, want false", code)
		}
	}
}

func TestSnippetInHeaderValues(t *testing.T) {
	headers := []httpmsg.HttpHeader{
		{Name: "Content-Type", Value: "text/html"},
		{Name: "Location", Value: "https://sso.example.com/auth?client_id=12345.apps.googleusercontent.com&state=abc"},
	}
	blob := JoinHeaderValues(headers)

	tests := []struct {
		name    string
		snippet string
		blob    string
		want    bool
	}{
		{
			name:    "secret reflected in Location header",
			snippet: "12345.apps.googleusercontent.com",
			blob:    blob,
			want:    true,
		},
		{
			name:    "snippet with surrounding whitespace still matches",
			snippet: "  12345.apps.googleusercontent.com  ",
			blob:    blob,
			want:    true,
		},
		{
			name:    "secret only in body, not in any header",
			snippet: "AKIAIOSFODNN7EXAMPLE",
			blob:    blob,
			want:    false,
		},
		{
			name:    "blank snippet never matches",
			snippet: "   ",
			blob:    blob,
			want:    false,
		},
		{
			name:    "no headers never matches",
			snippet: "12345.apps.googleusercontent.com",
			blob:    "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SnippetInHeaderValues(tt.snippet, tt.blob); got != tt.want {
				t.Errorf("SnippetInHeaderValues(%q, ...) = %v, want %v", tt.snippet, got, tt.want)
			}
		})
	}
}

func TestJoinHeaderValues(t *testing.T) {
	if got := JoinHeaderValues(nil); got != "" {
		t.Errorf("JoinHeaderValues(nil) = %q, want empty", got)
	}
	headers := []httpmsg.HttpHeader{
		{Name: "X-A", Value: "alpha"},
		{Name: "X-B", Value: "beta"},
	}
	got := JoinHeaderValues(headers)
	if want := "alpha\nbeta\n"; got != want {
		t.Errorf("JoinHeaderValues = %q, want %q", got, want)
	}
}
