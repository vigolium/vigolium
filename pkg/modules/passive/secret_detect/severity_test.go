package secret_detect

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestSecretFindingSeverity(t *testing.T) {
	tests := []struct {
		name                 string
		trusted              bool
		generic              bool
		validated            bool
		redirect             bool
		inHeader             bool
		reflectedFromRequest bool
		docDemoContext       bool
		lowValueJWT          bool
		recaptchaSiteKey     bool
		googleAPIKey         bool
		oauthClientID        bool
		wantSev              severity.Severity
		wantConf             severity.Confidence
	}{
		// --- trusted tier (high-confidence kingfisher rule): High baseline, full
		// downgrade nuance preserved. ---
		{
			name:     "trusted plain body match is High/Firm",
			trusted:  true,
			wantSev:  severity.High,
			wantConf: severity.Firm,
		},
		{
			name:     "trusted redirect downgrades to Low/Tentative",
			trusted:  true,
			redirect: true,
			wantSev:  severity.Low,
			wantConf: severity.Tentative,
		},
		{
			name:     "trusted header reflection downgrades to Low/Tentative",
			trusted:  true,
			inHeader: true,
			wantSev:  severity.Low,
			wantConf: severity.Tentative,
		},
		{
			name:                 "trusted request-URL reflection downgrades to Low/Tentative",
			trusted:              true,
			reflectedFromRequest: true,
			wantSev:              severity.Low,
			wantConf:             severity.Tentative,
		},
		{
			name:           "trusted docs-page demo secret downgrades to Low/Tentative",
			trusted:        true,
			docDemoContext: true,
			wantSev:        severity.Low,
			wantConf:       severity.Tentative,
		},
		{
			name:           "trusted docs demo context outranks Google API key (stays Low)",
			trusted:        true,
			docDemoContext: true,
			googleAPIKey:   true,
			wantSev:        severity.Low,
			wantConf:       severity.Tentative,
		},
		{
			name:           "trusted docs demo context outranks low-value JWT (stays Low)",
			trusted:        true,
			docDemoContext: true,
			lowValueJWT:    true,
			wantSev:        severity.Low,
			wantConf:       severity.Tentative,
		},
		{
			name:        "trusted low-value JWT caps at Medium/Tentative",
			trusted:     true,
			lowValueJWT: true,
			wantSev:     severity.Medium,
			wantConf:    severity.Tentative,
		},
		{
			name:         "trusted Google API key caps at Medium/Firm",
			trusted:      true,
			googleAPIKey: true,
			wantSev:      severity.Medium,
			wantConf:     severity.Firm,
		},
		{
			name:         "trusted redirect outranks Google API key (stays Low)",
			trusted:      true,
			googleAPIKey: true,
			redirect:     true,
			wantSev:      severity.Low,
			wantConf:     severity.Tentative,
		},

		// --- named-family tier (non-trusted, non-generic provider rule, e.g.
		// Storyblok / Bitfinex / Google Gemini): High baseline at Tentative, with
		// the Low/Medium downgrade ceilings now ACTIVE (they sit below High). ---
		{
			name:     "named family plain body match is High/Tentative",
			wantSev:  severity.High,
			wantConf: severity.Tentative,
		},
		{
			name:     "named family redirect downgrades to Low/Tentative",
			redirect: true,
			wantSev:  severity.Low,
			wantConf: severity.Tentative,
		},
		{
			name:                 "named family request reflection downgrades to Low/Tentative",
			reflectedFromRequest: true,
			wantSev:              severity.Low,
			wantConf:             severity.Tentative,
		},
		{
			name:           "named family docs demo context downgrades to Low/Tentative",
			docDemoContext: true,
			wantSev:        severity.Low,
			wantConf:       severity.Tentative,
		},
		{
			name:         "named family Google API key caps at Medium/Firm",
			googleAPIKey: true,
			wantSev:      severity.Medium,
			wantConf:     severity.Firm,
		},
		{
			name:         "named family Google API key on a redirect drops to Low",
			googleAPIKey: true,
			redirect:     true,
			wantSev:      severity.Low,
			wantConf:     severity.Tentative,
		},
		{
			name:        "named family low-value JWT caps at Medium/Tentative",
			lowValueJWT: true,
			wantSev:     severity.Medium,
			wantConf:    severity.Tentative,
		},

		// --- generic tier (family-less "Generic Password"/"Generic API Key"
		// matcher): Suspect baseline; the Low/Medium downgrade signals never PROMOTE
		// it above Suspect. ---
		{
			name:     "generic plain body match is Suspect/Tentative",
			generic:  true,
			wantSev:  severity.Suspect,
			wantConf: severity.Tentative,
		},
		{
			name:     "generic redirect stays Suspect (never promoted to Low)",
			generic:  true,
			redirect: true,
			wantSev:  severity.Suspect,
			wantConf: severity.Tentative,
		},
		{
			name:                 "generic request reflection stays Suspect",
			generic:              true,
			reflectedFromRequest: true,
			wantSev:              severity.Suspect,
			wantConf:             severity.Tentative,
		},
		{
			name:           "generic docs demo context stays Suspect",
			generic:        true,
			docDemoContext: true,
			wantSev:        severity.Suspect,
			wantConf:       severity.Tentative,
		},
		{
			name:         "generic Google API key stays Suspect",
			generic:      true,
			googleAPIKey: true,
			wantSev:      severity.Suspect,
			wantConf:     severity.Tentative,
		},
		{
			name:        "generic low-value JWT stays Suspect",
			generic:     true,
			lowValueJWT: true,
			wantSev:     severity.Suspect,
			wantConf:    severity.Tentative,
		},

		// --- validation: Critical anywhere (unreachable today, but tier-independent). ---
		{
			name:      "validated live secret in body is Critical",
			validated: true,
			wantSev:   severity.Critical,
			wantConf:  severity.Certain,
		},
		{
			name:                 "validation outranks request reflection (stays Critical)",
			reflectedFromRequest: true,
			validated:            true,
			wantSev:              severity.Critical,
			wantConf:             severity.Certain,
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
			name:         "validation outranks Google API key (stays Critical)",
			googleAPIKey: true,
			validated:    true,
			wantSev:      severity.Critical,
			wantConf:     severity.Certain,
		},

		// --- public identifiers: Info regardless of tier or validation. ---
		{
			name:             "reCAPTCHA site key is Info/Tentative (untrusted)",
			recaptchaSiteKey: true,
			wantSev:          severity.Info,
			wantConf:         severity.Tentative,
		},
		{
			name:             "reCAPTCHA site key is Info even on a trusted rule",
			trusted:          true,
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
			name:          "OAuth client ID is Info/Tentative",
			oauthClientID: true,
			wantSev:       severity.Info,
			wantConf:      severity.Tentative,
		},
		{
			name:          "OAuth client ID outranks validation (public by design, stays Info)",
			oauthClientID: true,
			validated:     true,
			wantSev:       severity.Info,
			wantConf:      severity.Tentative,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSev, gotConf := SecretFindingSeverity(tt.trusted, tt.generic, tt.validated, tt.redirect, tt.inHeader, tt.reflectedFromRequest, tt.docDemoContext, tt.lowValueJWT, tt.recaptchaSiteKey, tt.googleAPIKey, tt.oauthClientID)
			if gotSev != tt.wantSev {
				t.Errorf("severity = %v, want %v", gotSev, tt.wantSev)
			}
			if gotConf != tt.wantConf {
				t.Errorf("confidence = %v, want %v", gotConf, tt.wantConf)
			}
		})
	}
}

func TestIsDocDemoSecretContext(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		contentType string
		want        bool
	}{
		{
			// The real-world case: Supabase demo creds on a CLI docs page, served
			// as a Next.js RSC (?_rsc=) payload.
			name:        "docs/reference/cli RSC page is demo context",
			url:         "https://cloud.example.com/docs/reference/cli/introduction?_rsc=1p-R_iEY6bj0jY31",
			contentType: "text/x-component",
			want:        true,
		},
		{
			name:        "docs page served as HTML is demo context",
			url:         "https://cloud.example.com/docs/guides/getting-started",
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "manual route HTML is demo context",
			url:         "https://acme.example.com/manual/config",
			contentType: "text/html",
			want:        true,
		},
		{
			// A JWT inside a JS bundle under /docs/_next/... is a real embedded
			// credential, not page prose — must NOT be downgraded.
			name:        "JS bundle under a docs path is not demo context",
			url:         "https://cloud.example.com/docs/_next/static/chunks/3318-b4ad80c3468c46cc.js",
			contentType: "application/javascript; charset=utf-8",
			want:        false,
		},
		{
			name:        "docs JSON API response is not demo context",
			url:         "https://api.example.com/docs/config.json",
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "non-docs HTML page is not demo context",
			url:         "https://example.com/account/settings",
			contentType: "text/html",
			want:        false,
		},
		{
			// "client" must not be mistaken for the "cli" segment.
			name:        "client segment does not match cli",
			url:         "https://example.com/client/dashboard",
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "docs path with empty content type is not demo context",
			url:         "https://example.com/docs/intro",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDocDemoSecretContext(tt.url, tt.contentType); got != tt.want {
				t.Errorf("IsDocDemoSecretContext(%q, %q) = %v, want %v", tt.url, tt.contentType, got, tt.want)
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

func TestSnippetReflectedFromRequest(t *testing.T) {
	// The Cloudflare Access SSO case: the app id sits in the verify-code URL
	// path and is reflected into the login page body, where a generic
	// Cloudflare-token rule matches it.
	const appID = "abc84c1452a446328be5a8141b812b7f-acmeapp"
	const ssoURL = "https://acme-code.cloudflareaccess.com/cdn-cgi/access/verify-code/" + appID + "-p.pages.example.com?kid=46de"
	const ssoRequest = "GET /cdn-cgi/access/verify-code/" + appID + "-p.pages.example.com HTTP/1.1\r\nHost: acme-code.cloudflareaccess.com\r\n\r\n"

	tests := []struct {
		name       string
		snippet    string
		requestURL string
		rawRequest string
		want       bool
	}{
		{
			name:       "app id reflected from request URL",
			snippet:    appID,
			requestURL: ssoURL,
			want:       true,
		},
		{
			name:       "value reflected from raw request only",
			snippet:    appID,
			rawRequest: ssoRequest,
			want:       true,
		},
		{
			name:       "snippet with surrounding whitespace still matches",
			snippet:    "  " + appID + "  ",
			requestURL: ssoURL,
			want:       true,
		},
		{
			name:       "genuine server secret absent from the request is not a reflection",
			snippet:    "AKIAIOSFODNN7EXAMPLE",
			requestURL: ssoURL,
			rawRequest: ssoRequest,
			want:       false,
		},
		{
			name:    "blank snippet never matches",
			snippet: "   ",
			want:    false,
		},
		{
			name:    "empty request never matches",
			snippet: appID,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SnippetReflectedFromRequest(tt.snippet, tt.requestURL, tt.rawRequest); got != tt.want {
				t.Errorf("SnippetReflectedFromRequest(%q, ...) = %v, want %v", tt.snippet, got, tt.want)
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
