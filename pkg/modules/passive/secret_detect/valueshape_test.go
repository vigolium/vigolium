package secret_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestIsValueShapeNoise(t *testing.T) {
	tests := []struct {
		name     string
		ruleName string
		secret   string
		want     bool
	}{
		{
			name:     "reCAPTCHA site key on a non-reCAPTCHA rule is noise",
			ruleName: "Identified an AWS secret access key",
			secret:   "6LfnSAoUAAAAAG49XsPZF3YJHzE3KiAuQuoivYZb",
			want:     true,
		},
		{
			name:     "reCAPTCHA-shaped value on the reCAPTCHA rule is NOT dropped here (severity layer handles it)",
			ruleName: "Google reCAPTCHA site key",
			secret:   "6LfnSAoUAAAAAG49XsPZF3YJHzE3KiAuQuoivYZb",
			want:     false,
		},
		{
			name:     "HTML/markup fragment is noise",
			ruleName: "Generic Username and Password",
			secret:   `":"1234"}</li>`,
			want:     true,
		},
		{
			// The roche-component-library FP: a Stencil kebab-case attribute name
			// captured by the generic username/password proximity rule.
			name:     "kebab-case UI label slug on the generic credential rule is noise",
			ruleName: "Generic Username and Password",
			secret:   "label-password",
			want:     true,
		},
		{
			name:     "long kebab-case label slug on the generic credential rule is noise",
			ruleName: "Generic Username and Password",
			secret:   "label-unmatched-passwords",
			want:     true,
		},
		{
			name:     "camelCase prop identifier on the generic credential rule is noise",
			ruleName: "Generic Username and Password",
			secret:   "passwordConfirm",
			want:     true,
		},
		{
			name:     "snake_case identifier on the generic password rule is noise",
			ruleName: "Generic Password",
			secret:   "label_password_confirm",
			want:     true,
		},
		{
			// The slug guard is scoped to the generic-credential family: a clean
			// word-identifier captured by a provider-specific rule is left alone.
			name:     "identifier slug on a non-generic rule is NOT dropped here",
			ruleName: "Detected a Generic API Key",
			secret:   "label-password",
			want:     false,
		},
		{
			// A real low-entropy password with a digit is not an identifier slug.
			name:     "password with a digit on the generic credential rule is kept",
			ruleName: "Generic Username and Password",
			secret:   "hunter2000",
			want:     false,
		},
		{
			// A single unbroken lowercase word has no boundary — kept.
			name:     "single-word lowercase password on the generic rule is kept",
			ruleName: "Generic Password",
			secret:   "correcthorsebattery",
			want:     false,
		},
		{
			name:     "value with whitespace is noise",
			ruleName: "Generic Password",
			secret:   "correct horse battery",
			want:     true,
		},
		{
			name:     "JS object fragment is noise",
			ruleName: "Detected a Generic API Key",
			secret:   "overrideMbox(1)",
			want:     true,
		},
		{
			name:     "clean opaque token is not noise",
			ruleName: "Generic Password",
			secret:   "Sk9fLp2Qw7Zx4Rt8Yv3Bn6Mc1Ha5Ke",
			want:     false,
		},
		{
			name:     "connection-string-shaped value is not noise (`:` `@` `/` allowed)",
			ruleName: "Generic Database URL",
			secret:   "postgres://user:s3cr3tPass@db.internal:5432/app",
			want:     false,
		},
		{
			name:     "base64 token with trailing padding is not noise",
			ruleName: "Generic API Key",
			secret:   "aGVsbG93b3JsZHNlY3JldA==",
			want:     false,
		},
		{
			name:     "blank value is not noise",
			ruleName: "Generic Password",
			secret:   "   ",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValueShapeNoise(tt.ruleName, tt.secret); got != tt.want {
				t.Errorf("IsValueShapeNoise(%q, %q) = %v, want %v", tt.ruleName, tt.secret, got, tt.want)
			}
		})
	}
}

func TestIsIdentifierSlug(t *testing.T) {
	// Word-only identifiers with a boundary — the FP shapes from the compiled
	// roche-component-library bundle.
	slugs := []string{
		"label-password", "label-password-confirm", "label-unmatched-passwords",
		"passwordConfirm", "label_username", "AdminUser",
	}
	for _, s := range slugs {
		assert.Truef(t, isIdentifierSlug(s), "%q should read as an identifier slug", s)
	}
	// Not slugs: a digit/symbol carries entropy, or there's no word boundary.
	notSlugs := []string{
		"hunter2", "P@ssw0rd", "Sk9fLp2Qw7Zx4Rt8Yv3Bn6Mc", // digit / symbol
		"admin", "correcthorsebattery", "PASSWORD", // single unbroken word (no lower→upper transition)
		"",
	}
	for _, s := range notSlugs {
		assert.Falsef(t, isIdentifierSlug(s), "%q should NOT read as an identifier slug", s)
	}
}

func TestIsReCaptchaSiteKeyShape(t *testing.T) {
	assert.True(t, isReCaptchaSiteKeyShape("6LfnSAoUAAAAAG49XsPZF3YJHzE3KiAuQuoivYZb"))
	assert.True(t, isReCaptchaSiteKeyShape("6Lc-1234567890abcdefABCDEF_-1234567890ab"))
	assert.False(t, isReCaptchaSiteKeyShape("6LfnSAoUAAAAAG49XsPZF3YJHzE3KiAuQuoivYZ"), "39 chars is wrong length")
	assert.False(t, isReCaptchaSiteKeyShape("7LfnSAoUAAAAAG49XsPZF3YJHzE3KiAuQuoivYZb"), "wrong prefix")
	assert.False(t, isReCaptchaSiteKeyShape("6LfnSAoUAAAAAG49XsPZF3YJHzE3KiAuQuoiv=Zb"), "illegal char")
}

// TestModule_ValueShapeGuardDropsGenericMarkup proves the guard drops a
// code/markup-shaped capture from a low-confidence generic rule end-to-end,
// while a clean opaque token in the same generic context still surfaces (as
// Suspect). This is the r2 "Generic Username and Password on page markup" FP.
func TestModule_ValueShapeGuardDropsGenericMarkup(t *testing.T) {
	m := New()

	markup := `{"username":"admin","password":"</b>{tok}</b>"} more text here`
	ctx := makeHTTPCtx("text/html", markup)
	findings, err := m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, findings, "code/markup-shaped generic capture must be dropped, got %v", findingValues(findings))

	clean := `username: admin password: Sk9fLp2Qw7Zx4Rt8Yv3Bn6Mc1Ha5Ke more`
	ctx = makeHTTPCtx("text/html", clean)
	findings, err = m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "a clean opaque token from the same generic rule should still be reported")
	assert.Equal(t, severity.Suspect, findings[0].Info.Severity, "a low-confidence generic match is Suspect, not High")
}

// TestModule_ValueShapeGuardDropsComponentLabelSlug reproduces the
// roche-component-library FP: a compiled Stencil web-component bundle whose prop
// metadata lists `labelUsername`/`labelPassword` next to their kebab-case
// attribute names. The generic username/password proximity rule captures the
// `label-password` attribute name — a UI identifier, not a credential — which the
// identifier-slug guard now drops.
func TestModule_ValueShapeGuardDropsComponentLabelSlug(t *testing.T) {
	m := New()

	bundle := `qs("roche-login",{labelUsername:[1,"label-username"],labelPassword:[1,"label-password"],labelSubmit:[1,"label-submit"]});`
	ctx := makeHTTPCtx("text/javascript", bundle)
	findings, err := m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, findings, "component-label identifier slug must be dropped, got %v", findingValues(findings))
}
