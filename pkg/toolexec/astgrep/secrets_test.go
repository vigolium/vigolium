package astgrep

import (
	"testing"
)

func TestStripQuotes(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`"secret"`, "secret"},
		{`'secret'`, "secret"},
		{"`secret`", "secret"},
		{`secret`, "secret"},
		{`""`, ""},
		{`"a"`, "a"},
		{``, ""},
		{`"mismatched'`, `"mismatched'`},
	}
	for _, tt := range tests {
		got := stripQuotes(tt.input)
		if got != tt.want {
			t.Errorf("stripQuotes(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractFramework(t *testing.T) {
	tests := []struct {
		ruleID string
		want   string
	}{
		{"security-secrets-express-jwt-js", "express"},
		{"security-secrets-django-secret-key", "django"},
		{"security-secrets-flask-secret-key", "flask"},
		{"security-secrets-rails-secret-key-base", "rails"},
		{"security-secrets-rack-session-secret", "rack"},
		{"security-secrets-laravel-app-key", "laravel"},
	}
	for _, tt := range tests {
		got := extractFramework(tt.ruleID)
		if got != tt.want {
			t.Errorf("extractFramework(%q) = %q, want %q", tt.ruleID, got, tt.want)
		}
	}
}

func TestCheckSecrets(t *testing.T) {
	matches := []Match{
		{
			ID:       "security-secrets-express-jwt-js",
			Text:     `jwt.sign(payload, "secret")`,
			Severity: "warning",
			MetaVariables: map[string]MetaVariable{
				"SECRET": {Text: `"secret"`},
			},
		},
		{
			ID:       "security-secrets-django-secret-key",
			Text:     `SECRET_KEY = "my-totally-unique-and-random-key-12345"`,
			Severity: "warning",
			MetaVariables: map[string]MetaVariable{
				"SECRET": {Text: `"my-totally-unique-and-random-key-12345"`},
			},
		},
		{
			// Not a security-secrets rule — should be skipped
			ID:       "security-config-hardcoded-secret-js",
			Text:     `const secret = "test"`,
			Severity: "error",
			MetaVariables: map[string]MetaVariable{
				"SECRET": {Text: `"test"`},
			},
		},
		{
			// Template interpolation — should be skipped
			ID:       "security-secrets-express-session-js",
			Text:     "session({ secret: `${prefix}key` })",
			Severity: "warning",
			MetaVariables: map[string]MetaVariable{
				"SECRET": {Text: "`${prefix}key`"},
			},
		},
		{
			// No SECRET metavariable — should be skipped
			ID:       "security-secrets-flask-secret-key",
			Text:     `app.secret_key = x`,
			Severity: "warning",
			MetaVariables: map[string]MetaVariable{
				"APP": {Text: "app"},
			},
		},
	}

	known, hardcoded := CheckSecrets(matches)

	// "secret" is in the jwt.secrets.list wordlist
	if len(known) != 1 {
		t.Fatalf("expected 1 known default, got %d", len(known))
	}
	if known[0].SecretValue != "secret" {
		t.Errorf("expected known secret value 'secret', got %q", known[0].SecretValue)
	}
	if known[0].Framework != "express" {
		t.Errorf("expected framework 'express', got %q", known[0].Framework)
	}
	if !known[0].KnownWeak {
		t.Error("expected KnownWeak=true for known default")
	}

	// "my-totally-unique-and-random-key-12345" should NOT be in the wordlist
	if len(hardcoded) != 1 {
		t.Fatalf("expected 1 hardcoded value, got %d", len(hardcoded))
	}
	if hardcoded[0].SecretValue != "my-totally-unique-and-random-key-12345" {
		t.Errorf("expected hardcoded value, got %q", hardcoded[0].SecretValue)
	}
	if hardcoded[0].KnownWeak {
		t.Error("expected KnownWeak=false for hardcoded (non-wordlist) value")
	}
}

func TestCheckSecretsEmpty(t *testing.T) {
	known, hardcoded := CheckSecrets(nil)
	if known != nil || hardcoded != nil {
		t.Error("expected nil slices for nil input")
	}

	known, hardcoded = CheckSecrets([]Match{})
	if known != nil || hardcoded != nil {
		t.Error("expected nil slices for empty input")
	}
}

func TestIsKnownSecret(t *testing.T) {
	// These are common entries in jwt.secrets.list
	knownValues := []string{"secret", "password", "changeme", "supersecret"}
	for _, v := range knownValues {
		if !isKnownSecret(v) {
			t.Errorf("expected %q to be a known secret", v)
		}
	}

	// This should not be in the wordlist
	if isKnownSecret("xK9$mP2!vR7@nQ4&wL6#jF8*cB3^hT5") {
		t.Error("random string should not be a known secret")
	}
}
