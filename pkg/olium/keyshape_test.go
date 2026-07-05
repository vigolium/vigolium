package olium

import (
	"strings"
	"testing"
)

func TestValidateKeyShape(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		key      string
		wantErr  string // substring; empty = expect nil
	}{
		// happy paths
		{"openai with sk-or proxy key", "openai-api-key", "sk-or-v1-abc", ""},
		{"openai with sk-proj", "openai-api-key", "sk-proj-abcdef", ""},
		{"anthropic api key", "anthropic-api-key", "sk-ant-api03-abc", ""},
		{"anthropic oauth", "anthropic-oauth", "sk-ant-oat01-abc", ""},
		{"empty passthrough", "openai-api-key", "", ""},
		{"whitespace passthrough", "openai-api-key", "   ", ""},

		// openai-responses shares openai-api-key's key resolution + shape check
		{"openai-responses proxy key ok", "openai-responses", "sk-proj-abcdef", ""},
		{"anthropic key on openai-responses", "openai-responses", "sk-ant-api03-abc", "sk-ant-"},

		// cross-wires
		{"anthropic key on openai", "openai-api-key", "sk-ant-api03-abc", "sk-ant-"},
		{"anthropic oauth on openai", "openai-api-key", "sk-ant-oat01-abc", "sk-ant-"},
		{"oauth token on anthropic-api-key", "anthropic-api-key", "sk-ant-oat01-abc", "sk-ant-oat"},
		{"api key on anthropic-oauth", "anthropic-oauth", "sk-ant-api03-abc", "sk-ant-api"},

		// unexpanded env ref
		{"unexpanded env on openai", "openai-api-key", "${OPENAI_API_KEY}", "unexpanded"},
		{"unexpanded env on anthropic", "anthropic-api-key", "${ANTHROPIC_API_KEY}", "unexpanded"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateKeyShape(c.provider, c.key)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error %q does not contain %q", err, c.wantErr)
			}
		})
	}
}
