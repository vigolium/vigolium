package config

import (
	"os"
	"testing"
)

func TestExpandEnvVars(t *testing.T) {
	const testVar = "VIGOLIUM_TEST_EXPAND_VAR"

	tests := []struct {
		name   string
		input  string
		envVal string // empty means unset
		want   string
	}{
		{
			name:   "plain string no vars",
			input:  "oast.pro",
			want:   "oast.pro",
		},
		{
			name:   "simple var set",
			input:  "${VIGOLIUM_TEST_EXPAND_VAR}",
			envVal: "custom.server",
			want:   "custom.server",
		},
		{
			name:  "simple var unset",
			input: "${VIGOLIUM_TEST_EXPAND_VAR}",
			want:  "",
		},
		{
			name:   "default when var is set",
			input:  "${VIGOLIUM_TEST_EXPAND_VAR:-fallback}",
			envVal: "custom.server",
			want:   "custom.server",
		},
		{
			name:  "default when var is unset",
			input: "${VIGOLIUM_TEST_EXPAND_VAR:-fallback}",
			want:  "fallback",
		},
		{
			name:  "empty default when var is unset",
			input: "${VIGOLIUM_TEST_EXPAND_VAR:-}",
			want:  "",
		},
		{
			name:  "default with special chars",
			input: "${VIGOLIUM_TEST_EXPAND_VAR:-https://oast.example.com}",
			want:  "https://oast.example.com",
		},
		{
			name:   "mixed text and var with default",
			input:  "server: ${VIGOLIUM_TEST_EXPAND_VAR:-oast.pro}:443",
			envVal: "my.server",
			want:   "server: my.server:443",
		},
		{
			name:  "multiple vars with defaults",
			input: "${VIGOLIUM_TEST_EXPAND_VAR:-a}/${VIGOLIUM_TEST_EXPAND_VAR:-b}",
			want:  "a/b",
		},
		{
			name:   "dollar-var syntax (no default support)",
			input:  "$VIGOLIUM_TEST_EXPAND_VAR",
			envVal: "val",
			want:   "val",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv(testVar)
			if tt.envVal != "" {
				t.Setenv(testVar, tt.envVal)
			}

			got := ExpandEnvVars(tt.input)
			if got != tt.want {
				t.Errorf("ExpandEnvVars(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
