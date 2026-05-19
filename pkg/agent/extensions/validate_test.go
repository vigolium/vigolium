package extensions

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
)

func TestValidateExtensionSyntax(t *testing.T) {
	tests := []struct {
		name  string
		input []agenttypes.GeneratedExtension
		want  int
	}{
		{
			name: "valid JS passes",
			input: []agenttypes.GeneratedExtension{
				{Filename: "good.js", Code: "var x = 1;"},
			},
			want: 1,
		},
		{
			name: "invalid JS is dropped",
			input: []agenttypes.GeneratedExtension{
				{Filename: "bad.js", Code: "function(}{"},
			},
			want: 0,
		},
		{
			name: "empty code is dropped",
			input: []agenttypes.GeneratedExtension{
				{Filename: "empty.js", Code: "   "},
			},
			want: 0,
		},
		{
			name: "mix of valid and invalid",
			input: []agenttypes.GeneratedExtension{
				{Filename: "a.js", Code: "var a = 1;"},
				{Filename: "b.js", Code: "???"},
				{Filename: "c.js", Code: "var c = 2;"},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := ValidateExtensionSyntax(tt.input)
			if len(got) != tt.want {
				t.Errorf("ValidateExtensionSyntax() returned %d extensions, want %d", len(got), tt.want)
			}
		})
	}
}
