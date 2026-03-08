package nextjs_data_leakage

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
)

func TestNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.ID() != ModuleID {
		t.Errorf("ID = %q, want %q", m.ID(), ModuleID)
	}
	if m.Name() != ModuleName {
		t.Errorf("Name = %q, want %q", m.Name(), ModuleName)
	}
}

func TestBuildIDRegex(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`"buildId":"abc123"`, "abc123"},
		{`"buildId": "my-build-456"`, "my-build-456"},
		{`no match`, ""},
	}
	for _, tt := range tests {
		m := jsframework.BuildIDRegex.FindStringSubmatch(tt.input)
		got := ""
		if len(m) > 1 {
			got = m[1]
		}
		if got != tt.want {
			t.Errorf("input=%q: got %q, want %q", tt.input, got, tt.want)
		}
	}
}
