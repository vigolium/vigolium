package mass_assignment

import (
	"testing"
)

func TestToString(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"string value", "admin", `"admin"`},
		{"bool value", true, "true"},
		{"int value", 99, "99"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toString(tt.value)
			if got != tt.want {
				t.Errorf("toString(%v) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	m := New()
	if m.ID() != ModuleID {
		t.Errorf("ID() = %q, want %q", m.ID(), ModuleID)
	}
	if m.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", m.Name(), ModuleName)
	}
	if m.IncludesBaseCanProcess() {
		t.Error("IncludesBaseCanProcess() should return false")
	}
}
