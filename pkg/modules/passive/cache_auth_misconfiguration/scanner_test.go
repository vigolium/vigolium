package cache_auth_misconfiguration

import (
	"testing"
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

func TestIsCacheable(t *testing.T) {
	tests := []struct {
		cc   string
		want bool
	}{
		{"public, max-age=3600", true},
		{"s-maxage=600", true},
		{"private, max-age=3600", false},
		{"no-store", false},
		{"no-store, public", false},
		{"max-age=0", false},
		{"public, no-store", false},
	}
	for _, tt := range tests {
		got := isCacheable(tt.cc)
		if got != tt.want {
			t.Errorf("isCacheable(%q) = %v, want %v", tt.cc, got, tt.want)
		}
	}
}
