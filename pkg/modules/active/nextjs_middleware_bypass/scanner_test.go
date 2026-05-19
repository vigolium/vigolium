package nextjs_middleware_bypass

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

func TestIsLoginOrErrorPage(t *testing.T) {
	tests := []struct {
		body string
		want bool
	}{
		{"please log in to continue", true},
		{"/login?redirect=/admin", true},
		{"page not found", true},
		{"404 error", true},
		{"welcome to admin dashboard", false},
		{"user profile settings", false},
	}
	for _, tt := range tests {
		got := isLoginOrErrorPage(tt.body)
		if got != tt.want {
			t.Errorf("isLoginOrErrorPage(%q) = %v, want %v", tt.body, got, tt.want)
		}
	}
}

func TestPayloadTransforms(t *testing.T) {
	for _, pp := range pathPayloads {
		result := pp.transform("/admin")
		if result == "" {
			t.Errorf("transform(%q) returned empty string for %s", "/admin", pp.desc)
		}
	}
}
