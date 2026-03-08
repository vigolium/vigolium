package oast_probe

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestModuleMetadata(t *testing.T) {
	m := New()

	if m.ID() != ModuleID {
		t.Errorf("ID() = %q, want %q", m.ID(), ModuleID)
	}
	if m.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", m.Name(), ModuleName)
	}
	if m.Severity() != ModuleSeverity {
		t.Errorf("Severity() = %v, want %v", m.Severity(), ModuleSeverity)
	}
	if m.Confidence() != ModuleConfidence {
		t.Errorf("Confidence() = %v, want %v", m.Confidence(), ModuleConfidence)
	}
}

func TestCanProcessNilRequest(t *testing.T) {
	m := New()
	if m.CanProcess(nil) {
		t.Error("CanProcess(nil) should return false")
	}
}

func TestLooksLikeURLParam(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"url", "http://example.com", true},
		{"redirect_url", "", true},
		{"callback", "", true},
		{"src", "", true},
		{"page", "", true},
		{"id", "123", false},
		{"name", "test", false},
		{"q", "search term", false},
		{"ref", "http://example.com", true},      // value starts with http://
		{"data", "https://example.com/api", true}, // value starts with https://
		{"next", "//cdn.example.com", true},       // value starts with //
	}

	for _, tt := range tests {
		got := looksLikeURLParam(tt.name, tt.value)
		if got != tt.want {
			t.Errorf("looksLikeURLParam(%q, %q) = %v, want %v", tt.name, tt.value, got, tt.want)
		}
	}
}

func TestScanPerRequestNoOAST(t *testing.T) {
	m := New()
	// ScanContext with nil OAST provider should return nil results
	scanCtx := &modkit.ScanContext{}
	results, err := m.ScanPerRequest(nil, nil, scanCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Error("expected nil results when OAST provider is nil")
	}
}
