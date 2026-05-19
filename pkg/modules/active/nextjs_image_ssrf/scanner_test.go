package nextjs_image_ssrf

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

func TestInBandProbes(t *testing.T) {
	if len(inBandProbes) == 0 {
		t.Fatal("expected at least one in-band probe")
	}
	for _, p := range inBandProbes {
		if p.url == "" {
			t.Error("probe URL is empty")
		}
		if len(p.markers) == 0 {
			t.Errorf("probe %q has no markers", p.url)
		}
	}
}
