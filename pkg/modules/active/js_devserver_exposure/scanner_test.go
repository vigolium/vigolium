package js_devserver_exposure

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

func TestDevProbes(t *testing.T) {
	if len(devProbes) == 0 {
		t.Fatal("expected at least one dev probe")
	}
	for _, p := range devProbes {
		if p.path == "" {
			t.Error("probe path is empty")
		}
		if p.name == "" {
			t.Error("probe name is empty")
		}
		if p.desc == "" {
			t.Errorf("probe %q has no description", p.name)
		}
	}
}
