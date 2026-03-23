package codexsdk

import (
	"slices"
	"testing"
)

func TestOptions_BuildArgs_Default(t *testing.T) {
	opts := &Options{}
	args := opts.buildArgs()

	// Must always include app-server --listen stdio://
	if !slices.Contains(args, "app-server") {
		t.Error("args should contain 'app-server'")
	}
	if !slices.Contains(args, "--listen") {
		t.Error("args should contain '--listen'")
	}
	if !slices.Contains(args, "stdio://") {
		t.Error("args should contain 'stdio://'")
	}
}

func TestOptions_BuildArgs_WithModel(t *testing.T) {
	opts := &Options{Model: "o3"}
	args := opts.buildArgs()

	// Model should be injected as --config model=o3 BEFORE app-server
	configIdx := slices.Index(args, "--config")
	appServerIdx := slices.Index(args, "app-server")

	if configIdx < 0 {
		t.Fatal("args should contain '--config'")
	}
	if appServerIdx < 0 {
		t.Fatal("args should contain 'app-server'")
	}
	if configIdx >= appServerIdx {
		t.Error("--config should come before app-server")
	}

	// The value after --config should be model=o3
	if configIdx+1 >= len(args) || args[configIdx+1] != "model=o3" {
		t.Errorf("expected 'model=o3' after --config, got args: %v", args)
	}
}

func TestOptions_BuildArgs_WithConfigOverrides(t *testing.T) {
	opts := &Options{
		ConfigOverrides: []string{"sandbox=danger-full-access", "approval_policy=never"},
	}
	args := opts.buildArgs()

	// Count --config flags
	configCount := 0
	for _, a := range args {
		if a == "--config" {
			configCount++
		}
	}
	if configCount != 2 {
		t.Errorf("expected 2 --config flags, got %d (args: %v)", configCount, args)
	}
}

func TestOptions_BuildArgs_ModelAndOverrides(t *testing.T) {
	opts := &Options{
		Model:           "gpt-4.1",
		ConfigOverrides: []string{"sandbox=workspace-write"},
	}
	args := opts.buildArgs()

	// Should have 2 --config flags: one for the override, one for model
	configCount := 0
	for _, a := range args {
		if a == "--config" {
			configCount++
		}
	}
	if configCount != 2 {
		t.Errorf("expected 2 --config flags, got %d (args: %v)", configCount, args)
	}

	// All --config must come before app-server
	appServerIdx := slices.Index(args, "app-server")
	for i, a := range args {
		if a == "--config" && i >= appServerIdx {
			t.Error("--config should come before app-server")
		}
	}
}

func TestOptions_BuildArgs_Empty(t *testing.T) {
	opts := &Options{}
	args := opts.buildArgs()

	// Should be exactly: app-server --listen stdio://
	if len(args) != 3 {
		t.Errorf("expected 3 args for empty options, got %d: %v", len(args), args)
	}
}
