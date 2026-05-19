package vigtool

import (
	"context"
	"testing"
)

func TestOASTMintRequiresRepo(t *testing.T) {
	tl := NewOASTMintTool(&ScanContext{}) // Repo nil
	res, _ := tl.Execute(context.Background(), map[string]any{}, nil)
	if !res.IsError {
		t.Fatal("expected oast_mint to require a repository")
	}
}

func TestOASTMintNilContext(t *testing.T) {
	tl := NewOASTMintTool(nil)
	res, _ := tl.Execute(context.Background(), map[string]any{}, nil)
	if !res.IsError {
		t.Error("expected error with nil scan context")
	}
}

func TestOASTMintShutdownIsSafeWhenUnused(t *testing.T) {
	tl := NewOASTMintTool(&ScanContext{})
	// Never minted → no Service was created. Must not panic, and must be
	// safe to call more than once (autopilot defers it unconditionally).
	tl.Shutdown()
	tl.Shutdown()
}

func TestOASTMintToolMetadata(t *testing.T) {
	tl := NewOASTMintTool(&ScanContext{})
	if tl.Name() != "oast_mint" {
		t.Errorf("name = %q", tl.Name())
	}
	if tl.IsReadOnly() {
		t.Error("oast_mint mutates run state (starts a poller) — must not be read-only")
	}
	if _, ok := tl.Schema()["properties"]; !ok {
		t.Error("schema missing properties")
	}
}
