package server

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
)

// These tests cover the *deterministic* halves of the audit-harness picker
// (no source path → no audit; explicit `archon: "off"` → archon-disabled
// path; explicit `piolium: <mode>` → piolium harness). The auto-pick branch
// itself depends on `piolium.IsAvailable()` (which probes PATH and Pi
// settings.json) and is exercised end-to-end via the e2e tier.

// stubHandlers builds a Handlers value just rich enough for the resolver
// methods to read settings off it. Bypasses NewHandlers' background
// goroutines.
func stubHandlers() *Handlers {
	settings := config.DefaultSettings()
	return &Handlers{settings: settings}
}

func TestResolveAutopilotAudit_NoSourceReturnsNil(t *testing.T) {
	h := stubHandlers()
	req := AgentAutopilotRequest{} // SourcePath empty
	cfg, harness := h.resolveAutopilotAuditCfgServer(req, "")
	if cfg != nil {
		t.Errorf("expected nil cfg without source, got %+v", cfg)
	}
	if harness.Name != "" {
		t.Errorf("expected zero harness without source, got %q", harness.Name)
	}
}

func TestResolveAutopilotAudit_ExplicitPioliumWinsOverDefault(t *testing.T) {
	h := stubHandlers()
	req := AgentAutopilotRequest{
		SourcePath: "/some/source",
		Piolium:    "balanced",
		// Archon omitted — explicit piolium means archon stays off.
	}
	cfg, harness := h.resolveAutopilotAuditCfgServer(req, "/some/source")
	if cfg == nil {
		t.Fatalf("expected non-nil cfg")
	}
	if cfg.Mode != "balanced" {
		t.Errorf("expected Mode=balanced, got %q", cfg.Mode)
	}
	if harness.Name != "piolium" {
		t.Errorf("expected piolium harness, got %q", harness.Name)
	}
}

func TestResolveAutopilotAudit_ExplicitArchonOffPicksNothingWhenSourceMissing(t *testing.T) {
	// archon=off + no source → no audit at all; piolium stays empty.
	h := stubHandlers()
	req := AgentAutopilotRequest{Archon: "off"}
	cfg, harness := h.resolveAutopilotAuditCfgServer(req, "")
	if cfg != nil {
		t.Errorf("expected nil cfg with archon=off and no source, got %+v", cfg)
	}
	if harness.Name != "" {
		t.Errorf("expected zero harness, got %q", harness.Name)
	}
}

func TestResolveAutopilotAudit_ExplicitArchonModePicksArchon(t *testing.T) {
	h := stubHandlers()
	req := AgentAutopilotRequest{
		SourcePath: "/some/source",
		ArchonMode: "deep",
		// Piolium omitted — explicit archon should win even if pi is
		// available, because archon-explicit suppresses auto-pick.
	}
	cfg, harness := h.resolveAutopilotAuditCfgServer(req, "/some/source")
	if cfg == nil {
		t.Fatalf("expected non-nil cfg")
	}
	if cfg.Mode != "deep" {
		t.Errorf("expected Mode=deep, got %q", cfg.Mode)
	}
	if harness.Name != agent.DefaultArchonHarness().Name {
		t.Errorf("expected archon harness, got %q", harness.Name)
	}
}

func TestResolveSwarmAudit_OptInOnly_NoFlagsNoAudit(t *testing.T) {
	// Swarm is opt-in: empty archon AND empty piolium AND no source → nothing.
	h := stubHandlers()
	req := AgentSwarmRequest{}
	cfg, harness := h.resolveSwarmAuditCfgServer(req, "")
	if cfg != nil {
		t.Errorf("expected nil cfg, got %+v", cfg)
	}
	if harness.Name != "" {
		t.Errorf("expected zero harness, got %q", harness.Name)
	}
}

func TestResolveSwarmAudit_ExplicitPioliumOverridesArchon(t *testing.T) {
	h := stubHandlers()
	req := AgentSwarmRequest{
		SourcePath: "/some/source",
		Piolium:    "longshot",
		Archon:     "deep", // ignored when piolium is explicit
	}
	cfg, harness := h.resolveSwarmAuditCfgServer(req, "/some/source")
	if cfg == nil {
		t.Fatalf("expected non-nil cfg")
	}
	if cfg.Mode != "longshot" {
		t.Errorf("expected Mode=longshot, got %q", cfg.Mode)
	}
	if harness.Name != "piolium" {
		t.Errorf("expected piolium harness, got %q", harness.Name)
	}
}
