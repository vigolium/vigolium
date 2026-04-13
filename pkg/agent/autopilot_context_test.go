package agent

import "testing"

func TestDecideBrowserUsage(t *testing.T) {
	cfg := AutopilotPipelineConfig{
		TargetURL:      "https://example.com",
		BrowserEnabled: true,
	}
	bundle := AutopilotContextBundle{
		AuthFlows: []AutopilotAuthFlow{{Name: "jwt login", LoginPath: "/login"}},
	}

	mode, reason := decideBrowserUsage(cfg, bundle)
	if mode != "browser_recommended" {
		t.Fatalf("expected browser_recommended, got %q", mode)
	}
	if reason == "" {
		t.Fatal("expected non-empty browser reason")
	}
}

func TestBuildAutopilotPlanUsesDiffAndAuthSignals(t *testing.T) {
	cfg := AutopilotPipelineConfig{
		MaxCommands:    100,
		TargetURL:      "https://example.com",
		BrowserEnabled: true,
	}
	bundle := AutopilotContextBundle{
		ChangedFiles:    []string{"internal/auth.go"},
		BrowserDecision: "browser_recommended",
		BrowserReason:   "login flow likely browser-dependent",
		AuthFlows:       []AutopilotAuthFlow{{Name: "cookie/session login", LoginPath: "/login"}},
		Findings:        []AutopilotFindingSummary{{Title: "Auth bypass", Severity: "high", Action: "exploit"}},
	}
	spec := AutopilotArtifactSpec{FindingsPath: "findings.json"}

	plan := buildAutopilotPlan(cfg, bundle, spec)
	if !plan.AuthRequired {
		t.Fatal("expected auth to be required")
	}
	if plan.BrowserMode != "browser_recommended" {
		t.Fatalf("expected browser mode to be browser_recommended, got %q", plan.BrowserMode)
	}
	if len(plan.Tasks) < 3 {
		t.Fatalf("expected at least 3 plan tasks, got %d", len(plan.Tasks))
	}
	if plan.Tasks[0].Type != "auth" {
		t.Fatalf("expected auth task first, got %q", plan.Tasks[0].Type)
	}
	if got := plan.Budgets["validate"]; got <= 0 {
		t.Fatalf("expected validate budget > 0, got %d", got)
	}
}
