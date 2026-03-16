//go:build e2e

// e2e_test.go — Runs pilot crawler with real ACP agent against a live target.
// Run: go build -o /tmp/vigolium-pilot ./cmd/vigolium/ && go test -v -tags=e2e -timeout=300s -run TestPilotE2E ./pkg/spitolas/internal/pilot/...
package pilot

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	appconfig "github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/form"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

func TestPilotE2E(t *testing.T) {
	target := os.Getenv("BRAIN_TARGET")
	if target == "" {
		target = "https://ginandjuice.shop/"
	}

	timeout := 3 * time.Minute
	if d := os.Getenv("BRAIN_TIMEOUT"); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil {
			timeout = parsed
		}
	}

	sessionDir := t.TempDir()
	t.Logf("Target:  %s", target)
	t.Logf("Timeout: %s", timeout)
	t.Logf("Session: %s", sessionDir)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create crawler config
	cfg, err := config.New(target)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg.Headless = true
	cfg.BrowserCount = 1

	// Browser pool
	t.Log("[1/5] Starting browser...")
	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("browser pool: %v", err)
	}
	defer pool.Close()

	// Sub-components
	t.Log("[2/5] Creating infrastructure...")
	graph := state.NewGraph()
	formHandler := form.NewHandler(cfg)
	extractor := action.NewCandidateElementExtractor(cfg)
	extractor.SetClickOnce(false)
	capture := network.New(&network.NopWriter{}, true, false, false, false, false, cfg.URL.Hostname(), "pilot")

	tracePath := sessionDir + "/session_trace.md"
	trace, err := NewSessionTrace(tracePath)
	if err != nil {
		t.Fatalf("session trace: %v", err)
	}
	defer trace.Close()

	// Agent definition
	agentCfg := appconfig.DefaultAgentConfig()
	agentDef := agentCfg.Backends["claude"]

	pilotCfg := &PilotConfig{
		Enabled: true,
		Auth: PilotAuthConfig{
			Enabled:      true,
			AutoRegister: true,
		},
	}

	t.Log("[3/5] Creating PilotCrawler...")
	bc := NewPilotCrawler(cfg, pilotCfg, agentDef, pool, graph, formHandler, extractor, capture, trace, sessionDir+"/checkpoints.json")

	t.Log("[4/5] Running pilot crawl (ACP session)...")
	result, err := bc.Run(ctx)

	t.Log("[5/5] Analyzing results...")
	if err != nil {
		t.Logf("Pilot crawl error: %v", err)
	}
	if result != nil {
		t.Logf("States:      %d", result.StatesDiscovered)
		t.Logf("Actions:     %d", result.ActionsExecuted)
		t.Logf("Checkpoints: %d completed, %d pending", result.CheckpointsCompleted, result.CheckpointsPending)
		t.Logf("Duration:    %s", result.Duration)
	}

	// === Action Log Analysis ===
	entries := trace.Entries(0)
	t.Logf("\n=== ACTION LOG (%d entries) ===", len(entries))

	if len(entries) == 0 {
		t.Error("NO ACTIONS — agent did not call any browser tools")
		// Show prompt for debugging
		t.Logf("System prompt length: %d chars", len(systemPrompt))
		return
	}

	toolCounts := map[string]int{}
	failCount := 0
	for _, e := range entries {
		toolCounts[e.Tool]++
		if !e.Success {
			failCount++
		}
	}

	t.Log("\nTool usage:")
	for tool, count := range toolCounts {
		t.Logf("  %-20s %d", tool, count)
	}
	t.Logf("  failures:           %d", failCount)

	// Show first 10 and last 10 actions
	t.Log("\nFirst actions:")
	for _, e := range entries[:min(10, len(entries))] {
		args, _ := json.Marshal(e.Args)
		status := "OK"
		if !e.Success {
			status = "FAIL: " + e.Error
		}
		t.Logf("  #%d %s(%s) → %s", e.Seq, e.Tool, string(args), status)
	}

	if len(entries) > 10 {
		t.Log("\nLast actions:")
		for _, e := range entries[max(0, len(entries)-10):] {
			args, _ := json.Marshal(e.Args)
			status := "OK"
			if !e.Success {
				status = "FAIL: " + e.Error
			}
			t.Logf("  #%d %s(%s) → %s", e.Seq, e.Tool, string(args), status)
		}
	}

	// === Checkpoint Analysis ===
	checkpoints := bc.checkpoints.All()
	t.Logf("\n=== CHECKPOINTS (%d total) ===", len(checkpoints))
	for _, cp := range checkpoints {
		t.Logf("  [%s] %s — %s", strings.ToUpper(string(cp.Status)), cp.Name, cp.Description)
		if cp.Notes != "" {
			t.Logf("    notes: %s", cp.Notes)
		}
	}

	// === Blacklist ===
	bl := bc.blacklist.All()
	t.Logf("\n=== BLACKLIST (%d entries) ===", len(bl))
	for _, b := range bl {
		auto := ""
		if b.Auto {
			auto = " [auto]"
		}
		t.Logf("  %s — %s%s", b.XPath, b.Reason, auto)
	}

	// === Plan Compliance Checks ===
	t.Log("\n=== PLAN COMPLIANCE ===")

	// Check: agent should have discovered checkpoints
	if len(checkpoints) == 0 {
		t.Error("FAIL: agent did not discover any checkpoints (plan requires create_checkpoint usage)")
	} else {
		t.Logf("PASS: %d checkpoints discovered", len(checkpoints))
	}

	// Check: agent should have used click
	if toolCounts["click"] == 0 && toolCounts["navigate"] == 0 {
		t.Error("FAIL: agent did not navigate (no click or navigate calls)")
	} else {
		t.Logf("PASS: agent navigated (%d clicks, %d navigates)", toolCounts["click"], toolCounts["navigate"])
	}

	// Check: blacklist should have been auto-populated
	if len(bl) == 0 {
		t.Log("WARN: no blacklist entries (page may not have logout links)")
	} else {
		t.Logf("PASS: %d blacklist entries", len(bl))
	}

	// Check: multiple states discovered
	stateCount := graph.StateCount()
	if stateCount < 2 {
		t.Error("FAIL: only 1 state — agent didn't explore")
	} else {
		t.Logf("PASS: %d states in graph", stateCount)
	}

	// Dump action log file location
	if data, err := os.ReadFile(logPath); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		t.Logf("\nAction log: %s (%d lines, %d bytes)", logPath, len(lines), len(data))
	}

	// Save a readable report
	reportPath := sessionDir + "/report.txt"
	var report strings.Builder
	fmt.Fprintf(&report, "Pilot Crawl Report\n==================\n")
	fmt.Fprintf(&report, "Target: %s\nDuration: %s\n\n", target, result.Duration)
	fmt.Fprintf(&report, "States: %d\nActions: %d\nCheckpoints: %d\n\n", result.StatesDiscovered, result.ActionsExecuted, len(checkpoints))
	fmt.Fprintf(&report, "Tool Usage:\n")
	for tool, count := range toolCounts {
		fmt.Fprintf(&report, "  %-20s %d\n", tool, count)
	}
	fmt.Fprintf(&report, "\nCheckpoints:\n")
	for _, cp := range checkpoints {
		fmt.Fprintf(&report, "  [%s] %s — %s\n", cp.Status, cp.Name, cp.Description)
	}
	os.WriteFile(reportPath, []byte(report.String()), 0644)
	t.Logf("Report saved: %s", reportPath)
}
