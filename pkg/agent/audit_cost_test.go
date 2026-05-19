package agent

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/archon/archonstream"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/piolium/picost"
)

func TestScanCost_IsZero(t *testing.T) {
	if !(ScanCost{}).IsZero() {
		t.Error("zero value must report IsZero=true")
	}
	if (ScanCost{CostUSD: 0.01}).IsZero() {
		t.Error("nonzero cost must not report IsZero")
	}
	if (ScanCost{InputTokens: 10}).IsZero() {
		t.Error("nonzero input tokens must not report IsZero")
	}
	if (ScanCost{OutputTokens: 10}).IsZero() {
		t.Error("nonzero output tokens must not report IsZero")
	}
}

func TestScanCostFromArchon_Empty(t *testing.T) {
	if got := scanCostFromArchon(archonstream.Result{}, agenttypes.ArchonAgentClaude); !got.IsZero() {
		t.Errorf("empty Result should yield zero ScanCost, got %+v", got)
	}
}

func TestScanCostFromArchon_Full(t *testing.T) {
	res := archonstream.Result{
		AuditID:     "aud-1",
		Status:      "complete",
		TotalUSD:    1.42,
		TotalTokens: archonstream.Tokens{Input: 250_000, Output: 8_500},
		Findings: archonstream.Findings{
			Total:      4,
			BySeverity: map[string]int{"High": 4},
		},
	}
	got := scanCostFromArchon(res, agenttypes.ArchonAgentCodex)
	if got.Backend != "archon" {
		t.Errorf("Backend = %q, want archon", got.Backend)
	}
	if got.Model != "archon-codex" {
		t.Errorf("Model = %q, want archon-codex", got.Model)
	}
	if got.CostUSD != 1.42 {
		t.Errorf("CostUSD = %v", got.CostUSD)
	}
	if got.InputTokens != 250_000 || got.OutputTokens != 8_500 {
		t.Errorf("tokens = %d/%d", got.InputTokens, got.OutputTokens)
	}
	if !strings.Contains(got.Note, "codex") {
		t.Errorf("Note should cite agent, got %q", got.Note)
	}
	if !strings.Contains(got.Note, "complete") {
		t.Errorf("Note should cite status, got %q", got.Note)
	}
	if got.Blob == nil {
		t.Error("Blob should be non-nil")
	}
}

func TestScanCostFromArchon_DefaultsToClaudeAgent(t *testing.T) {
	res := archonstream.Result{
		AuditID:     "aud-2",
		Status:      "complete",
		TotalUSD:    0.05,
		TotalTokens: archonstream.Tokens{Input: 100, Output: 20},
		Findings:    archonstream.Findings{Total: 0},
	}
	got := scanCostFromArchon(res, "")
	if got.Model != "archon-claude" {
		t.Errorf("empty agent should default to claude, got %q", got.Model)
	}
}

func TestScanCostFromPi_Empty(t *testing.T) {
	if got := scanCostFromPi(picost.Summary{}); !got.IsZero() {
		t.Errorf("empty Summary should yield zero ScanCost, got %+v", got)
	}
}

func TestScanCostFromPi_SingleSession(t *testing.T) {
	s := picost.Summary{
		Model:        "gpt-5.5",
		CWD:          "/tmp/x",
		Usage:        picost.Usage{Input: 4254, Output: 14, TotalTokens: 4268},
		TotalCostUSD: 0.02169,
		Sessions: []picost.SessionSummary{
			{Model: "gpt-5.5", CostUSD: 0.02169},
		},
	}
	got := scanCostFromPi(s)
	if got.Backend != "pi" {
		t.Errorf("Backend = %q, want pi", got.Backend)
	}
	if got.CostUSD != 0.02169 {
		t.Errorf("CostUSD = %v", got.CostUSD)
	}
	if got.InputTokens != 4254 {
		t.Errorf("InputTokens = %d, want 4254", got.InputTokens)
	}
	if got.OutputTokens != 14 {
		t.Errorf("OutputTokens = %d, want 14", got.OutputTokens)
	}
	if !strings.Contains(got.Note, "gpt-5.5") {
		t.Errorf("Note should cite model, got %q", got.Note)
	}
	if strings.Contains(got.Note, "sessions") {
		t.Errorf("Note should not mention session count for single session, got %q", got.Note)
	}
}

func TestScanCostFromPi_MultipleSessionsAnnotated(t *testing.T) {
	s := picost.Summary{
		Model:        "gpt-5.5",
		Usage:        picost.Usage{Input: 1000, Output: 200, TotalTokens: 1200},
		TotalCostUSD: 0.5,
		Sessions: []picost.SessionSummary{
			{}, {}, {}, // 3 sessions
		},
	}
	got := scanCostFromPi(s)
	if !strings.Contains(got.Note, "3 sessions") {
		t.Errorf("Note should mention session count, got %q", got.Note)
	}
}

func TestApplyScanCost_ZeroIsNoOp(t *testing.T) {
	run := &database.AgenticScan{Model: "preset"}
	applyScanCost(run, ScanCost{})
	if run.Model != "preset" {
		t.Errorf("zero apply must not overwrite Model, got %q", run.Model)
	}
	if run.TotalInputTokens != 0 || run.TotalOutputTokens != 0 || run.EstimatedCostUSD != 0 {
		t.Error("zero apply must not write token/cost fields")
	}
	if run.TokenUsage != nil {
		t.Error("zero apply must not write Blob")
	}
}

func TestApplyScanCost_FullWritesAllColumns(t *testing.T) {
	run := &database.AgenticScan{}
	c := ScanCost{
		Backend:      "claude",
		Model:        "claude-opus-4-7",
		InputTokens:  10_000,
		OutputTokens: 500,
		CostUSD:      13.34,
		Note:         "(main $8.37 + 10 subagents $4.96)",
		Blob:         map[string]interface{}{"main": map[string]interface{}{"output_tokens": 2616}},
	}
	applyScanCost(run, c)
	if run.Model != "claude-opus-4-7" {
		t.Errorf("Model = %q", run.Model)
	}
	if run.TotalInputTokens != 10_000 {
		t.Errorf("TotalInputTokens = %d", run.TotalInputTokens)
	}
	if run.TotalOutputTokens != 500 {
		t.Errorf("TotalOutputTokens = %d", run.TotalOutputTokens)
	}
	if run.EstimatedCostUSD != 13.34 {
		t.Errorf("EstimatedCostUSD = %v", run.EstimatedCostUSD)
	}
	if run.TokenUsage == nil {
		t.Error("TokenUsage should be populated from Blob")
	}
}

func TestApplyScanCost_PreservesExistingModel(t *testing.T) {
	// If the caller already set run.Model (e.g. from somewhere else),
	// applyScanCost must not overwrite it with the ScanCost's model.
	run := &database.AgenticScan{Model: "explicitly-set"}
	applyScanCost(run, ScanCost{
		Model:        "claude-opus-4-7",
		InputTokens:  100,
		OutputTokens: 50,
		CostUSD:      0.01,
	})
	if run.Model != "explicitly-set" {
		t.Errorf("existing Model was overwritten to %q", run.Model)
	}
}

func TestDisplayModelName(t *testing.T) {
	if displayModelName("") != "unknown" {
		t.Error("empty should render as 'unknown'")
	}
	if displayModelName("gpt-5.4") != "gpt-5.4" {
		t.Error("non-empty should pass through")
	}
}
