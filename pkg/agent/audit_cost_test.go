package agent

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/archon/claudecost"
	"github.com/vigolium/vigolium/pkg/archon/codexcost"
	"github.com/vigolium/vigolium/pkg/database"
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

func TestScanCostFromClaude_Empty(t *testing.T) {
	if got := scanCostFromClaude(claudecost.Summary{}); !got.IsZero() {
		t.Errorf("empty Summary should yield zero ScanCost, got %+v", got)
	}
}

func TestScanCostFromClaude_MainOnly(t *testing.T) {
	s := claudecost.Summary{
		Model:            "claude-opus-4-7[1m]",
		Main:             claudecost.Usage{InputTokens: 100, OutputTokens: 2000, CacheReadTokens: 500_000},
		MainCostReported: 1.50,
		TotalCostUSD:     1.50,
	}
	got := scanCostFromClaude(s)
	if got.Backend != "claude" {
		t.Errorf("Backend = %q", got.Backend)
	}
	if got.CostUSD != 1.50 {
		t.Errorf("CostUSD = %v", got.CostUSD)
	}
	if got.InputTokens != 100 || got.OutputTokens != 2000 {
		t.Errorf("tokens = %d/%d", got.InputTokens, got.OutputTokens)
	}
	if !strings.Contains(got.Note, "main only") {
		t.Errorf("Note should mention main-only, got %q", got.Note)
	}
	if !strings.Contains(got.Note, "claude-opus-4-7") {
		t.Errorf("Note should include model, got %q", got.Note)
	}
	if got.Blob == nil {
		t.Error("Blob should be non-nil")
	}
}

func TestScanCostFromClaude_SingleSubagentUsesSingular(t *testing.T) {
	s := claudecost.Summary{
		Model:            "claude-opus-4-7",
		Main:             claudecost.Usage{InputTokens: 100, OutputTokens: 2000},
		MainCostReported: 8.00,
		Subagents: []claudecost.SubagentUsage{
			{AgentID: "a1", Model: "claude-sonnet-4-6", Usage: claudecost.Usage{InputTokens: 50, OutputTokens: 1000}, CostUSD: 0.50},
		},
		TotalCostUSD: 8.50,
	}
	got := scanCostFromClaude(s)
	if !strings.Contains(got.Note, "1 subagent ") {
		t.Errorf("Note should use singular 'subagent', got %q", got.Note)
	}
	if strings.Contains(got.Note, "subagents") {
		t.Errorf("Note must not pluralize for 1 subagent, got %q", got.Note)
	}
	// Totals should include subagent
	if got.InputTokens != 150 || got.OutputTokens != 3000 {
		t.Errorf("totals = %d/%d, want 150/3000", got.InputTokens, got.OutputTokens)
	}
}

func TestScanCostFromClaude_MultipleSubagents(t *testing.T) {
	s := claudecost.Summary{
		Model:            "claude-opus-4-7",
		Main:             claudecost.Usage{InputTokens: 123, OutputTokens: 2616, CacheReadTokens: 3_518_062},
		MainCostReported: 8.37,
		Subagents: []claudecost.SubagentUsage{
			{AgentID: "a1", Model: "claude-sonnet-4-6", Usage: claudecost.Usage{InputTokens: 500, OutputTokens: 10_000}, CostUSD: 1.20},
			{AgentID: "a2", Model: "claude-sonnet-4-6", Usage: claudecost.Usage{InputTokens: 600, OutputTokens: 8_000}, CostUSD: 0.80},
			{AgentID: "a3", Model: "claude-sonnet-4-6", Usage: claudecost.Usage{InputTokens: 700, OutputTokens: 6_000}, CostUSD: 0.60},
		},
		TotalCostUSD: 11.00,
	}
	got := scanCostFromClaude(s)
	if !strings.Contains(got.Note, "3 subagents") {
		t.Errorf("Note should say '3 subagents', got %q", got.Note)
	}
	if !strings.Contains(got.Note, "$8.37") {
		t.Errorf("Note should cite reported main cost $8.37, got %q", got.Note)
	}
	if !strings.Contains(got.Note, "$2.60") {
		t.Errorf("Note should aggregate subagent cost to $2.60, got %q", got.Note)
	}
	if got.CostUSD != 11.00 {
		t.Errorf("CostUSD = %v", got.CostUSD)
	}
}

func TestScanCostFromClaude_LocalPricingWhenNoReportedCost(t *testing.T) {
	// MainCostReported=0 means the result event was missing; fall back
	// to local pricing. The Note should still format correctly.
	s := claudecost.Summary{
		Model: "claude-opus-4-7",
		Main:  claudecost.Usage{InputTokens: 100, OutputTokens: 1000, CacheReadTokens: 10_000},
		Subagents: []claudecost.SubagentUsage{
			{AgentID: "a1", Usage: claudecost.Usage{OutputTokens: 500}, CostUSD: 0.10},
		},
		TotalCostUSD: 0.20, // pre-set by caller
	}
	got := scanCostFromClaude(s)
	if got.IsZero() {
		t.Fatal("should not be zero")
	}
	// Note must still render the main-portion number even without reported cost.
	if !strings.Contains(got.Note, "main $") {
		t.Errorf("Note should cite main cost even without reported, got %q", got.Note)
	}
}

func TestScanCostFromCodex_Empty(t *testing.T) {
	if got := scanCostFromCodex(codexcost.Summary{}); !got.IsZero() {
		t.Errorf("empty Summary should yield zero ScanCost, got %+v", got)
	}
}

func TestScanCostFromCodex_Full(t *testing.T) {
	s := codexcost.Summary{
		SessionID: "sess-x",
		Model:     "gpt-5.4",
		Usage: codexcost.Usage{
			InputTokens:           169_325,
			CachedInputTokens:     118_272,
			OutputTokens:          1_818,
			ReasoningOutputTokens: 1_080,
			TotalTokens:           171_143,
		},
		TotalCostUSD: 0.11,
	}
	got := scanCostFromCodex(s)
	if got.Backend != "codex" {
		t.Errorf("Backend = %q", got.Backend)
	}
	if got.CostUSD != 0.11 {
		t.Errorf("CostUSD = %v", got.CostUSD)
	}
	if got.InputTokens != 169_325 {
		t.Errorf("InputTokens = %d (should include cached)", got.InputTokens)
	}
	// Reasoning counts as output for DB accounting.
	if got.OutputTokens != 1_818+1_080 {
		t.Errorf("OutputTokens = %d, want %d (output + reasoning)", got.OutputTokens, 1_818+1_080)
	}
	if !strings.Contains(got.Note, "gpt-5.4") {
		t.Errorf("Note should cite model, got %q", got.Note)
	}
}

func TestScanCostFromCodex_MissingModelShowsUnknown(t *testing.T) {
	s := codexcost.Summary{
		Model:        "",
		Usage:        codexcost.Usage{InputTokens: 100, OutputTokens: 50, TotalTokens: 150},
		TotalCostUSD: 0.01,
	}
	got := scanCostFromCodex(s)
	if !strings.Contains(got.Note, "unknown") {
		t.Errorf("Note should fall back to 'unknown' for empty model, got %q", got.Note)
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
