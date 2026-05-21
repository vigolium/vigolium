package agent

import (
	"encoding/json"
	"fmt"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/audit/stream"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/piolium/picost"
)

// ScanCost is vigolium's normalized view of an audit harness's token
// usage and USD cost, produced by the per-harness cost adapter and
// consumed by the CLI summary and the DB writer.
//
// Note is a short human-readable annotation the CLI renders after the
// dollar figure (e.g. "(model gpt-5.5, 3 sessions)" for piolium, "(agent
// codex, status complete)" for audit). It is populated by the adapter
// that converts from the harness-specific summary, not by the CLI, so
// each harness can render its own details without the CLI having to
// branch on harness type.
type ScanCost struct {
	Backend      string                 // "audit" | "pi"
	Model        string                 // model id reported by the harness
	InputTokens  int64                  // total input tokens across the run
	OutputTokens int64                  // total output tokens across the run
	CostUSD      float64                // priced total in USD
	Note         string                 // CLI-facing one-line annotation
	Blob         map[string]interface{} // payload for the TokenUsage JSONB column
}

// IsZero reports whether no usage was recorded. Applied by the CLI and
// the DB writer to skip rendering/persisting empty summaries.
func (c ScanCost) IsZero() bool {
	return c.CostUSD == 0 && c.InputTokens == 0 && c.OutputTokens == 0
}

// scanCostFromPi converts a picost.Summary into the neutral ScanCost shape.
// Pi pre-prices each assistant turn, so picost just sums the reported
// totals — there's no local pricing table to apply.
func scanCostFromPi(s picost.Summary) ScanCost {
	if s.TotalCostUSD == 0 && s.Usage.TotalTokens == 0 {
		return ScanCost{}
	}
	var note string
	switch len(s.Sessions) {
	case 0, 1:
		note = fmt.Sprintf("(model %s)", displayModelName(s.Model))
	default:
		note = fmt.Sprintf("(model %s, %d sessions)", displayModelName(s.Model), len(s.Sessions))
	}
	return ScanCost{
		Backend:      "pi",
		Model:        s.Model,
		InputTokens:  s.Usage.Input,
		OutputTokens: s.Usage.Output,
		CostUSD:      s.TotalCostUSD,
		Note:         note,
		Blob:         toJSONMap(s),
	}
}

// scanCostFromAudit converts the captured audit `result` event into
// the neutral ScanCost shape. vigolium-audit pre-prices every run and emits
// totalUsd / totalTokens in the final NDJSON event, so there is no
// transcript mining and no per-provider pricing table to apply on the
// vigolium side. agent labels the audit-internal adapter (claude or
// codex) for the CLI banner / DB row.
func scanCostFromAudit(res stream.Result, agent agenttypes.AuditDriverAgent) ScanCost {
	if res.IsZero() {
		return ScanCost{}
	}
	if agent == "" {
		agent = agenttypes.AuditDriverAgentClaude
	}
	model := "audit-" + string(agent)
	return ScanCost{
		Backend:      "audit",
		Model:        model,
		InputTokens:  res.TotalTokens.Input,
		OutputTokens: res.TotalTokens.Output,
		CostUSD:      res.TotalUSD,
		Note:         fmt.Sprintf("(agent %s, status %s)", agent, res.Status),
		Blob:         toJSONMap(res),
	}
}

// toJSONMap marshals a typed summary into a generic map suitable for the
// JSONB TokenUsage column. Returns nil on failure so the column remains
// NULL rather than holding a partial blob.
func toJSONMap(v interface{}) map[string]interface{} {
	blob, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(blob, &m); err != nil {
		return nil
	}
	return m
}

// displayModelName renders a model id safely, substituting a placeholder
// for the empty string so the CLI never renders "(model )".
func displayModelName(m string) string {
	if m == "" {
		return "unknown"
	}
	return m
}

// applyScanCost copies the normalized cost into the AgenticScan row's
// existing usage columns. No-op on a zero cost so it is safe to call
// unconditionally.
func applyScanCost(run *database.AgenticScan, c ScanCost) {
	if c.IsZero() {
		return
	}
	if run.Model == "" {
		run.Model = c.Model
	}
	run.TotalInputTokens = c.InputTokens
	run.TotalOutputTokens = c.OutputTokens
	run.EstimatedCostUSD = c.CostUSD
	if c.Blob != nil {
		run.TokenUsage = c.Blob
	}
}
