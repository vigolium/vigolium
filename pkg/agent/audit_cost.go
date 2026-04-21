package agent

import (
	"encoding/json"
	"fmt"

	"github.com/vigolium/vigolium/pkg/archon/claudecost"
	"github.com/vigolium/vigolium/pkg/archon/codexcost"
	"github.com/vigolium/vigolium/pkg/database"
)

// ScanCost is vigolium's normalized view of an archon audit's token usage
// and USD cost, produced by one of the backend-specific cost packages
// (claudecost, codexcost) and consumed by the CLI summary and the DB
// writer.
//
// Note is a short human-readable annotation the CLI renders after the
// dollar figure (e.g. "(main $8.37 + 10 subagents $4.96)" for Claude,
// "(model gpt-5.4)" for Codex). It is populated by the adapter that
// converts from the backend-specific summary, not by the CLI, so each
// backend can render its own details without the CLI having to branch
// on backend type.
type ScanCost struct {
	Backend      string                 // "claude" | "codex"
	Model        string                 // model id reported by the backend
	InputTokens  int64                  // best-effort total input tokens across the run
	OutputTokens int64                  // best-effort total output tokens (incl. reasoning for Codex)
	CostUSD      float64                // priced total in USD
	Note         string                 // CLI-facing one-line annotation
	Blob         map[string]interface{} // payload for the TokenUsage JSONB column
}

// IsZero reports whether no usage was recorded. Applied by the CLI and
// the DB writer to skip rendering/persisting empty summaries.
func (c ScanCost) IsZero() bool {
	return c.CostUSD == 0 && c.InputTokens == 0 && c.OutputTokens == 0
}

// scanCostFromClaude converts a claudecost.Summary into the neutral
// ScanCost shape. Main-session tokens are reported as-is; subagent
// tokens are rolled into InputTokens/OutputTokens totals so the DB
// columns reflect the whole run, not just the parent agent.
func scanCostFromClaude(s claudecost.Summary) ScanCost {
	if s.TotalCostUSD == 0 && s.Main.OutputTokens == 0 && len(s.Subagents) == 0 {
		return ScanCost{}
	}

	in := s.Main.InputTokens
	out := s.Main.OutputTokens
	mainCost := s.Main.Price(s.Model)
	if s.MainCostReported > 0 {
		mainCost = s.MainCostReported
	}
	var subCost float64
	for _, sub := range s.Subagents {
		in += sub.Usage.InputTokens
		out += sub.Usage.OutputTokens
		subCost += sub.CostUSD
	}

	var note string
	switch {
	case len(s.Subagents) == 0:
		note = fmt.Sprintf("(main only, model %s)", displayModelName(s.Model))
	case len(s.Subagents) == 1:
		note = fmt.Sprintf("(main $%.2f + 1 subagent $%.2f)", mainCost, subCost)
	default:
		note = fmt.Sprintf("(main $%.2f + %d subagents $%.2f)", mainCost, len(s.Subagents), subCost)
	}

	return ScanCost{
		Backend:      "claude",
		Model:        s.Model,
		InputTokens:  in,
		OutputTokens: out,
		CostUSD:      s.TotalCostUSD,
		Note:         note,
		Blob:         toJSONMap(s),
	}
}

// scanCostFromCodex converts a codexcost.Summary into the neutral
// ScanCost shape. Codex reports cumulative totals — input excludes the
// cached portion for CLI display in the Note, but the full InputTokens
// (cached + non-cached) is what we persist in the DB so downstream
// consumers can distinguish.
func scanCostFromCodex(s codexcost.Summary) ScanCost {
	if s.TotalCostUSD == 0 && s.Usage.TotalTokens == 0 {
		return ScanCost{}
	}
	out := s.Usage.OutputTokens + s.Usage.ReasoningOutputTokens
	return ScanCost{
		Backend:      "codex",
		Model:        s.Model,
		InputTokens:  s.Usage.InputTokens,
		OutputTokens: out,
		CostUSD:      s.TotalCostUSD,
		Note:         fmt.Sprintf("(model %s)", displayModelName(s.Model)),
		Blob:         toJSONMap(s),
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
