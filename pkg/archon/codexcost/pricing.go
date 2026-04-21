// Package codexcost computes estimated token usage and USD cost for an
// archon-audit run that used the Codex CLI backend, by parsing the per-
// session JSONL rollout Codex writes under ~/.codex/sessions/.
package codexcost

import "strings"

// Pricing describes per-million-token rates for a single Codex model.
// Cached input is a discounted rate — non-cached input is billed at
// NonCachedInputUSDPerMTok, cached at CachedInputUSDPerMTok. Reasoning
// output tokens are billed at the same rate as regular output.
type Pricing struct {
	Model                     string
	NonCachedInputUSDPerMTok  float64
	CachedInputUSDPerMTok     float64
	OutputUSDPerMTok          float64
}

// defaultPricing is the fallback applied when no prefix matches. Chosen to
// mirror the gpt-5 family so unknown models (e.g. a future gpt-5.5) still
// produce a plausible estimate rather than silently reporting $0.
var defaultPricing = Pricing{
	Model:                    "default",
	NonCachedInputUSDPerMTok: 1.25,
	CachedInputUSDPerMTok:    0.125,
	OutputUSDPerMTok:         10.00,
}

// pricingTable is a small prefix-matched list. First prefix match wins —
// order more-specific prefixes before less-specific ones.
var pricingTable = []Pricing{
	{
		// Covers "gpt-5", "gpt-5.4", "gpt-5-codex", etc. Codex reports
		// the model id verbatim from turn_context so prefix match is
		// robust to point revisions.
		Model:                    "gpt-5",
		NonCachedInputUSDPerMTok: 1.25,
		CachedInputUSDPerMTok:    0.125,
		OutputUSDPerMTok:         10.00,
	},
	{
		Model:                    "gpt-4.1",
		NonCachedInputUSDPerMTok: 2.00,
		CachedInputUSDPerMTok:    0.50,
		OutputUSDPerMTok:         8.00,
	},
	{
		Model:                    "o4-mini",
		NonCachedInputUSDPerMTok: 1.10,
		CachedInputUSDPerMTok:    0.275,
		OutputUSDPerMTok:         4.40,
	},
}

// PricingFor returns the pricing row that best matches the given model by
// prefix, falling back to defaultPricing.
func PricingFor(model string) Pricing {
	m := strings.ToLower(strings.TrimSpace(model))
	for _, p := range pricingTable {
		if strings.HasPrefix(m, p.Model) {
			return p
		}
	}
	return defaultPricing
}

// Usage captures Codex's token-accounting shape. Mirrors the
// total_token_usage object in the rollout's token_count events.
type Usage struct {
	InputTokens            int64 `json:"input_tokens"`
	CachedInputTokens      int64 `json:"cached_input_tokens"`
	OutputTokens           int64 `json:"output_tokens"`
	ReasoningOutputTokens  int64 `json:"reasoning_output_tokens"`
	TotalTokens            int64 `json:"total_tokens"`
}

// Price applies the given model's pricing to this usage. Non-cached input
// = InputTokens - CachedInputTokens. Reasoning tokens are priced as output.
func (u Usage) Price(model string) float64 {
	p := PricingFor(model)
	nonCached := u.InputTokens - u.CachedInputTokens
	if nonCached < 0 {
		nonCached = 0
	}
	outputTotal := u.OutputTokens + u.ReasoningOutputTokens
	usd := float64(nonCached)*p.NonCachedInputUSDPerMTok +
		float64(u.CachedInputTokens)*p.CachedInputUSDPerMTok +
		float64(outputTotal)*p.OutputUSDPerMTok
	return usd / 1_000_000.0
}
