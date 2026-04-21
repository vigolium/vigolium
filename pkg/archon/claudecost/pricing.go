// Package claudecost computes estimated token usage and USD cost for an
// archon-audit run by parsing the Claude CLI's stream-json transcript.
//
// Scope: Claude backend only. Codex and OpenCode do not emit per-turn usage
// events on the same shape, so they're out of scope here.
package claudecost

import "strings"

// Pricing describes the per-million-token rates for a single model.
// All rates are in USD per 1,000,000 tokens.
type Pricing struct {
	Model                    string
	InputUSDPerMTok          float64
	OutputUSDPerMTok         float64
	CacheReadUSDPerMTok      float64
	CacheCreate5mUSDPerMTok  float64
	CacheCreate1hUSDPerMTok  float64
}

// defaultPricing is the fallback when no model-specific entry matches.
// Picked to mirror Opus 4.x so the estimate degrades gracefully rather
// than silently reporting $0 for unknown model IDs.
var defaultPricing = Pricing{
	Model:                   "default",
	InputUSDPerMTok:         15.00,
	OutputUSDPerMTok:        75.00,
	CacheReadUSDPerMTok:     1.50,
	CacheCreate5mUSDPerMTok: 18.75,
	CacheCreate1hUSDPerMTok: 30.00,
}

// pricingTable is a small, prefix-matched list. The first entry whose Model
// field is a prefix of the actual model string wins. Ordering matters —
// place more specific prefixes before less specific ones.
var pricingTable = []Pricing{
	{
		// Claude Opus 4.x family (claude-opus-4-7, claude-opus-4-7[1m], etc.)
		Model:                   "claude-opus-4",
		InputUSDPerMTok:         15.00,
		OutputUSDPerMTok:        75.00,
		CacheReadUSDPerMTok:     1.50,
		CacheCreate5mUSDPerMTok: 18.75,
		CacheCreate1hUSDPerMTok: 30.00,
	},
	{
		// Claude Sonnet 4.x family
		Model:                   "claude-sonnet-4",
		InputUSDPerMTok:         3.00,
		OutputUSDPerMTok:        15.00,
		CacheReadUSDPerMTok:     0.30,
		CacheCreate5mUSDPerMTok: 3.75,
		CacheCreate1hUSDPerMTok: 6.00,
	},
	{
		// Claude Haiku 4.x family
		Model:                   "claude-haiku-4",
		InputUSDPerMTok:         1.00,
		OutputUSDPerMTok:        5.00,
		CacheReadUSDPerMTok:     0.10,
		CacheCreate5mUSDPerMTok: 1.25,
		CacheCreate1hUSDPerMTok: 2.00,
	},
}

// PricingFor returns the pricing row that best matches the given model
// identifier by prefix. Returns defaultPricing when no entry matches.
func PricingFor(model string) Pricing {
	m := strings.ToLower(strings.TrimSpace(model))
	for _, p := range pricingTable {
		if strings.HasPrefix(m, p.Model) {
			return p
		}
	}
	return defaultPricing
}

// Usage captures the aggregated token counts produced by a single Claude
// session (main agent or a subagent).
type Usage struct {
	InputTokens       int64 `json:"input_tokens"`
	OutputTokens      int64 `json:"output_tokens"`
	CacheReadTokens   int64 `json:"cache_read_tokens"`
	CacheCreateTokens int64 `json:"cache_create_tokens"`

	// CacheCreate5mTokens and CacheCreate1hTokens, when non-zero, give a
	// more accurate breakdown for pricing. If both are zero but
	// CacheCreateTokens is not, the whole thing is priced at the 5m rate
	// (which is the more common default).
	CacheCreate5mTokens int64 `json:"cache_create_5m_tokens,omitempty"`
	CacheCreate1hTokens int64 `json:"cache_create_1h_tokens,omitempty"`
}

// Add sums another Usage into u in place.
func (u *Usage) Add(o Usage) {
	u.InputTokens += o.InputTokens
	u.OutputTokens += o.OutputTokens
	u.CacheReadTokens += o.CacheReadTokens
	u.CacheCreateTokens += o.CacheCreateTokens
	u.CacheCreate5mTokens += o.CacheCreate5mTokens
	u.CacheCreate1hTokens += o.CacheCreate1hTokens
}

// Price applies the given model's pricing to this usage and returns the
// estimated cost in USD.
func (u Usage) Price(model string) float64 {
	p := PricingFor(model)
	// Prefer the explicit 5m/1h breakdown when available; fall back to
	// treating CacheCreateTokens as 5m cache (the common case).
	create5m := u.CacheCreate5mTokens
	create1h := u.CacheCreate1hTokens
	if create5m == 0 && create1h == 0 {
		create5m = u.CacheCreateTokens
	}
	usd := float64(u.InputTokens)*p.InputUSDPerMTok +
		float64(u.OutputTokens)*p.OutputUSDPerMTok +
		float64(u.CacheReadTokens)*p.CacheReadUSDPerMTok +
		float64(create5m)*p.CacheCreate5mUSDPerMTok +
		float64(create1h)*p.CacheCreate1hUSDPerMTok
	return usd / 1_000_000.0
}
