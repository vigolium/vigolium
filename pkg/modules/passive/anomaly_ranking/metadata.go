package anomaly_ranking

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "anomaly-ranking"
	ModuleName  = "Anomaly Ranking"
	ModuleShort = "Statistical anomaly detection across per-host response batches"
)

var (
	ModuleDesc = `**What it means:** An informational triage signal, not a vulnerability. The scanner statistically compared this host's responses (status, body size, headers) and flagged this one as an outlier from the baseline. Outliers are disproportionately interesting attack surface - error pages leaking stack traces, debug endpoints, or admin panels.

**How it's exploited:** No direct exploit. Each response gets a relative risk-score percentile so an analyst reviews the most anomalous endpoints first instead of triaging near-identical responses by hand.

**Fix:** No remediation required; treat this as a prioritization hint and manually review the flagged endpoint for sensitive functionality or unexpected behavior.`

	ModuleConfirmation = "Indicated when a response's statistical attributes (size, status, headers) deviate significantly from the per-host baseline"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"behavior-analysis", "light"}
)
