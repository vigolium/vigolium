package anomaly_ranking

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "anomaly-ranking"
	ModuleName  = "Anomaly Ranking"
	ModuleShort = "Statistical anomaly detection across per-host response batches"
)

var (
	ModuleDesc = `**What it means:** This is an informational triage signal, not a vulnerability. The scanner statistically compared this host's HTTP responses (status code, body size, headers, and other extracted attributes) and flagged this response as an outlier that deviates from the host's typical baseline. Outlier responses are disproportionately likely to be interesting attack surface, such as error pages leaking stack traces, debug endpoints, admin panels, or pages that behave unlike the rest of the site.

**How it's exploited:** There is no direct exploit. The ranking assigns each response a relative risk-score percentile so an analyst or downstream module can prioritize manual review of the most anomalous endpoints first, instead of triaging hundreds of near-identical responses by hand. The disclosed signal speeds up finding the genuinely sensitive or misbehaving endpoints on the target.

**Fix:** No remediation is required; treat this as a prioritization hint and manually review the flagged endpoint to confirm whether it exposes sensitive functionality, error detail, or unexpected behavior.`

	ModuleConfirmation = "Indicated when a response's statistical attributes (size, status, headers) deviate significantly from the per-host baseline"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"behavior-analysis", "light"}
)
