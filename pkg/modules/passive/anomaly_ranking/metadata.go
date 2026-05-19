package anomaly_ranking

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "anomaly-ranking"
	ModuleName  = "Anomaly Ranking"
	ModuleShort = "Statistical anomaly detection across per-host response batches"
)

var (
	ModuleDesc = `## Description
Ranks HTTP responses by statistical anomaly to identify interesting endpoints. Buffers
responses per host and applies statistical ranking when thresholds are reached.

## Notes
- Buffers per-host response attributes and flushes at configurable thresholds
- Uses statistical analysis to identify outlier responses worth investigating
- Updates risk_score on database records for prioritization

## References
- https://en.wikipedia.org/wiki/Anomaly_detection`

	ModuleConfirmation = "Indicated when a response's statistical attributes (size, status, headers) deviate significantly from the per-host baseline"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"behavior-analysis", "light"}
)
