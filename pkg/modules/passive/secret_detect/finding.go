package secret_detect

import (
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/toolexec/kingfisher"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// NewSecretFinding builds the ResultEvent shared by both secret-finding emission
// paths — the passive module's batch flush and the known-issue-scan batch — so
// the two can't drift in title, tags, evidence, or metadata (they already did
// once: one path titled findings by rule ID, the other by rule name). Callers
// set the source-specific fields (ModuleID, ModuleType, FindingSource,
// ModuleShort, and any extra tags) on the returned event.
func NewSecretFinding(f *kingfisher.Finding, sev severity.Severity, conf severity.Confidence, host, url, request, response string) *output.ResultEvent {
	return &output.ResultEvent{
		Info: output.Info{
			Name:        f.RuleName(),
			Description: secretFindingDescription(f.RuleName(), f.Snippet()),
			Severity:    sev,
			Confidence:  conf,
			Tags:        []string{"secret", "credential", "exposure"},
		},
		Host:             host,
		URL:              url,
		Matched:          url,
		ExtractedResults: []string{f.Snippet()},
		Request:          request,
		Response:         response,
		Metadata: map[string]any{
			"rule_id":   f.RuleID(),
			"rule_name": f.RuleName(),
			"validated": f.IsValidated(),
		},
	}
}
