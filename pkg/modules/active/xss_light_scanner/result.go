package xss_light_scanner

import "fmt"

// XSSScanResult contains the results of an XSS scan
type XSSScanResult struct {
	ExploitableAnalyses []*EscapeAnalysis // Analyses that indicate exploitability
	UsedPrefix          string            // Which bypass prefix worked (if any)

	// Payload and response tracking
	PrimaryPayload    *CanaryPayload // Primary payload used
	SecondaryPayload  *CanaryPayload // Secondary payload used (if any)
	PrimaryResponse   []byte         // Response from primary payload
	SecondaryResponse []byte         // Response from secondary payload (if any)
	InsertionPoint    string         // Description of insertion point
}

// NewXSSScanResult creates a new scan result
func NewXSSScanResult() *XSSScanResult {
	return &XSSScanResult{
		ExploitableAnalyses: make([]*EscapeAnalysis, 0),
	}
}

// HasVulnerability returns true if any exploitable points were found
func (r *XSSScanResult) HasVulnerability() bool {
	return len(r.ExploitableAnalyses) > 0
}

// VulnerabilityCount returns the number of exploitable points
func (r *XSSScanResult) VulnerabilityCount() int {
	return len(r.ExploitableAnalyses)
}

// GetContextSummary returns a summary of all contexts found
func (r *XSSScanResult) GetContextSummary() string {
	contextCounts := make(map[ReflectionContext]int)

	for _, ea := range r.ExploitableAnalyses {
		contextCounts[ea.Context]++
	}

	if len(contextCounts) == 0 {
		return "No exploitable contexts found"
	}

	summary := "Exploitable contexts: "
	first := true
	for ctx, count := range contextCounts {
		if !first {
			summary += ", "
		}
		summary += fmt.Sprintf("%s (%d)", ctx.String(), count)
		first = false
	}

	if r.UsedPrefix != "" && r.UsedPrefix != "none" {
		summary += fmt.Sprintf(" [bypass: %s]", r.UsedPrefix)
	}

	return summary
}

// GetEvidence returns evidence strings for reporting
func (r *XSSScanResult) GetEvidence() []string {
	var evidence []string

	if r.PrimaryPayload != nil {
		evidence = append(evidence, fmt.Sprintf("Primary payload: %s", r.PrimaryPayload.FullPayload))
	}

	if r.SecondaryPayload != nil {
		evidence = append(evidence, fmt.Sprintf("Secondary payload: %s", r.SecondaryPayload.FullPayload))
	}

	if r.UsedPrefix != "" && r.UsedPrefix != "none" {
		evidence = append(evidence, fmt.Sprintf("Bypass prefix: %s", r.UsedPrefix))
	}

	for i, ea := range r.ExploitableAnalyses {
		evidence = append(evidence, fmt.Sprintf(
			"Reflection %d: %s at offset %d",
			i+1,
			ea.Context.String(),
			ea.Offset,
		))
	}

	return evidence
}

// String returns a string representation
func (r *XSSScanResult) String() string {
	return fmt.Sprintf(
		"XSSScanResult{exploitable=%d, contexts=%s}",
		r.VulnerabilityCount(),
		r.GetContextSummary(),
	)
}
