package sourcetools

import (
	"encoding/json"
	"fmt"
)

// RawFinding represents a finding parsed from a third-party tool's JSON output.
type RawFinding struct {
	RuleID    string
	RuleName  string // rule shortDescription/fullDescription text (for Description)
	Message   string
	Severity  string
	FilePath  string
	StartLine int
	EndLine   int
	ToolName  string
}

// --- Semgrep JSON output structures ---

type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	End     semgrepPos   `json:"end"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Metadata any    `json:"metadata"`
}

// ParseSemgrepOutput parses semgrep JSON output into RawFindings.
func ParseSemgrepOutput(data []byte) ([]RawFinding, error) {
	var out semgrepOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	findings := make([]RawFinding, 0, len(out.Results))
	for _, r := range out.Results {
		findings = append(findings, RawFinding{
			RuleID:    r.CheckID,
			Message:   r.Extra.Message,
			Severity:  normalizeSeverity(r.Extra.Severity),
			FilePath:  r.Path,
			StartLine: r.Start.Line,
			EndLine:   r.End.Line,
			ToolName:  "semgrep",
		})
	}
	return findings, nil
}

// --- OSV-Scanner JSON output structures ---

type osvScannerOutput struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Source   osvSource    `json:"source"`
	Packages []osvPackage `json:"packages"`
}

type osvSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type osvPackage struct {
	Package         osvPackageInfo    `json:"package"`
	Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
}

type osvPackageInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvVulnerability struct {
	ID       string           `json:"id"`
	Summary  string           `json:"summary"`
	Detail   string           `json:"detail"`
	Severity []osvSeverityEntry `json:"severity"`
}

type osvSeverityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// ParseOSVScannerOutput parses osv-scanner JSON output into RawFindings.
func ParseOSVScannerOutput(data []byte) ([]RawFinding, error) {
	var out osvScannerOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	var findings []RawFinding
	for _, r := range out.Results {
		for _, pkg := range r.Packages {
			for _, v := range pkg.Vulnerabilities {
				msg := v.Summary
				if msg == "" {
					msg = v.Detail
				}
				sev := osvSeverityFromCVSS(v.Severity)
				findings = append(findings, RawFinding{
					RuleID:   v.ID,
					Message:  fmt.Sprintf("%s (%s %s)", msg, pkg.Package.Name, pkg.Package.Version),
					Severity: sev,
					FilePath: r.Source.Path,
					ToolName: "osv-scanner",
				})
			}
		}
	}
	return findings, nil
}

// osvSeverityFromCVSS derives a normalized severity from OSV CVSS scores.
func osvSeverityFromCVSS(entries []osvSeverityEntry) string {
	for _, e := range entries {
		if e.Type == "CVSS_V3" || e.Type == "CVSS_V4" {
			// Parse CVSS base score from vector string or raw score
			score := parseCVSSScore(e.Score)
			switch {
			case score >= 9.0:
				return "critical"
			case score >= 7.0:
				return "high"
			case score >= 4.0:
				return "medium"
			case score > 0:
				return "low"
			}
		}
	}
	return "medium" // default when no CVSS available
}

// parseCVSSScore extracts the base score from a CVSS vector or numeric string.
func parseCVSSScore(s string) float64 {
	// Try plain numeric score first
	var score float64
	if _, err := fmt.Sscanf(s, "%f", &score); err == nil {
		return score
	}
	return 0
}

// ParseGenericJSON attempts to parse JSON output as a list of objects with common fields.
// This is a best-effort fallback for unknown tools.
func ParseGenericJSON(data []byte, toolName string) ([]RawFinding, error) {
	// Try array of objects first
	var items []map[string]any
	if err := json.Unmarshal(data, &items); err != nil {
		// Try object with "results" key
		var wrapper map[string]json.RawMessage
		if err2 := json.Unmarshal(data, &wrapper); err2 != nil {
			return nil, err
		}
		for _, key := range []string{"results", "findings", "vulnerabilities", "issues"} {
			if raw, ok := wrapper[key]; ok {
				if err3 := json.Unmarshal(raw, &items); err3 == nil {
					break
				}
			}
		}
	}

	findings := make([]RawFinding, 0, len(items))
	for _, item := range items {
		findings = append(findings, RawFinding{
			RuleID:   strFromMap(item, "rule_id", "id", "check_id"),
			Message:  strFromMap(item, "message", "description", "title"),
			Severity: normalizeSeverity(strFromMap(item, "severity", "level")),
			FilePath: strFromMap(item, "file", "path", "filename"),
			ToolName: toolName,
		})
	}
	return findings, nil
}

// strFromMap returns the first non-empty string value for the given keys.
func strFromMap(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// normalizeSeverity maps tool-specific severity strings to canonical values.
func normalizeSeverity(s string) string {
	switch {
	case eqFold(s, "CRITICAL"):
		return "critical"
	case eqFold(s, "HIGH"):
		return "high"
	case eqFold(s, "MEDIUM"), eqFold(s, "WARNING"):
		return "medium"
	case eqFold(s, "LOW"):
		return "low"
	case eqFold(s, "INFO"), eqFold(s, "NOTE"):
		return "info"
	default:
		return "info"
	}
}

// --- SARIF output structures ---

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult  `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string                    `json:"id"`
	ShortDescription     sarifMessage              `json:"shortDescription"`
	FullDescription      sarifMessage              `json:"fullDescription"`
	DefaultConfiguration sarifDefaultConfiguration `json:"defaultConfiguration"`
	Properties           sarifRuleProperties       `json:"properties"`
}

type sarifDefaultConfiguration struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags []string `json:"tags"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine"`
}

// ParseSARIF parses SARIF format output from any tool into RawFindings.
func ParseSARIF(data []byte, toolName string) ([]RawFinding, error) {
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, err
	}

	var findings []RawFinding
	for _, run := range log.Runs {
		// Build rule lookup map for severity fallback.
		ruleByID := make(map[string]sarifRule, len(run.Tool.Driver.Rules))
		for _, r := range run.Tool.Driver.Rules {
			ruleByID[r.ID] = r
		}

		for _, res := range run.Results {
			var filePath string
			var startLine, endLine int
			if len(res.Locations) > 0 {
				loc := res.Locations[0].PhysicalLocation
				filePath = loc.ArtifactLocation.URI
				startLine = loc.Region.StartLine
				endLine = loc.Region.EndLine
			}

			// Resolve rule name from shortDescription → fullDescription → message
			var ruleName string
			if rule, ok := ruleByID[res.RuleID]; ok {
				switch {
				case rule.ShortDescription.Text != "":
					ruleName = rule.ShortDescription.Text
				case rule.FullDescription.Text != "":
					ruleName = rule.FullDescription.Text
				}
			}

			findings = append(findings, RawFinding{
				RuleID:    res.RuleID,
				RuleName:  ruleName,
				Message:   res.Message.Text,
				Severity:  resolveSARIFSeverity(res, ruleByID),
				FilePath:  filePath,
				StartLine: startLine,
				EndLine:   endLine,
				ToolName:  toolName,
			})
		}
	}
	return findings, nil
}

// resolveSARIFSeverity determines severity using a priority chain:
// 1. result.level (osv-scanner sets this; semgrep does not)
// 2. rule.defaultConfiguration.level
// 3. rule.properties.tags scanned for severity keywords
// 4. fallback: "info"
func resolveSARIFSeverity(res sarifResult, ruleByID map[string]sarifRule) string {
	// 1. Result-level severity
	if res.Level != "" {
		return normalizeSARIFLevel(res.Level)
	}

	rule, ok := ruleByID[res.RuleID]
	if !ok {
		return "info"
	}

	// 2. Rule default configuration level
	if rule.DefaultConfiguration.Level != "" {
		return normalizeSARIFLevel(rule.DefaultConfiguration.Level)
	}

	// 3. Scan tags for severity keywords
	for _, tag := range rule.Properties.Tags {
		sev := normalizeSeverity(tag)
		if sev != "info" {
			return sev
		}
	}

	// 4. Fallback
	return "info"
}

// normalizeSARIFLevel maps SARIF level values to canonical severity strings.
func normalizeSARIFLevel(level string) string {
	switch {
	case eqFold(level, "error"):
		return "high"
	case eqFold(level, "warning"):
		return "medium"
	case eqFold(level, "note"):
		return "low"
	default:
		return "info"
	}
}

// eqFold is a simple case-insensitive compare using strings.EqualFold.
func eqFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
