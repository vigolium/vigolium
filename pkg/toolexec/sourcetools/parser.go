package sourcetools

import "encoding/json"

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

// --- Trivy JSON output structures ---

type trivyOutput struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string             `json:"Target"`
	Vulnerabilities []trivyVuln        `json:"Vulnerabilities"`
	Misconfigs      []trivyMisconfig   `json:"Misconfigurations"`
	Secrets         []trivySecret      `json:"Secrets"`
}

type trivyVuln struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	Title           string `json:"Title"`
	Description     string `json:"Description"`
	Severity        string `json:"Severity"`
}

type trivyMisconfig struct {
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Severity    string `json:"Severity"`
	Message     string `json:"Message"`
}

type trivySecret struct {
	RuleID   string `json:"RuleID"`
	Category string `json:"Category"`
	Title    string `json:"Title"`
	Severity string `json:"Severity"`
	StartLine int   `json:"StartLine"`
	EndLine   int   `json:"EndLine"`
}

// ParseTrivyOutput parses trivy JSON output into RawFindings.
func ParseTrivyOutput(data []byte) ([]RawFinding, error) {
	var out trivyOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	var findings []RawFinding
	for _, r := range out.Results {
		for _, v := range r.Vulnerabilities {
			msg := v.Title
			if msg == "" {
				msg = v.Description
			}
			findings = append(findings, RawFinding{
				RuleID:   v.VulnerabilityID,
				Message:  msg,
				Severity: normalizeSeverity(v.Severity),
				FilePath: r.Target,
				ToolName: "trivy",
			})
		}
		for _, m := range r.Misconfigs {
			msg := m.Title
			if msg == "" {
				msg = m.Description
			}
			findings = append(findings, RawFinding{
				RuleID:   m.ID,
				Message:  msg,
				Severity: normalizeSeverity(m.Severity),
				FilePath: r.Target,
				ToolName: "trivy",
			})
		}
		for _, s := range r.Secrets {
			findings = append(findings, RawFinding{
				RuleID:    s.RuleID,
				Message:   s.Title,
				Severity:  normalizeSeverity(s.Severity),
				FilePath:  r.Target,
				StartLine: s.StartLine,
				EndLine:   s.EndLine,
				ToolName:  "trivy",
			})
		}
	}
	return findings, nil
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
// 1. result.level (trivy sets this; semgrep does not)
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
