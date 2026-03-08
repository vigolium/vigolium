package harness

// SASTExtractionDefinition describes a route extraction benchmark for a single framework.
type SASTExtractionDefinition struct {
	Framework          string             `yaml:"framework"`
	SourceDir          string             `yaml:"source_dir"`
	DetectFramework    bool               `yaml:"detect_framework"`
	ExpectedRoutes     []ExpectedRoute    `yaml:"expected_routes"`
	ExpectedMatchCount MatchCountBounds   `yaml:"expected_match_count"`
	NegativeRoutes     []ExpectedRoute    `yaml:"negative_routes"`
}

// ExpectedRoute describes a route that should (or should not) appear in extraction results.
type ExpectedRoute struct {
	Method    string   `yaml:"method"`
	Path      string   `yaml:"path"`
	File      string   `yaml:"file,omitempty"`
	Params    []string `yaml:"params,omitempty"`
	Assertion string   `yaml:"assertion"` // strict | soft (default: strict)
}

// MatchCountBounds defines min/max bounds for match counts.
type MatchCountBounds struct {
	Min int `yaml:"min"`
	Max int `yaml:"max"`
}

// SASTSARIFDefinition describes a SARIF parsing benchmark.
type SASTSARIFDefinition struct {
	Fixture  string           `yaml:"fixture"`
	ToolName string           `yaml:"tool_name"`
	Format   string           `yaml:"format"` // sarif | semgrep-json | trivy-json (default: sarif)
	Expected SARIFExpectation `yaml:"expected"`
}

// SARIFExpectation describes expected results from parsing a SARIF fixture.
type SARIFExpectation struct {
	FindingCount         int                `yaml:"finding_count"`
	Error                bool               `yaml:"error"`
	Findings             []ExpectedFinding  `yaml:"findings,omitempty"`
	SeverityDistribution map[string]int     `yaml:"severity_distribution,omitempty"`
}

// ExpectedFinding describes a specific finding expected in SARIF output.
type ExpectedFinding struct {
	RuleID    string `yaml:"rule_id"`
	Severity  string `yaml:"severity"`
	FilePath  string `yaml:"file_path,omitempty"`
	StartLine int    `yaml:"start_line,omitempty"`
	ToolName  string `yaml:"tool_name,omitempty"`
}

// SASTHandoffDefinition describes a route-to-HRR conversion benchmark.
type SASTHandoffDefinition struct {
	Framework string         `yaml:"framework"`
	BaseURL   string         `yaml:"base_url"`
	Routes    []HandoffRoute `yaml:"routes"`
}

// HandoffRoute describes a single route for handoff testing.
type HandoffRoute struct {
	Method          string          `yaml:"method"`
	Path            string          `yaml:"path"`
	Params          []string        `yaml:"params,omitempty"`
	ExpectedRequest ExpectedRequest `yaml:"expected_request"`
	ExpectedSkip    bool            `yaml:"expected_skip"`
}

// ExpectedRequest describes the expected HTTP request properties after route conversion.
type ExpectedRequest struct {
	Method string `yaml:"method"`
	URI    string `yaml:"uri"`
	Host   string `yaml:"host"`
}
