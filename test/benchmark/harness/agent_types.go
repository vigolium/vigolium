package harness

import "time"

// AgentFixture represents a cached agent output for benchmark testing.
// Each fixture captures the raw output from a single (stub × template) run.
type AgentFixture struct {
	Metadata  AgentFixtureMetadata `json:"metadata"`
	RawOutput string               `json:"raw_output"`
	Parsed    AgentFixtureParsed   `json:"parsed"`
}

// AgentFixtureMetadata records provenance for a cached fixture.
type AgentFixtureMetadata struct {
	Stub         string    `json:"stub"`
	Template     string    `json:"template"`
	AgentName    string    `json:"agent_name"`
	OutputSchema string    `json:"output_schema"` // "findings" or "http_records"
	GeneratedAt  time.Time `json:"generated_at"`
	AgentModel   string    `json:"agent_model,omitempty"`
}

// AgentFixtureParsed holds pre-parsed results stored alongside the raw output.
type AgentFixtureParsed struct {
	FindingCount int `json:"finding_count"`
	RecordCount  int `json:"record_count"`
}

// AgentParsingDefinition describes a Layer 1 benchmark: parsing raw agent output.
type AgentParsingDefinition struct {
	Fixture      string               `yaml:"fixture"`
	OutputSchema string               `yaml:"output_schema"` // "findings" or "http_records"
	Expected     AgentParsingExpected `yaml:"expected"`
}

// AgentParsingExpected describes expected parsing results.
type AgentParsingExpected struct {
	FindingCount   int                  `yaml:"finding_count"`
	RecordCount    int                  `yaml:"record_count"`
	Error          bool                 `yaml:"error"`
	RequiredFields []AgentRequiredField `yaml:"required_fields,omitempty"`
}

// AgentRequiredField describes a field that must be present in parsed output.
type AgentRequiredField struct {
	Field    string `yaml:"field"`
	NonEmpty bool   `yaml:"non_empty"`
}

// AgentQualityDefinition describes a Layer 2 benchmark: validating finding quality.
type AgentQualityDefinition struct {
	Fixture    string               `yaml:"fixture"`
	SourceStub string               `yaml:"source_stub"`
	Template   string               `yaml:"template"`
	Assertion  string               `yaml:"assertion"` // strict | soft (default: soft)
	Expected   AgentQualityExpected `yaml:"expected"`
}

// AgentQualityExpected describes expected quality metrics for agent findings.
type AgentQualityExpected struct {
	MinFindings          int            `yaml:"min_findings"`
	MaxFindings          int            `yaml:"max_findings"`
	ExpectedCWEs         []string       `yaml:"expected_cwes,omitempty"`
	ExpectedVulnTypes    []string       `yaml:"expected_vuln_types,omitempty"`
	SeverityDistribution map[string]int `yaml:"severity_distribution,omitempty"`
}

// AgentHandoffDefinition describes a Layer 3 benchmark: HTTP record conversion.
type AgentHandoffDefinition struct {
	Fixture  string               `yaml:"fixture"`
	Expected AgentHandoffExpected `yaml:"expected"`
}

// AgentHandoffExpected describes expected results from HTTP record conversion.
type AgentHandoffExpected struct {
	ConvertibleCount int                   `yaml:"convertible_count"`
	SkippedCount     int                   `yaml:"skipped_count"`
	Records          []AgentExpectedRecord `yaml:"records,omitempty"`
}

// AgentExpectedRecord describes an expected HTTP record after conversion.
type AgentExpectedRecord struct {
	Method    string `yaml:"method"`
	URLPrefix string `yaml:"url_prefix"`
	HasHost   bool   `yaml:"has_host"`
	Assertion string `yaml:"assertion"` // strict | soft (default: strict)
}

// AgentE2EDefinition describes a Layer 4 benchmark: end-to-end scanning.
type AgentE2EDefinition struct {
	Fixture    string             `yaml:"fixture"`
	App        AgentE2EApp        `yaml:"app"`
	ScanConfig AgentE2EScanConfig `yaml:"scan_config"`
	Expected   AgentE2EExpected   `yaml:"expected"`
}

// AgentE2EApp describes the target vulnerable application for E2E testing.
type AgentE2EApp struct {
	Name        string `yaml:"name"`
	ComposeFile string `yaml:"compose_file"`
	BaseURL     string `yaml:"base_url"`
	WaitPath    string `yaml:"wait_path"`
}

// AgentE2EScanConfig describes scan parameters for E2E testing.
type AgentE2EScanConfig struct {
	Modules    []string `yaml:"modules"`
	MaxRecords int      `yaml:"max_records"`
}

// AgentE2EExpected describes expected E2E results.
type AgentE2EExpected struct {
	MinFindings int    `yaml:"min_findings"`
	Assertion   string `yaml:"assertion"` // strict | soft (default: soft)
}
