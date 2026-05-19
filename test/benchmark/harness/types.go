// Package harness provides a data-driven benchmark test framework for Vigolium scanner modules.
// It loads YAML benchmark definitions and drives module execution with configurable assertions.
package harness

import "time"

// BenchmarkDefinition represents a complete YAML benchmark file.
type BenchmarkDefinition struct {
	App       AppConfig  `yaml:"app"`
	Setup     *Setup     `yaml:"setup,omitempty"`
	TestCases []TestCase `yaml:"test_cases"`
}

// AppConfig describes the target application.
type AppConfig struct {
	Name           string            `yaml:"name"`
	Type           string            `yaml:"type"` // docker | compose | external | xbow
	Image          string            `yaml:"image,omitempty"`
	ComposeFile    string            `yaml:"compose_file,omitempty"`
	Port           int               `yaml:"port,omitempty"`
	ExposedPort    string            `yaml:"exposed_port,omitempty"`
	WaitEndpoint   string            `yaml:"wait_endpoint,omitempty"`
	StartupTimeout time.Duration     `yaml:"startup_timeout,omitempty"`
	BaseURL        string            `yaml:"base_url,omitempty"` // for external apps
	Env            map[string]string `yaml:"env,omitempty"`
	RateLimit      int               `yaml:"rate_limit,omitempty"`    // requests per second
	BuildContext   string            `yaml:"build_context,omitempty"` // path to dir with docker-compose.yml (xbow)
	ServiceName    string            `yaml:"service_name,omitempty"`  // docker-compose service to get mapped port from
	InternalPort   int               `yaml:"internal_port,omitempty"` // port inside the container
}

// Setup holds optional pre-test configuration like auth flows.
type Setup struct {
	AuthFlow []AuthStep `yaml:"auth_flow,omitempty"`
}

// AuthStep is a single step in an authentication flow.
type AuthStep struct {
	Name    string            `yaml:"name"`
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty"`
	Extract map[string]string `yaml:"extract,omitempty"` // key -> JSONPath
}

// TestCase defines a single benchmark test.
type TestCase struct {
	ID           string            `yaml:"id"`
	Endpoint     string            `yaml:"endpoint"`
	Method       string            `yaml:"method"`
	Headers      map[string]string `yaml:"headers,omitempty"`
	Body         string            `yaml:"body,omitempty"`
	Modules      []string          `yaml:"modules"`
	VulnTypes    []string          `yaml:"vuln_types,omitempty"`
	Assertion    string            `yaml:"assertion"` // strict | soft | negative
	MinFindings  int               `yaml:"min_findings,omitempty"`
	ScanMode     string            `yaml:"scan_mode"` // active | passive
	Description  string            `yaml:"description,omitempty"`
	Timeout      time.Duration     `yaml:"timeout,omitempty"`
	RequiresOAST bool              `yaml:"requires_oast,omitempty"`
}

// TestResult captures the outcome of a single test case execution.
type TestResult struct {
	TestCase     TestCase
	ModuleID     string
	FindingCount int
	Passed       bool
	Error        error
	Duration     time.Duration
}

// BenchmarkReport is a summary of all test results for one definition file.
type BenchmarkReport struct {
	AppName    string
	Results    []TestResult
	TotalTests int
	Passed     int
	Failed     int
	Skipped    int
	Duration   time.Duration
}

// CoverageEntry tracks module coverage across benchmark definitions.
type CoverageEntry struct {
	ModuleID   string
	ModuleType string // active | passive
	Apps       []string
	TestCount  int
	Covered    bool
}

// CoverageReport provides a full module coverage matrix.
type CoverageReport struct {
	Entries        []CoverageEntry
	TotalActive    int
	CoveredActive  int
	TotalPassive   int
	CoveredPassive int
	TotalTestCases int
}
