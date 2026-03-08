package agent

import "io"

// Options holds parameters for a single agent run.
type Options struct {
	// Agent selection
	AgentName string // name from config (e.g. "claude")

	// Prompt mode: template-based or inline
	PromptTemplate string // template ID (e.g. "security-code-review")
	PromptFile     string // path to a prompt file
	PromptInline   string // inline prompt string
	Stdin          bool   // read prompt from stdin

	// Context
	RepoPath  string   // path to source code repository
	Files     []string // specific files to include (relative to RepoPath)
	Source    string   // source identifier for findings
	Append    string   // extra text appended to the rendered prompt
	TargetURL string   // target URL for scanning context
	Hostname  string   // target hostname (derived from TargetURL if empty)

	// Output
	OutputPath   string    // write agent output to this file
	DryRun       bool      // render prompt and print it, don't execute agent
	ScanUUID     string    // scan UUID to attach findings to
	ProjectUUID  string    // project UUID for data scoping
	StreamWriter io.Writer `json:"-"` // when non-nil, agent output is streamed here in real-time

	// Autopilot mode
	Autopilot    bool // enable terminal execution for autonomous scanning
	MaxCommands  int  // max terminal commands the agent can run (0 = default 100)
}

// Result holds the outcome of an agent run.
type Result struct {
	AgentName    string            `json:"agent_name"`
	TemplateID   string            `json:"template_id,omitempty"`
	RawOutput    string            `json:"raw_output"`
	Stderr       string            `json:"stderr,omitempty"`
	Findings     []AgentFinding    `json:"findings,omitempty"`
	HTTPRecords  []AgentHTTPRecord `json:"http_records,omitempty"`
	OutputSchema string            `json:"output_schema,omitempty"` // "findings" or "http_records"
	SavedCount   int               `json:"saved_count"`
	SkippedCount int               `json:"skipped_count"`
	DryRun       bool              `json:"dry_run,omitempty"`
}

// PromptTemplate represents a parsed prompt template with frontmatter metadata.
type PromptTemplate struct {
	ID           string            `yaml:"id"`
	Name         string            `yaml:"name"`
	Description  string            `yaml:"description"`
	OutputSchema string            `yaml:"output_schema"` // "findings" or "http_records"
	Variables    []string          `yaml:"variables"`
	Body         string            `yaml:"-"`
	Source       string            `yaml:"-"` // "embedded", "user", "config"
}

// TemplateData holds the variables passed to a prompt template.
type TemplateData struct {
	SourceCode string
	Language   string
	Framework  string
	FilePath   string
	RepoPath   string
	TargetURL  string
	Hostname   string
	Endpoints           string
	Extra               map[string]string
	PreviousFindings    string // JSON array of findings from DB
	DiscoveredEndpoints string // JSON array of HTTP records from DB
	HighRiskEndpoints   string // JSON array of top risk-scored HTTP records from DB
	ModuleList          string // JSON array of available scanner modules
	ScanStats           string // JSON object of scan statistics
	AvailableCommands   string // hardcoded CLI command reference
}

// AgentFinding represents a single finding reported by an AI agent.
type AgentFinding struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence,omitempty"`
	File        string   `json:"file,omitempty"`
	Line        int      `json:"line,omitempty"`
	Snippet     string   `json:"snippet,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// AgentFindingsOutput is the expected JSON output for findings-type templates.
type AgentFindingsOutput struct {
	Findings []AgentFinding `json:"findings"`
}

// AgentHTTPRecord represents an HTTP request/response pair reported by an AI agent.
type AgentHTTPRecord struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	Notes   string            `json:"notes,omitempty"`
}

// AgentHTTPRecordsOutput is the expected JSON output for http_records-type templates.
type AgentHTTPRecordsOutput struct {
	HTTPRecords []AgentHTTPRecord `json:"http_records"`
}

