// Package agenttypes defines shared data types used across the agent subsystem.
// It is the leaf of the dependency DAG — subpackages import agenttypes, not root agent.
package agenttypes

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"time"
)

// RunResult holds the output of an agent run (any protocol).
type RunResult struct {
	Stdout    string
	Stderr    string
	SessionID string // session ID for resume
}

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
	SourcePath  string   // path to source code repository (--source flag)
	Files       []string // specific files to include (relative to SourcePath)
	Source      string   // source identifier for findings
	Append      string   // extra text appended to the rendered prompt
	Instruction string   // user-provided custom instruction appended to the prompt
	TargetURL   string   // target URL for scanning context
	Hostname    string   // target hostname (derived from TargetURL if empty)

	// Output
	OutputPath   string    // write agent output to this file
	DryRun       bool      // render prompt and print it, don't execute agent
	ShowPrompt   bool      // print rendered prompt to stderr before executing
	ScanUUID     string    // scan UUID to attach findings to
	ProjectUUID  string    // project UUID for data scoping
	StreamWriter io.Writer `json:"-"` // when non-nil, agent output is streamed here in real-time

	// Extra template data (injected into {{.Extra}} in prompt templates)
	Extra map[string]string `json:"-"`

	// Session isolation: when set, overrides the pool map key to prevent context
	// accumulation across phases that share the same agent backend.
	SessionKey string `json:"-"`

	// SessionID is a pre-generated UUID passed as --session-id to the Claude CLI (SDK mode only).
	// Enables session persistence so the conversation can be resumed with `claude --resume <id>`.
	SessionID string `json:"-"`

	// Autopilot mode
	Autopilot     bool   // enable autonomous scanning
	MaxCommands   int    // max agent turns (0 = default 100)
	Effort        string // SDK effort level override (e.g. "low", "medium", "high"); empty = default
	SessionWeight int    `json:"-"` // session weight for pool scheduling (0 = default)
	SessionDir    string `json:"-"` // session directory for artifacts (SDK: CLAUDE.md written here for system prompt)

	// Retry: when non-nil, retries transient agent failures with exponential backoff.
	Retry *RetryConfig `json:"-"`
}

// Result holds the outcome of an agent run.
type Result struct {
	AgentName      string                 `json:"agent_name"`
	TemplateID     string                 `json:"template_id,omitempty"`
	SessionID      string                 `json:"session_id,omitempty"` // session ID for resume (e.g. claude --resume <id>)
	RawOutput      string                 `json:"raw_output"`
	RenderedPrompt string                 `json:"-"` // rendered prompt sent to agent (not serialized)
	Stderr         string                 `json:"stderr,omitempty"`
	Findings       []AgentFinding         `json:"findings,omitempty"`
	HTTPRecords    []AgentHTTPRecord      `json:"http_records,omitempty"`
	Evidence       []ExploitationEvidence `json:"evidence,omitempty"`
	OutputSchema   string                 `json:"output_schema,omitempty"` // "findings" or "http_records"
	SavedCount     int                    `json:"saved_count"`
	SkippedCount   int                    `json:"skipped_count"`
	DryRun         bool                   `json:"dry_run,omitempty"`
}

// PromptTemplate represents a parsed prompt template with frontmatter metadata.
type PromptTemplate struct {
	ID           string   `yaml:"id"`
	Name         string   `yaml:"name"`
	Description  string   `yaml:"description"`
	OutputSchema string   `yaml:"output_schema"` // "findings" or "http_records"
	Variables    []string `yaml:"variables"`
	Body         string   `yaml:"-"`
	Source       string   `yaml:"-"` // "embedded", "user", "config"
}

// TemplateData holds the variables passed to a prompt template.
type TemplateData struct {
	SourceCode          string
	Language            string
	Framework           string
	FilePath            string
	SourcePath          string
	DirectoryTree       string
	SkipGuidance        string
	SourceHint          string
	TargetURL           string
	Hostname            string
	Endpoints           string
	Extra               map[string]string
	PreviousFindings    string // JSON array of findings from DB
	DiscoveredEndpoints string // JSON array of HTTP records from DB
	HighRiskEndpoints   string // JSON array of top risk-scored HTTP records from DB
	ModuleList          string // JSON array of available scanner modules
	ModuleTags          string // JSON array of unique module tags
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

// UnmarshalJSON implements lenient parsing for AgentFinding.
// Handles: line as string ("42"), tags as single string, severity as int.
func (f *AgentFinding) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if v, ok := raw["title"]; ok {
		f.Title = fmt.Sprint(v)
	}
	if v, ok := raw["description"]; ok {
		f.Description = fmt.Sprint(v)
	}
	if v, ok := raw["severity"]; ok {
		f.Severity = fmt.Sprint(v)
	}
	if v, ok := raw["confidence"]; ok {
		f.Confidence = fmt.Sprint(v)
	}
	if v, ok := raw["file"]; ok {
		f.File = fmt.Sprint(v)
	}
	if v, ok := raw["line"]; ok {
		f.Line = flexInt(v)
	}
	if v, ok := raw["snippet"]; ok {
		f.Snippet = fmt.Sprint(v)
	}
	if v, ok := raw["cwe"]; ok {
		f.CWE = fmt.Sprint(v)
	}
	if v, ok := raw["tags"]; ok {
		f.Tags = flexStringSlice(v)
	}
	return nil
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

// UnmarshalJSON implements custom unmarshaling that tolerates the body field
// being a JSON object/array instead of a string. LLMs frequently output
// "body": {"key":"value"} instead of "body": "{\"key\":\"value\"}".
// This detects non-string body values and re-serializes them to a JSON string.
func (r *AgentHTTPRecord) UnmarshalJSON(data []byte) error {
	// Use a raw alias to avoid infinite recursion.
	type raw struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers,omitempty"`
		Body    json.RawMessage   `json:"body,omitempty"`
		Notes   string            `json:"notes,omitempty"`
	}
	var v raw
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	r.Method = v.Method
	r.URL = v.URL
	r.Headers = v.Headers
	r.Notes = v.Notes

	if len(v.Body) == 0 {
		return nil
	}

	// Try unmarshaling as a string first (the expected case).
	var s string
	if err := json.Unmarshal(v.Body, &s); err == nil {
		r.Body = s
		return nil
	}

	// Body is a JSON object/array — re-serialize it to a string.
	// Use compact encoding to match what the LLM likely intended.
	r.Body = string(v.Body)
	return nil
}

// AgentHTTPRecordsOutput is the expected JSON output for http_records-type templates.
type AgentHTTPRecordsOutput struct {
	HTTPRecords []AgentHTTPRecord `json:"http_records"`
}

// Evidence status values.
const (
	EvidenceStatusExploited     = "exploited"
	EvidenceStatusBlocked       = "blocked"
	EvidenceStatusFalsePositive = "false_positive"
)

// ExploitationEvidence records proof that a finding is exploitable.
type ExploitationEvidence struct {
	FindingRef  string   `json:"finding_ref"`
	Status      string   `json:"status"`      // "exploited", "blocked", "false_positive"
	VulnClass   string   `json:"vuln_class"`
	Payload     string   `json:"payload"`
	Request     string   `json:"request"`
	Response    string   `json:"response"`
	Impact      string   `json:"impact"`
	Screenshots []string `json:"screenshots,omitempty"`
	Confidence  string   `json:"confidence"` // "proven", "likely", "unconfirmed"
	Notes       string   `json:"notes,omitempty"`
}

// RetryConfig controls retry behavior for agent calls.
type RetryConfig struct {
	MaxRetries    int           // maximum number of retries (default: 2)
	InitialDelay  time.Duration // initial backoff delay (default: 2s)
	MaxDelay      time.Duration // maximum backoff delay (default: 30s)
	BackoffFactor float64       // exponential backoff multiplier (default: 2.0)
}

// DefaultRetryConfig returns sensible defaults for agent call retries.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:    2,
		InitialDelay:  2 * time.Second,
		MaxDelay:      30 * time.Second,
		BackoffFactor: 2.0,
	}
}

// EffectiveMaxRetries returns MaxRetries or the default if unset.
// Use MaxRetries=-1 to explicitly disable retries (returns 0).
func (rc RetryConfig) EffectiveMaxRetries() int {
	if rc.MaxRetries < 0 {
		return 0
	}
	if rc.MaxRetries > 0 {
		return rc.MaxRetries
	}
	return 2
}

// EffectiveInitialDelay returns InitialDelay or the default if unset.
func (rc RetryConfig) EffectiveInitialDelay() time.Duration {
	if rc.InitialDelay > 0 {
		return rc.InitialDelay
	}
	return 2 * time.Second
}

// EffectiveMaxDelay returns MaxDelay or the default if unset.
func (rc RetryConfig) EffectiveMaxDelay() time.Duration {
	if rc.MaxDelay > 0 {
		return rc.MaxDelay
	}
	return 30 * time.Second
}

// EffectiveBackoffFactor returns BackoffFactor or the default if unset.
func (rc RetryConfig) EffectiveBackoffFactor() float64 {
	if rc.BackoffFactor > 0 {
		return rc.BackoffFactor
	}
	return 2.0
}

// BackoffDelay computes the next backoff delay given the current delay.
func (rc RetryConfig) BackoffDelay(current time.Duration) time.Duration {
	return time.Duration(math.Min(float64(current)*rc.EffectiveBackoffFactor(), float64(rc.EffectiveMaxDelay())))
}
