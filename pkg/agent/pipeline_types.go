package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// PipelinePhase identifies a phase in the multi-phase scanning pipeline.
type PipelinePhase string

const (
	PhaseDiscover PipelinePhase = "discover"
	PhasePlan     PipelinePhase = "plan"
	PhaseScan     PipelinePhase = "scan"
	PhaseTriage   PipelinePhase = "triage"
	PhaseRescan   PipelinePhase = "rescan"
	PhaseReport   PipelinePhase = "report"
)

// AllPipelinePhases returns the ordered list of pipeline phases.
func AllPipelinePhases() []PipelinePhase {
	return []PipelinePhase{
		PhaseDiscover, PhasePlan, PhaseScan,
		PhaseTriage, PhaseRescan, PhaseReport,
	}
}

// AttackPlan is the structured output from the plan agent checkpoint (phase 2).
// The agent analyzes discovery results and produces a scanning strategy.
type AttackPlan struct {
	ModuleTags []string          `json:"module_tags"`
	ModuleIDs  []string          `json:"module_ids,omitempty"`
	FocusAreas []string          `json:"focus_areas,omitempty"`
	SkipPaths  []string          `json:"skip_paths,omitempty"`
	Endpoints  []PlannedEndpoint `json:"endpoints,omitempty"`
	Notes      string            `json:"notes,omitempty"`
}

// PlannedEndpoint represents a prioritized endpoint in the attack plan.
type PlannedEndpoint struct {
	URL       string   `json:"url"`
	Method    string   `json:"method,omitempty"`
	Priority  string   `json:"priority"` // high, medium, low
	Rationale string   `json:"rationale,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

// TriageResult is the structured output from the triage agent checkpoint (phase 4).
// The agent reviews findings and decides whether additional scanning is needed.
type TriageResult struct {
	Confirmed      []TriagedFinding `json:"confirmed"`
	FalsePositives []TriagedFinding `json:"false_positives"`
	FollowUps      []FollowUpScan   `json:"follow_up_scans,omitempty"`
	Verdict        string           `json:"verdict"` // "done" or "rescan"
	Notes          string           `json:"notes,omitempty"`
}

// TriagedFinding is a finding that has been reviewed by the triage agent.
type TriagedFinding struct {
	Title    string `json:"title"`
	ModuleID string `json:"module_id,omitempty"`
	URL      string `json:"url,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// FollowUpScan describes a targeted rescan recommended by the triage agent.
type FollowUpScan struct {
	URL        string   `json:"url"`
	Method     string   `json:"method,omitempty"`
	ModuleTags []string `json:"module_tags,omitempty"`
	ModuleIDs  []string `json:"module_ids,omitempty"`
	Rationale  string   `json:"rationale,omitempty"`
}

// PipelineConfig configures a pipeline run.
type PipelineConfig struct {
	TargetURL       string
	AgentName       string
	Focus           string
	RepoPath        string
	Files           []string
	MaxRescanRounds int
	SkipPhases      map[PipelinePhase]bool
	StartFrom       PipelinePhase
	DryRun          bool
	StreamWriter    io.Writer
	ProjectUUID     string
	ScanUUID        string

	// DiscoverFunc runs the discovery phase (deparos + spidering).
	// It should populate the database with HTTP records.
	DiscoverFunc func(ctx context.Context) error

	// ScanFunc runs the dynamic assessment phase with the given module filters.
	// moduleTags and moduleIDs come from the agent's attack plan.
	ScanFunc func(ctx context.Context, moduleTags []string, moduleIDs []string) error

	// PhaseCallback is called when a pipeline phase starts.
	// Used by the API server to emit SSE phase events and update status.
	PhaseCallback func(phase PipelinePhase)
}

// PipelineResult holds the outcome of a full pipeline run.
type PipelineResult struct {
	Plan           *AttackPlan     `json:"plan,omitempty"`
	TriageResults  []*TriageResult `json:"triage_results,omitempty"`
	TotalFindings  int             `json:"total_findings"`
	Confirmed      int             `json:"confirmed"`
	FalsePositives int             `json:"false_positives"`
	RescanRounds   int             `json:"rescan_rounds"`
	PhasesRun      []PipelinePhase `json:"phases_run"`
	Duration       time.Duration   `json:"duration"`
}

// attackPlanWrapper wraps AttackPlan for JSON parsing flexibility.
type attackPlanWrapper struct {
	Plan AttackPlan `json:"plan"`
}

// triageResultWrapper wraps TriageResult for JSON parsing flexibility.
type triageResultWrapper struct {
	Triage TriageResult `json:"triage"`
}

// ParseAttackPlan extracts an AttackPlan from raw agent output.
func ParseAttackPlan(raw string) (*AttackPlan, error) {
	jsonStr, err := extractJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JSON from agent output: %w", err)
	}

	// Try wrapped format: {"plan": {...}}
	var wrapper attackPlanWrapper
	if err := json.Unmarshal([]byte(jsonStr), &wrapper); err == nil && len(wrapper.Plan.ModuleTags) > 0 {
		return &wrapper.Plan, nil
	}

	// Try direct format: {...}
	var plan AttackPlan
	if err := json.Unmarshal([]byte(jsonStr), &plan); err == nil && len(plan.ModuleTags) > 0 {
		return &plan, nil
	}

	return nil, fmt.Errorf("failed to parse attack plan from JSON: invalid structure (expected module_tags)")
}

// ParseTriageResult extracts a TriageResult from raw agent output.
func ParseTriageResult(raw string) (*TriageResult, error) {
	jsonStr, err := extractJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JSON from agent output: %w", err)
	}

	// Try wrapped format: {"triage": {...}}
	var wrapper triageResultWrapper
	if err := json.Unmarshal([]byte(jsonStr), &wrapper); err == nil && wrapper.Triage.Verdict != "" {
		return &wrapper.Triage, nil
	}

	// Try direct format: {...}
	var result TriageResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err == nil && result.Verdict != "" {
		return &result, nil
	}

	return nil, fmt.Errorf("failed to parse triage result from JSON: invalid structure (expected verdict)")
}
