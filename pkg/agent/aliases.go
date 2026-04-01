package agent

// This file re-exports types from the agenttypes subpackage via type aliases.
// External code continues to use agent.X as before — aliases are transparent.
//
// Only symbols with external consumers (outside pkg/agent/) are re-exported here.
// Internal-only symbols use direct subpackage imports in their consuming files.

import (
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/agent/backend"
	agentinput "github.com/vigolium/vigolium/pkg/agent/input"
	"github.com/vigolium/vigolium/pkg/agent/parsing"
	agentprompt "github.com/vigolium/vigolium/pkg/agent/prompt"
)

// Core types
type (
	RunResult      = agenttypes.RunResult
	Options        = agenttypes.Options
	Result         = agenttypes.Result
	PromptTemplate = agenttypes.PromptTemplate
	TemplateData   = agenttypes.TemplateData
	RetryConfig    = agenttypes.RetryConfig
)

// Findings & HTTP records
type (
	AgentFinding           = agenttypes.AgentFinding
	AgentFindingsOutput    = agenttypes.AgentFindingsOutput
	AgentHTTPRecord        = agenttypes.AgentHTTPRecord
	AgentHTTPRecordsOutput = agenttypes.AgentHTTPRecordsOutput
)

// Exploitation evidence
type ExploitationEvidence = agenttypes.ExploitationEvidence

// Pipeline types
type (
	AttackPlan            = agenttypes.AttackPlan
	PlannedEndpoint       = agenttypes.PlannedEndpoint
	TriageResult          = agenttypes.TriageResult
	TriagedFinding        = agenttypes.TriagedFinding
	FollowUpScan          = agenttypes.FollowUpScan
	SourceAnalysisResult  = agenttypes.SourceAnalysisResult
	AgentSessionConfig    = agenttypes.AgentSessionConfig
	AgentSessionEntry     = agenttypes.AgentSessionEntry
	AgentLoginFlow        = agenttypes.AgentLoginFlow
	AgentExpectResponse   = agenttypes.AgentExpectResponse
	AgentExtractRule      = agenttypes.AgentExtractRule
	GeneratedExtension    = agenttypes.GeneratedExtension
	QuickCheck            = agenttypes.QuickCheck
	QuickCheckRequest     = agenttypes.QuickCheckRequest
	QuickCheckMatch       = agenttypes.QuickCheckMatch
	Snippet               = agenttypes.Snippet
	SwarmPlan             = agenttypes.SwarmPlan
	BatchProvenance       = agenttypes.BatchProvenance
	TokenUsage            = agenttypes.TokenUsage
	ProgressEvent         = agenttypes.ProgressEvent
	SwarmResult           = agenttypes.SwarmResult
	SwarmCheckpoint       = agenttypes.SwarmCheckpoint
	ScanRequest           = agenttypes.ScanRequest
	ScanFunc              = agenttypes.ScanFunc
	SDKSessionEntry       = agenttypes.SDKSessionEntry
	SDKSessionManifest    = agenttypes.SDKSessionManifest
	SourceAnalysisConfig  = agenttypes.SourceAnalysisConfig
	AgentExtensionsOutput = agenttypes.AgentExtensionsOutput
	RepairConfig          = agenttypes.RepairConfig
)

// Extension validation types
type (
	InvalidExtension    = agenttypes.InvalidExtension
	QuickCheckLintIssue = agenttypes.QuickCheckLintIssue
)

// Autopilot types
type AutopilotPipelineResult = agenttypes.AutopilotPipelineResult

// Intent types
type (
	ScanIntent        = agenttypes.ScanIntent
	SetupCleanup      = agenttypes.SetupCleanup
	AppIntent         = agenttypes.AppIntent
	IntentParseOption = agenttypes.IntentParseOption
	IntentParseConfig = agenttypes.IntentParseConfig
)

// Input types
type InputType = agenttypes.InputType

// Audit types
type (
	AuditAgentConfig = agenttypes.AuditAgentConfig
	AuditAgentStatus = agenttypes.AuditAgentStatus
)

// Re-export constants. Go type aliases preserve constant compatibility
// for typed constants, but untyped string constants must be re-declared.
const (
	// Evidence status
	EvidenceStatusExploited     = agenttypes.EvidenceStatusExploited
	EvidenceStatusBlocked       = agenttypes.EvidenceStatusBlocked
	EvidenceStatusFalsePositive = agenttypes.EvidenceStatusFalsePositive

	// InputType
	InputTypeURL        = agenttypes.InputTypeURL
	InputTypeCurl       = agenttypes.InputTypeCurl
	InputTypeBurp       = agenttypes.InputTypeBurp
	InputTypeRaw        = agenttypes.InputTypeRaw
	InputTypeBase64     = agenttypes.InputTypeBase64
	InputTypeRecordUUID = agenttypes.InputTypeRecordUUID
	InputTypeUnknown    = agenttypes.InputTypeUnknown

	// SwarmPhase
	SwarmPhaseNormalize      = agenttypes.SwarmPhaseNormalize
	SwarmPhaseAuth           = agenttypes.SwarmPhaseAuth
	SwarmPhaseSourceAnalysis = agenttypes.SwarmPhaseSourceAnalysis
	SwarmPhaseCodeAudit      = agenttypes.SwarmPhaseCodeAudit
	SwarmPhaseSAST           = agenttypes.SwarmPhaseSAST
	SwarmPhaseSASTReview     = agenttypes.SwarmPhaseSASTReview
	SwarmPhaseDiscover       = agenttypes.SwarmPhaseDiscover
	SwarmPhasePlan           = agenttypes.SwarmPhasePlan
	SwarmPhaseExtension      = agenttypes.SwarmPhaseExtension
	SwarmPhaseScan           = agenttypes.SwarmPhaseScan
	SwarmPhaseTriage         = agenttypes.SwarmPhaseTriage
	SwarmPhaseRescan         = agenttypes.SwarmPhaseRescan
)

// Re-export functions with external consumers.
var (
	NormalizeSwarmPhase = agenttypes.NormalizeSwarmPhase
	PhaseSkipped        = agenttypes.PhaseSkipped
	WithSessionsDir     = agenttypes.WithSessionsDir
)

// Re-export backend functions with external consumers.
var (
	RunAgent                     = backend.RunAgent
	Ping                         = backend.Ping
	CleanupSessionDirs           = backend.CleanupSessionDirs
	AgentSessionConfigToSessions = backend.AgentSessionConfigToSessions
)

// Re-export parsing functions with external consumers.
var (
	ParseFindings    = parsing.ParseFindings
	ParseHTTPRecords = parsing.ParseHTTPRecords
	ToDBFinding      = parsing.ToDBFinding
)

// Re-export input functions with external consumers.
var TargetURLFromInput = agentinput.TargetURLFromInput

// Re-export prompt functions with external consumers.
var (
	ListTemplates       = agentprompt.ListTemplates
	ResolveTemplatePath = agentprompt.ResolveTemplatePath
)

// Package-local aliases for prompt functions used within the agent package.
var (
	enrichContextFromDB   = agentprompt.EnrichContextFromDB
	enrichContextModules  = agentprompt.EnrichContextModules
	enrichContextCommands = agentprompt.EnrichContextCommands
	hostnameFromURL       = agentprompt.HostnameFromURL
)
