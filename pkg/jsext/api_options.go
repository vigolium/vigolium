package jsext

import (
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/llm"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/output"
)

// APIOptions holds all context needed to set up the vigolium.* JS API on a VM.
type APIOptions struct {
	ScriptID   string
	HTTPClient *http.Requester
	ConfigVars map[string]string

	// Scanner context (all nil-safe)
	ScopeMatcher *config.ScopeMatcher
	ScopeConfig  *config.ScopeConfig
	ScanUUID     string
	ProjectUUID  string

	// Security controls (from extensions config)
	AllowExec   bool   // gate for exec() and setEnv(); default false
	SandboxDir  string // base path for file ops; empty = cwd
	ExecTimeout int    // max seconds for exec(); default 30, cap 120

	// Finding emitter for hooks that want to create findings
	FindingEmitter func(*output.ResultEvent)

	// Database repository for ingest API (nil = ingest disabled)
	Repository *database.Repository

	// LLMClient enables vigolium.agent.* API (nil = disabled)
	LLMClient llm.Client
	// AgentDefs provides subprocess agent backends for vigolium.agent.run()
	AgentDefs map[string]config.AgentDef

	// OASTService enables vigolium.oast.* API (nil = disabled)
	OASTService *oast.Service
}

// EngineOptions provides scanner context to the JS engine.
// These come from the runner at engine creation time.
type EngineOptions struct {
	ScopeMatcher *config.ScopeMatcher
	ScopeConfig  *config.ScopeConfig
	ScanUUID     string
	Repository   *database.Repository

	// LLMClient enables vigolium.agent.* API (nil = disabled)
	LLMClient llm.Client
	// AgentDefs provides subprocess agent backends for vigolium.agent.run()
	AgentDefs map[string]config.AgentDef

	// OASTService enables vigolium.oast.* API (nil = disabled)
	OASTService *oast.Service
}
