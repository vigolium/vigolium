package jsext

import (
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/llm"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/oast"
)

// APIOptions lives in pkg/jsext/api; it is re-exported here via an alias in
// api_aliases.go.

// EngineOptions provides scanner context to the JS engine.
// These come from the runner at engine creation time.
type EngineOptions struct {
	ScopeMatcher *config.ScopeMatcher
	ScopeConfig  *config.ScopeConfig
	ScanUUID     string
	Repository   *database.Repository

	// LLMClient enables vigolium.agent.* API (nil = disabled)
	LLMClient llm.Client

	// OASTService enables vigolium.oast.* API (nil = disabled)
	OASTService *oast.Service
}
