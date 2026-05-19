// Package tool defines the Tool interface, registry, and shared types
// used by olium's agent loop to execute model-requested actions.
//
// The design mirrors pi-mono's AgentTool: a tool is a named function with
// a JSON-Schema-compatible parameter spec, a human label, and an Execute
// function that streams partial updates before returning a final Result.
package tool

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Tool categories. Used by the renderer (toollog) to distinguish vigolium-
// specific tools (run_scan, report_finding, etc.) from generic agent tools
// (bash, web_fetch, etc.). New tools default to CategoryBuiltin; only
// vigolium-domain tools should declare CategoryVigolium.
const (
	CategoryBuiltin  = "builtin"
	CategoryVigolium = "vigolium"
)

// Result is what a tool returns on success (or on handled failure with IsError=true).
type Result struct {
	// Content is the primary payload the model consumes as a string.
	// For structured tools (file reads, grep matches) this is the rendered text.
	Content string `json:"content"`
	// Details is optional structured metadata the TUI can show alongside Content.
	Details map[string]any `json:"details,omitempty"`
	// IsError marks a handled failure — the loop still continues but the model
	// sees the failure text as the tool result.
	IsError bool `json:"isError,omitempty"`
}

// UpdateFn streams partial results back to the event sink while a tool is
// still running. Used for long-running commands (bash) to show live stdout.
type UpdateFn func(partial Result)

// ApprovalFn is consulted before running tools that pattern-match as
// dangerous. Return true to allow execution, false to block. A blocked
// call returns a tool result with IsError=true and a skip message.
type ApprovalFn func(ctx context.Context, toolName string, args map[string]any, reason string) bool

// Tool is the contract every built-in tool implements.
type Tool interface {
	Name() string
	Label() string
	Description() string
	// Schema returns a JSON Schema-compatible map describing the tool's
	// parameters. Providers (Codex, Anthropic) each wrap this in their
	// own declaration envelope.
	Schema() map[string]any
	// Category groups tools for renderer purposes — CategoryBuiltin for
	// generic agent tools (bash, web_fetch) and CategoryVigolium for
	// scanner-domain tools (run_scan, report_finding). The toollog uses
	// it to color the output arrow.
	Category() string
	// IsReadOnly reports whether this tool has no observable side effects
	// — no filesystem writes, no network mutations, no DB writes. The
	// engine fans out read-only tool calls in parallel within a single
	// turn; anything that returns false runs strictly serially.
	//
	// When in doubt, return false. False positives just lose
	// concurrency; false negatives can corrupt state.
	IsReadOnly() bool
	// Execute runs the tool. ctx carries cancellation. onUpdate may be nil.
	Execute(ctx context.Context, args map[string]any, onUpdate UpdateFn) (Result, error)
}

// Registry holds the set of tools available to an Engine.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{tools: map[string]Tool{}}
}

// Register adds a tool. Duplicate names replace the prior entry.
func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name()] = t
}

// Get returns a tool by name, or an error if unknown.
func (r *Registry) Get(name string) (Tool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
	return t, nil
}

// List returns registered tools sorted by name — stable ordering matters
// for provider tool declarations so prompt caching can kick in.
func (r *Registry) List() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
