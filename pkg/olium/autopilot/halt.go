// Package autopilot implements the olium-backed autopilot mode — a single
// long-running AI loop that plans and executes its own security scan
// workflow, with full access to olium's tool registry plus two autopilot-
// specific tools (halt_scan, report_finding) that let the model signal
// completion and persist findings to the database.
package autopilot

import (
	"context"
	"sync"

	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// HaltSignal is a thread-safe halt flag shared between the halt_scan tool
// and the autopilot's outer loop. The loop checks the flag after each
// assistant turn and exits cleanly when the model has called halt_scan.
type HaltSignal struct {
	mu     sync.Mutex
	halted bool
	reason string
}

// Halted returns whether halt was requested and (optionally) the reason.
func (h *HaltSignal) Halted() (bool, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.halted, h.reason
}

// Set marks the signal as halted. Subsequent calls are ignored.
func (h *HaltSignal) Set(reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.halted {
		h.halted = true
		h.reason = reason
	}
}

// haltTool is the tool form of HaltSignal — the model invokes it to end
// the scan early with a structured reason.
type haltTool struct{ signal *HaltSignal }

// NewHaltTool constructs the halt_scan tool bound to the given signal.
func NewHaltTool(signal *HaltSignal) tool.Tool { return &haltTool{signal: signal} }

func (*haltTool) Name() string     { return "halt_scan" }
func (*haltTool) Label() string    { return "Halt scan" }
func (*haltTool) Category() string { return tool.CategoryVigolium }
func (*haltTool) IsReadOnly() bool { return false }
func (*haltTool) Description() string {
	return "Signal that the autopilot scan is complete and no further work is needed. Call this when you've finished auditing, reported findings, and have nothing productive left to do. The outer loop will exit after you return. Provide a short reason for the audit log."
}

func (*haltTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"reason": map[string]any{
				"type":        "string",
				"description": "Short explanation of why you're stopping (e.g., 'scope audited, 3 findings reported, nothing more to investigate').",
			},
		},
		"required": []string{"reason"},
	}
}

func (h *haltTool) Execute(ctx context.Context, args map[string]any, onUpdate tool.UpdateFn) (tool.Result, error) {
	reason, _ := args["reason"].(string)
	if reason == "" {
		reason = "(no reason provided)"
	}
	h.signal.Set(reason)
	return tool.Result{
		Content: "Halt requested. The autopilot will exit after this turn completes.",
	}, nil
}
