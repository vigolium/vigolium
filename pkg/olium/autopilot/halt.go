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

// HaltSource identifies who tripped the halt signal. The post-halt coverage
// loop only re-enters when the source is HaltSourceModel — a budget-driven
// halt means the operator's cost cap is already exhausted, and any extra
// turns would violate that cap.
type HaltSource int

const (
	// HaltSourceUnset is the zero value before any Set call.
	HaltSourceUnset HaltSource = iota
	// HaltSourceModel was set by the halt_scan tool fired by the model.
	HaltSourceModel
	// HaltSourceBudget was set by the outer loop's wall-time or token cap.
	HaltSourceBudget
)

// HaltSignal is a thread-safe halt flag shared between the halt_scan tool
// and the autopilot's outer loop. The loop checks the flag after each
// assistant turn and exits cleanly when the model has called halt_scan.
type HaltSignal struct {
	mu     sync.Mutex
	halted bool
	reason string
	source HaltSource
}

// Halted returns whether halt was requested and (optionally) the reason.
func (h *HaltSignal) Halted() (bool, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.halted, h.reason
}

// Source returns the most recent halt source. HaltSourceUnset when no halt
// has fired yet — useful for distinguishing budget-driven exits from
// model-driven ones in the post-halt coverage loop.
func (h *HaltSignal) Source() HaltSource {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.source
}

// SetByModel marks the signal as halted on behalf of the halt_scan tool.
// Subsequent calls of any kind are ignored until Reset is called.
func (h *HaltSignal) SetByModel(reason string) {
	h.set(reason, HaltSourceModel)
}

// SetByBudget marks the signal as halted on behalf of the autopilot's wall-
// time or token budget enforcement. Same idempotency contract as
// SetByModel.
func (h *HaltSignal) SetByBudget(reason string) {
	h.set(reason, HaltSourceBudget)
}

func (h *HaltSignal) set(reason string, src HaltSource) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.halted {
		h.halted = true
		h.reason = reason
		h.source = src
	}
}

// Reset clears the halt flag so a re-entry can observe a fresh signal.
// Preserves the previous source so the caller can decide whether a re-entry
// is appropriate before calling Reset. After Reset, Halted returns false
// and Source returns HaltSourceUnset.
func (h *HaltSignal) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.halted = false
	h.reason = ""
	h.source = HaltSourceUnset
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
	h.signal.SetByModel(reason)
	return tool.Result{
		Content: "Halt requested. The autopilot will exit after this turn completes.",
	}, nil
}
