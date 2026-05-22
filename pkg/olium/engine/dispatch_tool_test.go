package engine

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/provider"
)

// TestDispatchToolNilRegistryReturnsErrorNotPanic verifies that a tools-less
// engine (Config.Tools == nil, e.g. the single-turn guardrail classifier) does
// not panic on a hallucinated tool call: dispatchTool returns a recoverable
// error result instead of dereferencing the nil registry.
func TestDispatchToolNilRegistryReturnsErrorNotPanic(t *testing.T) {
	eng := &Engine{} // zero Config → Tools is nil

	out := make(chan Event, 4)
	res := eng.dispatchTool(
		context.Background(),
		provider.ToolCall{ID: "1", Name: "bash", Args: map[string]any{"cmd": "ls"}},
		out,
	)

	if !res.IsError {
		t.Fatalf("expected an error result for a tool call on a tools-less engine, got: %+v", res)
	}
}
