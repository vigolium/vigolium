package provider

import (
	"context"

	"github.com/vigolium/vigolium/pkg/olium/auth"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// AnthropicVertex is the Vertex provider variant that routes Claude models
// to the publishers/anthropic endpoint. The transport (HTTP client, GCP
// auth, project/location resolution) is shared with GoogleVertex via the
// internal vertexTransport — only model-prefix validation and Name() differ.
type AnthropicVertex struct {
	t *vertexTransport
}

// NewAnthropicVertex builds the Anthropic-on-Vertex provider. project/
// location must be resolved by the caller (env > YAML > SA-file fallback
// for project, env > YAML > "us-central1" default for location).
func NewAnthropicVertex(a *auth.VertexAuth, project, location string) *AnthropicVertex {
	return &AnthropicVertex{t: newVertexTransport(a, project, location)}
}

func (*AnthropicVertex) Name() string { return "anthropic-vertex" }

// Stream forwards a Claude-shaped request to publishers/anthropic on
// Vertex. Non-claude-* model ids fail fast since this provider key
// promises Anthropic routing only — pick google-vertex for Gemini.
func (a *AnthropicVertex) Stream(ctx context.Context, req Request) (<-chan stream.Event, error) {
	if err := a.t.requireProjectAndLocation("anthropic-vertex"); err != nil {
		return nil, err
	}
	if err := a.t.requireModelPrefix("anthropic-vertex", "claude-", req.Model, "google-vertex"); err != nil {
		return nil, err
	}
	return a.t.streamAnthropic(ctx, "anthropic-vertex", req)
}
