package provider

import (
	"context"

	"github.com/vigolium/vigolium/pkg/olium/auth"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// GoogleVertex is the Vertex provider variant that routes Gemini models
// to the publishers/google endpoint. The transport (HTTP client, GCP
// auth, project/location resolution) is shared with AnthropicVertex via
// the internal vertexTransport — only model-prefix validation and Name()
// differ.
type GoogleVertex struct {
	t *vertexTransport
}

// NewGoogleVertex builds the Gemini-on-Vertex provider. project/location
// must be resolved by the caller (env > YAML > SA-file fallback for
// project, env > YAML > "us-central1" default for location).
func NewGoogleVertex(a *auth.VertexAuth, project, location string) *GoogleVertex {
	return &GoogleVertex{t: newVertexTransport(a, project, location)}
}

func (*GoogleVertex) Name() string { return "google-vertex" }

// Stream forwards a Gemini-shaped request to publishers/google on Vertex.
// Non-gemini-* model ids fail fast since this provider key promises
// Gemini routing only — pick anthropic-vertex for Claude.
func (g *GoogleVertex) Stream(ctx context.Context, req Request) (<-chan stream.Event, error) {
	if err := g.t.requireProjectAndLocation("google-vertex"); err != nil {
		return nil, err
	}
	if err := g.t.requireModelPrefix("google-vertex", "gemini-", req.Model, "anthropic-vertex"); err != nil {
		return nil, err
	}
	return g.t.streamGemini(ctx, "google-vertex", req)
}
