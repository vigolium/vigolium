package agent

import (
	"context"
	"io"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
)

// fakeRuntime is a test double for AgentRuntime — it records dispatch and
// returns canned output without touching a provider, the network, or the olium
// engine.
type fakeRuntime struct {
	runPromptCalls atomic.Int32
	sessionCalls   atomic.Int32
	output         string
}

func (f *fakeRuntime) RunPrompt(_ context.Context, _ *config.OliumConfig, _ string, _, _ io.Writer, _ string, _ bool) (oliumRunOutput, error) {
	f.runPromptCalls.Add(1)
	return oliumRunOutput{Text: f.output}, nil
}

func (f *fakeRuntime) RunOnSession(_ context.Context, _ *config.OliumConfig, _ AgentSession, _ string, _, _ io.Writer, _ bool) (oliumRunOutput, error) {
	return oliumRunOutput{Text: f.output}, nil
}

func (f *fakeRuntime) NewSession(_ *config.OliumConfig, _ string) (AgentSession, error) {
	f.sessionCalls.Add(1)
	return fakeSession{}, nil
}

func (f *fakeRuntime) NewSessionWithSpec(_ *config.OliumConfig, _ SessionSpec) (AgentSession, error) {
	f.sessionCalls.Add(1)
	return fakeSession{}, nil
}

type fakeSession struct{}

func (fakeSession) Fork() AgentSession { return fakeSession{} }

// TestEngineDispatchesThroughInjectedRuntime proves the engine depends on the
// AgentRuntime interface rather than the concrete olium engine: a fake runtime
// drives a full Run with no provider, network, or olium engine involved. Before
// the decoupling this was impossible — engine.go called the olium dispatch
// helpers directly.
func TestEngineDispatchesThroughInjectedRuntime(t *testing.T) {
	t.Parallel()
	fake := &fakeRuntime{output: "result from fake runtime"}
	e := &Engine{runtime: fake}

	res, err := e.Run(context.Background(), Options{PromptInline: "find vulns"})
	require.NoError(t, err)
	require.Equal(t, int32(1), fake.runPromptCalls.Load(), "Run must dispatch through the injected runtime")
	require.Contains(t, res.RawOutput, "result from fake runtime")
}
