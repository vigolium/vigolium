package agent

import (
	"context"
	"io"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/olium"
)

// fakeRuntime is a test double for AgentRuntime — it records dispatch and
// returns canned output without touching a provider, the network, or the olium
// engine.
type fakeRuntime struct {
	runPromptCalls    atomic.Int32
	sessionCalls      atomic.Int32
	runOnSessionCalls atomic.Int32
	lastSpec          SessionSpec
	output            string
}

func (f *fakeRuntime) RunPrompt(_ context.Context, _ *config.OliumConfig, _ string, _, _ io.Writer, _ string, _ bool, _ RecordSpec) (oliumRunOutput, error) {
	f.runPromptCalls.Add(1)
	return oliumRunOutput{Text: f.output}, nil
}

func (f *fakeRuntime) RunOnSession(_ context.Context, _ *config.OliumConfig, _ AgentSession, _ string, _, _ io.Writer, _ bool) (oliumRunOutput, error) {
	f.runOnSessionCalls.Add(1)
	return oliumRunOutput{Text: f.output}, nil
}

func (f *fakeRuntime) NewSession(_ *config.OliumConfig, _ string) (AgentSession, error) {
	f.sessionCalls.Add(1)
	return fakeSession{}, nil
}

func (f *fakeRuntime) NewSessionWithSpec(_ *config.OliumConfig, spec SessionSpec) (AgentSession, error) {
	f.sessionCalls.Add(1)
	f.lastSpec = spec
	return fakeSession{}, nil
}

type fakeSession struct{}

func (fakeSession) Fork() AgentSession { return fakeSession{} }
func (fakeSession) Close() error       { return nil }

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

// TestRunWithSkillsUsesSkillSession proves the skills path builds a per-call
// session carrying SessionSpec.Skills (and runs on it) rather than the plain
// RunPrompt path — so the <available_skills> block + load_skill tool reach the
// agent. A nil/empty registry must fall back to the plain RunPrompt path.
func TestRunWithSkillsUsesSkillSession(t *testing.T) {
	t.Parallel()
	reg, _ := olium.LoadSkillsFor(false)
	require.NotNil(t, reg)
	require.Greater(t, reg.Len(), 0, "embedded skills must load for this test")

	fake := &fakeRuntime{output: "ok"}
	e := &Engine{runtime: fake}

	_, err := e.RunWithSkills(context.Background(), Options{PromptInline: "triage"}, reg)
	require.NoError(t, err)
	require.Equal(t, int32(0), fake.runPromptCalls.Load(), "skills path must not use plain RunPrompt")
	require.Equal(t, int32(1), fake.runOnSessionCalls.Load(), "skills path must run on a built session")
	require.NotNil(t, fake.lastSpec.Skills, "SessionSpec.Skills must carry the registry")
	require.True(t, fake.lastSpec.IncludeTools, "skills session must include tools for load_skill")

	// Empty/nil registry → plain path.
	fake2 := &fakeRuntime{output: "ok"}
	e2 := &Engine{runtime: fake2}
	_, err = e2.RunWithSkills(context.Background(), Options{PromptInline: "triage"}, nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), fake2.runPromptCalls.Load(), "nil registry must fall back to RunPrompt")
}
