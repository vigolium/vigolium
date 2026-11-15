package diagnostics

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

// An endpoint provider is unverified in the plain report and probed by
// --for agent.
func TestEndpointProviderIsUnverified(t *testing.T) {
	s := config.DefaultSettings()
	s.Agent.Olium.Provider = "openai-compatible"
	s.Agent.Olium.CustomProvider.BaseURL = "http://127.0.0.1:11434/v1"
	s.Agent.Olium.Model = "llama3"
	a := checkAgent(s)
	if a.Status != StatusOK || !a.Unverified || a.Endpoint == "" {
		t.Fatalf("checkAgent = %+v, want ok+unverified with the endpoint", a)
	}
	r := &Report{Agent: a}
	var got string
	for _, c := range r.Checks() {
		if c.ID == "agent" {
			got = c.Status
		}
	}
	if got != CheckStatusUnverified {
		t.Fatalf("flat agent status = %q, want unverified", got)
	}
	if caps := r.Capabilities(); caps.Agent != CapabilityUnverified {
		t.Fatalf("capabilities.agent = %q", caps.Agent)
	}

	prev := scopedDial
	t.Cleanup(func() { scopedDial = prev })
	scopedDial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("connection refused") }
	if sc := agentCheck(a); sc.Status != ScopedNotReady {
		t.Fatalf("--for agent with a refused endpoint = %+v, want not_ready", sc)
	}
}

func TestCheckIDForToken(t *testing.T) {
	checks := []Check{{ID: "chromium"}, {ID: "nuclei_templates"}, {ID: "oast"}, {ID: "agent-browser"}}
	for tok, want := range map[string]string{
		"chrome": "chromium", "nuclei": "nuclei_templates", "nuclei-templates": "nuclei_templates",
		"oast": "oast", "agent-browser": "agent-browser", "nope": "",
	} {
		if got := CheckIDForToken(tok, checks); got != want {
			t.Errorf("CheckIDForToken(%q) = %q, want %q", tok, got, want)
		}
	}
}
