package agent

import (
	"context"
	"testing"
)

func TestRunAutopilotTriageRequiresEngineAndRepo(t *testing.T) {
	// nil engine/repo must be rejected before any work — the caller treats
	// the error as non-fatal, but it must not panic or no-op silently.
	_, err := RunAutopilotTriage(context.Background(), nil, nil, AutopilotTriageParams{
		ProjectUUID:     "p",
		AgenticScanUUID: "a",
	})
	if err == nil {
		t.Fatal("expected error when engine and repository are nil")
	}
}

func TestHostnameFromTarget(t *testing.T) {
	cases := map[string]string{
		"https://app.example.com/login?x=1": "app.example.com",
		"http://app.example.com:8080":       "app.example.com",
		"app.example.com:443":               "app.example.com",
		"app.example.com":                   "app.example.com",
		"":                                  "",
		"   ":                               "",
	}
	for in, want := range cases {
		if got := hostnameFromTarget(in); got != want {
			t.Errorf("hostnameFromTarget(%q) = %q, want %q", in, got, want)
		}
	}
}
