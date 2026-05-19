package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
)

// TestHydrateSessionConfig_TokenPathShorthand verifies that an AgentLoginFlow
// using the type/token_path shorthand (without an explicit extract array)
// hydrates into Authorization: Bearer headers. Source-analysis emits configs
// in this shape; before the swarm.go fix the type/token_path fields were
// dropped during the agent → authentication conversion, so hydration silently
// produced zero headers.
func TestHydrateSessionConfig_TokenPathShorthand(t *testing.T) {
	const wantToken = "test.jwt.token"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/user/login" || r.Method != http.MethodPost {
			http.Error(w, "unexpected route", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authentication": map[string]any{"token": wantToken},
		})
	}))
	defer srv.Close()

	cfg := &AgentSessionConfig{
		Sessions: []agenttypes.AgentSessionEntry{{
			Name: "admin",
			Role: "primary",
			Login: &agenttypes.AgentLoginFlow{
				URL:         srv.URL + "/rest/user/login",
				Method:      "POST",
				ContentType: "application/json",
				Body:        `{"email":"admin@example.com","password":"hunter2"}`,
				Type:        "bearer",
				TokenPath:   ".authentication.token",
				// Note: Extract intentionally empty — the shorthand should drive
				// rule expansion via authentication.NormalizeLoginFlow.
			},
		}},
	}

	headers := hydrateSessionConfig(cfg)

	got, ok := headers["Authorization"]
	if !ok {
		t.Fatalf("expected Authorization header to be hydrated, got headers=%v", headers)
	}
	want := "Bearer " + wantToken
	if got != want {
		t.Errorf("Authorization header mismatch: got %q, want %q", got, want)
	}

	// The hydrated headers should also be persisted back onto the entry so
	// downstream code (DB writes, prepared.HeaderCount) sees the same data.
	if len(cfg.Sessions[0].Headers) == 0 {
		t.Errorf("expected hydrated headers to be written back to session entry, got empty map")
	}
	if cfg.Sessions[0].Headers["Authorization"] != want {
		t.Errorf("entry headers Authorization mismatch: got %q, want %q",
			cfg.Sessions[0].Headers["Authorization"], want)
	}
}
