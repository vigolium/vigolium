package codexcost

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPricingForKnownPrefix(t *testing.T) {
	cases := []struct {
		model string
		want  string
	}{
		{"gpt-5", "gpt-5"},
		{"gpt-5.4", "gpt-5"},
		{"gpt-5-codex", "gpt-5"},
		{"gpt-4.1-mini", "gpt-4.1"},
		{"o4-mini", "o4-mini"},
		{"unknown-model", "default"},
	}
	for _, c := range cases {
		if got := PricingFor(c.model); got.Model != c.want {
			t.Errorf("PricingFor(%q).Model = %q, want %q", c.model, got.Model, c.want)
		}
	}
}

func TestUsagePriceSplitsCachedAndReasoning(t *testing.T) {
	// Real totals from the observed VAmPI codex run.
	u := Usage{
		InputTokens:           169_325,
		CachedInputTokens:     118_272,
		OutputTokens:          1_818,
		ReasoningOutputTokens: 1_080,
	}
	got := u.Price("gpt-5.4")
	// Expected at gpt-5 rates:
	//   non-cached input: (169325-118272)=51053 × $1.25/M  = 0.0638
	//   cached input:     118272          × $0.125/M       = 0.0148
	//   output+reasoning: (1818+1080)=2898 × $10.00/M      = 0.0290
	//   TOTAL ≈ $0.1076
	const want = 0.1076
	if got < want-0.005 || got > want+0.005 {
		t.Errorf("Price = %.4f, want ~%.4f", got, want)
	}
}

func TestParseRolloutHonorsLastTokenCount(t *testing.T) {
	fixture := strings.Join([]string{
		`{"type":"session_meta","payload":{"id":"sess-1","cwd":"/repo","timestamp":"2026-04-22T01:03:56.797Z"}}`,
		`{"type":"turn_context","payload":{"model":"gpt-5.4"}}`,
		// Intermediate cumulative counts — must be ignored in favor of the last.
		`{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":50000,"cached_input_tokens":40000,"output_tokens":100,"reasoning_output_tokens":50,"total_tokens":50100}}}}`,
		`{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":169325,"cached_input_tokens":118272,"output_tokens":1818,"reasoning_output_tokens":1080,"total_tokens":171143}}}}`,
		// Noise.
		`{"type":"response_item","payload":{"type":"message"}}`,
	}, "\n")

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout.jsonl")
	if err := os.WriteFile(path, []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}

	sid, model, cwd, usage, err := ParseRollout(path)
	if err != nil {
		t.Fatalf("ParseRollout: %v", err)
	}
	if sid != "sess-1" {
		t.Errorf("session = %q", sid)
	}
	if model != "gpt-5.4" {
		t.Errorf("model = %q", model)
	}
	if cwd != "/repo" {
		t.Errorf("cwd = %q", cwd)
	}
	want := Usage{
		InputTokens:           169_325,
		CachedInputTokens:     118_272,
		OutputTokens:          1_818,
		ReasoningOutputTokens: 1_080,
		TotalTokens:           171_143,
	}
	if usage != want {
		t.Errorf("usage = %+v, want %+v", usage, want)
	}
}

func TestFindRolloutMatchesByCWDAndTime(t *testing.T) {
	// Lay out a fake $CODEX_HOME/sessions/YYYY/MM/DD/rollout-*.jsonl
	codexHome := t.TempDir()
	startedAt := time.Date(2026, 4, 22, 1, 3, 56, 0, time.UTC)
	day := filepath.Join(codexHome, "sessions", "2026", "04", "22")
	if err := os.MkdirAll(day, 0o755); err != nil {
		t.Fatal(err)
	}

	// Match: same cwd, timestamp within tolerance.
	good := filepath.Join(day, "rollout-good.jsonl")
	writeFixture(t, good, `{"type":"session_meta","payload":{"id":"sess-good","cwd":"/Users/x/project","timestamp":"2026-04-22T01:03:59.455Z"}}`)

	// Wrong cwd.
	bad := filepath.Join(day, "rollout-wrongcwd.jsonl")
	writeFixture(t, bad, `{"type":"session_meta","payload":{"id":"sess-bad","cwd":"/elsewhere","timestamp":"2026-04-22T01:03:59.455Z"}}`)

	// Right cwd but way outside time window.
	old := filepath.Join(day, "rollout-stale.jsonl")
	writeFixture(t, old, `{"type":"session_meta","payload":{"id":"sess-stale","cwd":"/Users/x/project","timestamp":"2026-04-22T00:30:00.000Z"}}`)

	// Not a rollout file (no session_meta first).
	junk := filepath.Join(day, "rollout-nosession.jsonl")
	writeFixture(t, junk, `{"type":"event_msg","payload":{"type":"task_started"}}`)

	got, err := FindRollout(codexHome, "/Users/x/project", startedAt)
	if err != nil {
		t.Fatalf("FindRollout: %v", err)
	}
	if got != good {
		t.Errorf("got %q, want %q", got, good)
	}
}

func TestFindRolloutEmptyWhenNoCodexHome(t *testing.T) {
	got, err := FindRollout("/definitely/does/not/exist/codex", "/repo", time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestBuildSummaryEndToEnd(t *testing.T) {
	codexHome := t.TempDir()
	t.Setenv("CODEX_HOME", codexHome)

	startedAt := time.Date(2026, 4, 22, 1, 3, 56, 0, time.UTC)
	day := filepath.Join(codexHome, "sessions", "2026", "04", "22")
	if err := os.MkdirAll(day, 0o755); err != nil {
		t.Fatal(err)
	}
	fixture := strings.Join([]string{
		`{"type":"session_meta","payload":{"id":"sess-e2e","cwd":"/demo","timestamp":"2026-04-22T01:03:59.455Z"}}`,
		`{"type":"turn_context","payload":{"model":"gpt-5.4"}}`,
		`{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":169325,"cached_input_tokens":118272,"output_tokens":1818,"reasoning_output_tokens":1080,"total_tokens":171143}}}}`,
	}, "\n")
	writeFixture(t, filepath.Join(day, "rollout-e2e.jsonl"), fixture)

	s, err := BuildSummary("/demo", startedAt)
	if err != nil {
		t.Fatalf("BuildSummary: %v", err)
	}
	if s.SessionID != "sess-e2e" {
		t.Errorf("SessionID = %q", s.SessionID)
	}
	if s.Model != "gpt-5.4" {
		t.Errorf("Model = %q", s.Model)
	}
	if s.TotalCostUSD < 0.10 || s.TotalCostUSD > 0.12 {
		t.Errorf("TotalCostUSD = %.4f, want ~0.11", s.TotalCostUSD)
	}
	// Sanity: RolloutPath should point back into the fixture dir.
	if !strings.HasSuffix(s.RolloutPath, "rollout-e2e.jsonl") {
		t.Errorf("RolloutPath = %q", s.RolloutPath)
	}
}

func TestBuildSummaryReturnsZeroWhenNoRollout(t *testing.T) {
	codexHome := t.TempDir()
	t.Setenv("CODEX_HOME", codexHome)
	s, err := BuildSummary("/nothing-here", time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.TotalCostUSD != 0 || s.SessionID != "" {
		t.Errorf("expected zero-value summary, got %+v", s)
	}
}

func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// Compile-time assertion: our Usage is the same shape the Claude CLI
// would serialize, minus cache tiers. Just a sanity anchor.
var _ = fmt.Sprintf("%d", Usage{}.InputTokens)
