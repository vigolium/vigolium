package picost

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEncodeSessionDir(t *testing.T) {
	cases := []struct {
		cwd  string
		want string
	}{
		{"/Users/j3ssie/Desktop/vuln-apps/VAmPI", "--Users-j3ssie-Desktop-vuln-apps-VAmPI--"},
		{"/", "----"},
		{"", "----"},
		{"/tmp", "--tmp--"},
		{"/a/b", "--a-b--"},
	}
	for _, c := range cases {
		if got := EncodeSessionDir(c.cwd); got != c.want {
			t.Errorf("EncodeSessionDir(%q) = %q, want %q", c.cwd, got, c.want)
		}
	}
}

// makePiHome stages a fake $PI_HOME with a single session transcript at
// agent/sessions/<encoded>/file.jsonl populated from the supplied lines.
// Returns the path to the session file.
func makePiHome(t *testing.T, cwd string, sessionTimestamp string, lines []string) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("PI_HOME", root)
	dir := filepath.Join(root, "agent", "sessions", EncodeSessionDir(cwd))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	header := `{"type":"session","version":3,"id":"019aa","timestamp":"` + sessionTimestamp + `","cwd":"` + cwd + `"}`
	all := append([]string{header}, lines...)
	path := filepath.Join(dir, "2026-05-01T09-00-00-000Z_019aa.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(all, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestBuildSummary_SumsAcrossAssistantMessages(t *testing.T) {
	cwd := "/tmp/picost-test-target"
	lines := []string{
		// One priced assistant message.
		`{"type":"message","message":{"role":"assistant","provider":"openai","model":"gpt-5.5","usage":{"input":100,"output":20,"cacheRead":0,"cacheWrite":0,"totalTokens":120,"cost":{"input":0.01,"output":0.005,"cacheRead":0,"cacheWrite":0,"total":0.015}}}}`,
		// A user echo — must be ignored.
		`{"type":"message","message":{"role":"user","content":[]}}`,
		// A second assistant turn — also priced; sums into the total.
		`{"type":"message","message":{"role":"assistant","model":"gpt-5.5","usage":{"input":50,"output":10,"cacheRead":5,"cacheWrite":0,"totalTokens":65,"cost":{"input":0.005,"output":0.0025,"total":0.0085}}}}`,
		// An errored turn (zero usage, error message) — kept; doesn't perturb totals.
		`{"type":"message","message":{"role":"assistant","model":"gpt-5.5","usage":{"input":0,"output":0,"totalTokens":0,"cost":{"total":0}},"errorMessage":"401"}}`,
	}
	makePiHome(t, cwd, "2026-05-01T09:00:01.000Z", lines)

	startedAt, _ := time.Parse(time.RFC3339, "2026-05-01T09:00:00Z")
	s, err := BuildSummary(cwd, startedAt)
	if err != nil {
		t.Fatalf("BuildSummary: %v", err)
	}
	if len(s.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(s.Sessions))
	}
	if s.Usage.TotalTokens != 185 {
		t.Errorf("totalTokens = %d, want 185", s.Usage.TotalTokens)
	}
	if s.Usage.Input != 150 {
		t.Errorf("input = %d, want 150", s.Usage.Input)
	}
	if s.Usage.Output != 30 {
		t.Errorf("output = %d, want 30", s.Usage.Output)
	}
	// 0.015 + 0.0085 = 0.0235.
	if got := s.TotalCostUSD; got < 0.0234 || got > 0.0236 {
		t.Errorf("totalCostUSD = %.4f, want ~0.0235", got)
	}
	if s.Model != "gpt-5.5" {
		t.Errorf("model = %q, want gpt-5.5", s.Model)
	}
}

func TestBuildSummary_SkipsZeroCostTranscripts(t *testing.T) {
	cwd := "/tmp/picost-zero"
	lines := []string{
		// Only a 401-errored turn — zero tokens AND zero cost. The
		// transcript shouldn't surface in the summary at all.
		`{"type":"message","message":{"role":"assistant","model":"gpt-5.4","usage":{"input":0,"output":0,"totalTokens":0,"cost":{"total":0}},"errorMessage":"401"}}`,
	}
	makePiHome(t, cwd, "2026-05-01T09:00:01.000Z", lines)
	startedAt, _ := time.Parse(time.RFC3339, "2026-05-01T09:00:00Z")
	s, err := BuildSummary(cwd, startedAt)
	if err != nil {
		t.Fatalf("BuildSummary: %v", err)
	}
	if len(s.Sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(s.Sessions))
	}
	if s.TotalCostUSD != 0 || s.Usage.TotalTokens != 0 {
		t.Errorf("expected zero totals, got cost=%.4f tokens=%d", s.TotalCostUSD, s.Usage.TotalTokens)
	}
}

func TestBuildSummary_FiltersBySessionStartTime(t *testing.T) {
	cwd := "/tmp/picost-filter"
	lines := []string{
		`{"type":"message","message":{"role":"assistant","model":"gpt-5.5","usage":{"input":1,"output":1,"totalTokens":2,"cost":{"total":0.001}}}}`,
	}
	// Session header stamped well before startedAt — outside the slack window.
	makePiHome(t, cwd, "2026-04-30T00:00:00.000Z", lines)
	startedAt, _ := time.Parse(time.RFC3339, "2026-05-01T09:00:00Z")
	s, err := BuildSummary(cwd, startedAt)
	if err != nil {
		t.Fatalf("BuildSummary: %v", err)
	}
	if len(s.Sessions) != 0 {
		t.Errorf("expected old session to be filtered out, got %d", len(s.Sessions))
	}
}

func TestBuildSummary_NoSessionDirReturnsEmpty(t *testing.T) {
	t.Setenv("PI_HOME", t.TempDir()) // empty PI_HOME — no encoded-cwd dir
	startedAt, _ := time.Parse(time.RFC3339, "2026-05-01T09:00:00Z")
	s, err := BuildSummary("/some/cwd", startedAt)
	if err != nil {
		t.Fatalf("BuildSummary: %v", err)
	}
	if s.TotalCostUSD != 0 || len(s.Sessions) != 0 {
		t.Errorf("expected empty summary, got %+v", s)
	}
}

func TestBuildSummary_EmptyCWD(t *testing.T) {
	startedAt, _ := time.Parse(time.RFC3339, "2026-05-01T09:00:00Z")
	s, err := BuildSummary("", startedAt)
	if err != nil {
		t.Fatalf("BuildSummary: %v", err)
	}
	if s.TotalCostUSD != 0 || len(s.Sessions) != 0 {
		t.Errorf("expected empty summary for empty cwd, got %+v", s)
	}
}
