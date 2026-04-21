package claudecost

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPricingForKnownPrefix(t *testing.T) {
	cases := []struct {
		model string
		want  string
	}{
		{"claude-opus-4-7[1m]", "claude-opus-4"},
		{"claude-opus-4-5", "claude-opus-4"},
		{"claude-sonnet-4-6", "claude-sonnet-4"},
		{"claude-haiku-4-5-20251001", "claude-haiku-4"},
		{"some-unknown-model", "default"},
		{"", "default"},
	}
	for _, c := range cases {
		if got := PricingFor(c.model); got.Model != c.want {
			t.Errorf("PricingFor(%q).Model = %q, want %q", c.model, got.Model, c.want)
		}
	}
}

func TestUsagePrice_PrefersExplicit5mBreakdown(t *testing.T) {
	// When ephemeral breakdown is present, CacheCreateTokens should NOT be
	// double-counted — only the 5m/1h fields feed into pricing.
	u := Usage{
		CacheCreateTokens:   2537, // aggregate, would double-count if used
		CacheCreate5mTokens: 2537,
	}
	got := u.Price("claude-opus-4-7")
	want := 2537 * 18.75 / 1_000_000.0
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Price = %v, want %v", got, want)
	}
}

func TestParseStreamFileDedupesByMessageID(t *testing.T) {
	// Three streaming deltas for the same message.id — we must take the
	// final (highest output_tokens) and ignore the earlier cumulative
	// snapshots rather than summing them.
	fixture := strings.Join([]string{
		`{"type":"system","subtype":"init","session_id":"s-123","cwd":"/tmp/demo","model":"claude-opus-4-7[1m]"}`,
		`{"type":"assistant","message":{"id":"msg_A","model":"claude-opus-4-7[1m]","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":1000}}}`,
		`{"type":"assistant","message":{"id":"msg_A","model":"claude-opus-4-7[1m]","usage":{"input_tokens":10,"output_tokens":20,"cache_read_input_tokens":1000}}}`,
		`{"type":"assistant","message":{"id":"msg_A","model":"claude-opus-4-7[1m]","usage":{"input_tokens":10,"output_tokens":42,"cache_read_input_tokens":1000,"cache_creation_input_tokens":200,"cache_creation":{"ephemeral_5m_input_tokens":200,"ephemeral_1h_input_tokens":0}}}}`,
		`{"type":"assistant","message":{"id":"msg_B","usage":{"input_tokens":3,"output_tokens":7,"cache_read_input_tokens":500}}}`,
		`{"type":"result","subtype":"success","total_cost_usd":0.1234}`,
	}, "\n")

	dir := t.TempDir()
	path := filepath.Join(dir, "stream.jsonl")
	writeFile(t, path, fixture)

	usage, model, sid, cwd, reported, err := ParseStreamFile(path)
	if err != nil {
		t.Fatalf("ParseStreamFile: %v", err)
	}
	if model != "claude-opus-4-7[1m]" {
		t.Errorf("model = %q", model)
	}
	if sid != "s-123" {
		t.Errorf("session_id = %q", sid)
	}
	if cwd != "/tmp/demo" {
		t.Errorf("cwd = %q", cwd)
	}
	if reported != 0.1234 {
		t.Errorf("reportedCost = %v", reported)
	}
	// msg_A final (10, 42, 1000, 200) + msg_B (3, 7, 500, 0)
	want := Usage{
		InputTokens:         13,
		OutputTokens:        49,
		CacheReadTokens:     1500,
		CacheCreateTokens:   200,
		CacheCreate5mTokens: 200,
	}
	if usage != want {
		t.Errorf("usage = %+v, want %+v", usage, want)
	}
}

func TestSubagentTasksDirEscapesCWD(t *testing.T) {
	got := SubagentTasksDir(501, "/Users/alice/project", "abc-123")
	want := "/tmp/claude-501/-Users-alice-project/abc-123/tasks"
	if got != want {
		t.Errorf("SubagentTasksDir = %q, want %q", got, want)
	}
	if SubagentTasksDir(501, "", "abc") != "" {
		t.Error("empty cwd should yield empty path")
	}
	if SubagentTasksDir(501, "/x", "") != "" {
		t.Error("empty sessionID should yield empty path")
	}
}

func TestFindSubagentFilesFiltersNonAgentFiles(t *testing.T) {
	dir := t.TempDir()
	// Real async agent (first line has agentId)
	writeFile(t, filepath.Join(dir, "a3514db3.output"),
		`{"agentId":"a3514db3","type":"user","message":{}}
`)
	// Bash background task (no agentId)
	writeFile(t, filepath.Join(dir, "bn42nz1aj.output"),
		`running...
done
`)
	// Not a .output file — should be ignored
	writeFile(t, filepath.Join(dir, "notes.txt"), `ignore me`)

	files, err := FindSubagentFiles(dir)
	if err != nil {
		t.Fatalf("FindSubagentFiles: %v", err)
	}
	if len(files) != 1 || !strings.HasSuffix(files[0], "a3514db3.output") {
		t.Errorf("unexpected result: %v", files)
	}
}

func TestFindSubagentFilesMissingDirReturnsEmpty(t *testing.T) {
	files, err := FindSubagentFiles("/nonexistent/path/for/claudecost/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected empty, got %v", files)
	}
}

func TestPriceMatchesRealArchonRunWithin1Percent(t *testing.T) {
	// Anchored to an observed archon lite run against VAmPI where the
	// Claude CLI reported total_cost_usd = 8.37 for main session usage
	// equivalent to the values below. Our local pricing should land
	// within 1% of that — a wider miss means the pricing table has
	// drifted out of sync with Anthropic's published rates.
	mainUsage := Usage{
		InputTokens:         123,
		OutputTokens:        2616,
		CacheReadTokens:     3_518_062,
		CacheCreateTokens:   156_217,
		CacheCreate5mTokens: 156_217,
	}
	cost := mainUsage.Price("claude-opus-4-7[1m]")
	const reported = 8.37
	diff := cost - reported
	if diff < 0 {
		diff = -diff
	}
	if diff/reported > 0.01 {
		t.Errorf("local estimate %.4f diverges from reported %.2f by %.2f%%", cost, reported, 100*diff/reported)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
