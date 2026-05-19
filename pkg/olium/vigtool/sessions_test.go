package vigtool

import (
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

func TestClampLimit(t *testing.T) {
	cases := []struct {
		req, def, max, want int
	}{
		{0, 25, 200, 25},    // zero -> default
		{-5, 25, 200, 25},   // negative -> default
		{100, 25, 200, 100}, // within bounds -> as-is
		{500, 25, 200, 200}, // over max -> max
		{200, 25, 200, 200}, // exactly max -> max
	}
	for _, c := range cases {
		if got := clampLimit(c.req, c.def, c.max); got != c.want {
			t.Errorf("clampLimit(%d, %d, %d) = %d, want %d", c.req, c.def, c.max, got, c.want)
		}
	}
}

func TestSummarizeSession(t *testing.T) {
	now := time.Now().UTC()
	r := &database.AgenticScan{
		UUID:         "uuid-1",
		Mode:         "autopilot",
		Status:       "completed",
		CurrentPhase: "halt",
		TargetURL:    "https://example.com",
		InputType:    "url",
		FindingCount: 3,
		RecordCount:  17,
		StartedAt:    now,
		CompletedAt:  now.Add(2 * time.Minute),
		DurationMs:   120000,
	}
	got := summarizeSession(r)
	if got.UUID != "uuid-1" {
		t.Errorf("UUID = %q", got.UUID)
	}
	if got.FindingCount != 3 || got.RecordCount != 17 {
		t.Errorf("counts wrong: findings=%d records=%d", got.FindingCount, got.RecordCount)
	}
	if got.DurationMs != 120000 {
		t.Errorf("DurationMs = %d", got.DurationMs)
	}
	if got.StartedAt == "" || got.CompletedAt == "" {
		t.Error("non-zero timestamps should serialize")
	}

	// Zero timestamps should serialize as empty (not "0001-01-01T00:00:00Z").
	r.StartedAt = time.Time{}
	r.CompletedAt = time.Time{}
	got2 := summarizeSession(r)
	if got2.StartedAt != "" || got2.CompletedAt != "" {
		t.Errorf("zero timestamps should be empty, got %q / %q", got2.StartedAt, got2.CompletedAt)
	}
}

func TestSummarizeFindingTruncatesDescription(t *testing.T) {
	long := make([]byte, 600)
	for i := range long {
		long[i] = 'x'
	}
	f := &database.Finding{
		ID:          1,
		ScanUUID:    "scan-1",
		URL:         "https://example.com/api",
		ModuleName:  " custom-mod ",
		Severity:    "high",
		Description: string(long),
		FoundAt:     time.Now().UTC(),
	}
	got := summarizeFinding(f)
	if got.Module != "custom-mod" {
		t.Errorf("module name should be trimmed, got %q", got.Module)
	}
	// Truncation cap is 500 bytes of source plus a 3-byte UTF-8 ellipsis,
	// so 503 is the maximum legal byte length.
	if len(got.Description) > 503 {
		t.Errorf("description byte length = %d, want <= 503", len(got.Description))
	}
	if !strings.HasSuffix(got.Description, "…") {
		t.Errorf("truncated description should end with ellipsis, last 6 bytes = %q", got.Description[len(got.Description)-6:])
	}
}

// TestQueryToolMetadata pins down the schema-and-flags surface so future
// edits don't accidentally rename a tool or flip a read-only flag (which
// would break engine-level parallelism).
func TestQueryToolMetadata(t *testing.T) {
	cases := []struct {
		tool     tool.Tool
		name     string
		readOnly bool
	}{
		{NewListSessionsTool(&SessionsContext{}), "list_sessions", true},
		{NewGetSessionTool(&SessionsContext{}), "get_session", true},
		{NewListFindingsTool(&SessionsContext{}), "list_findings", true},
		{NewRunScanTool(&ScanContext{}), "run_native_scan", false},
		{NewRunExtensionTool(&ScanContext{}), "run_extension", false},
	}
	for _, c := range cases {
		if got := c.tool.Name(); got != c.name {
			t.Errorf("Name() = %q, want %q", got, c.name)
		}
		if got := c.tool.IsReadOnly(); got != c.readOnly {
			t.Errorf("%s IsReadOnly() = %v, want %v", c.name, got, c.readOnly)
		}
		if c.tool.Schema() == nil {
			t.Errorf("%s has nil Schema", c.name)
		}
	}
}
