package harness

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRecordBenchResult(t *testing.T) {
	out := filepath.Join(t.TempDir(), "bench.jsonl")
	t.Setenv(BenchOutEnv, out)
	t.Setenv(BenchCommitEnv, "abc123")
	benchCommitO = sync.Once{} // re-read BENCH_COMMIT for this test

	tc := TestCase{ID: "case-1", ScanMode: "active", Assertion: "strict"}
	for i, err := range []error{nil, errors.New("boom")} {
		tr := TestResult{TestCase: tc, ModuleID: "m", FindingCount: i + 1, Requests: 42,
			Duration: 1500 * time.Millisecond, Passed: err == nil, Error: err}
		if e := RecordBenchResult(tr); e != nil {
			t.Fatal(e)
		}
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	var rec BenchRecord
	if err := json.Unmarshal([]byte(lines[1]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Commit != "abc123" || rec.CaseID != "case-1" || rec.Requests != 42 || rec.DurationMs != 1500 ||
		rec.Findings != 2 || rec.Error != "boom" || rec.Passed {
		t.Fatalf("record = %+v", rec)
	}
}

func TestRecordBenchResult_NoEnvNoFile(t *testing.T) {
	t.Setenv(BenchOutEnv, "")
	if err := RecordBenchResult(TestResult{}); err != nil {
		t.Fatal(err)
	}
}
