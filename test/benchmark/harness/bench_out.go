package harness

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// BenchOutEnv names the file every benchmark run appends its per-case results
// to (one JSON object per line). Unset: nothing is written. The nightly CI job
// sets it and uploads the file; `make bench-diff` compares two of them.
const BenchOutEnv = "BENCH_OUT"

// BenchCommitEnv overrides the commit recorded in each line (CI sets
// GITHUB_SHA, which is also honoured).
const BenchCommitEnv = "BENCH_COMMIT"

// BenchRecord is one line of a BENCH_OUT file: the outcome of one module on
// one benchmark case at one commit.
type BenchRecord struct {
	Commit     string `json:"commit"`
	CaseID     string `json:"case_id"`
	Module     string `json:"module"`
	ScanMode   string `json:"scan_mode"`
	Assertion  string `json:"assertion"`
	Findings   int    `json:"findings"`
	Requests   int64  `json:"requests"`
	DurationMs int64  `json:"duration_ms"`
	Passed     bool   `json:"passed"`
	Error      string `json:"error,omitempty"`
}

var (
	benchOutMu   sync.Mutex
	benchCommit  string
	benchCommitO sync.Once
)

// resolveBenchCommit returns the commit to stamp: BENCH_COMMIT, GITHUB_SHA,
// else `git rev-parse HEAD`, else "unknown".
func resolveBenchCommit() string {
	benchCommitO.Do(func() {
		for _, env := range []string{BenchCommitEnv, "GITHUB_SHA"} {
			if v := strings.TrimSpace(os.Getenv(env)); v != "" {
				benchCommit = v
				return
			}
		}
		if out, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
			benchCommit = strings.TrimSpace(string(out))
			return
		}
		benchCommit = "unknown"
	})
	return benchCommit
}

// newBenchRecord converts a harness result into a BENCH_OUT line.
func newBenchRecord(tr TestResult) BenchRecord {
	rec := BenchRecord{
		Commit:     resolveBenchCommit(),
		CaseID:     tr.TestCase.ID,
		Module:     tr.ModuleID,
		ScanMode:   tr.TestCase.ScanMode,
		Assertion:  tr.TestCase.Assertion,
		Findings:   tr.FindingCount,
		Requests:   tr.Requests,
		DurationMs: tr.Duration.Round(time.Millisecond).Milliseconds(),
		Passed:     tr.Passed,
	}
	if tr.Error != nil {
		rec.Error = tr.Error.Error()
	}
	return rec
}

// RecordBenchResult appends tr to $BENCH_OUT when it is set. Append-only
// writes of one line each keep concurrent test packages (separate processes)
// from interleaving partial records.
func RecordBenchResult(tr TestResult) error {
	path := os.Getenv(BenchOutEnv)
	if path == "" {
		return nil
	}
	line, err := json.Marshal(newBenchRecord(tr))
	if err != nil {
		return err
	}
	benchOutMu.Lock()
	defer benchOutMu.Unlock()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Close()
}
