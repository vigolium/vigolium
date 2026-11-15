package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// scanArtifact is one file a scan wrote, for the human summary's "Report:"
// lines and the -j envelope's `artifacts`.
type scanArtifact struct {
	Format string `json:"format"`
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
}

// scanNextStep is a follow-up command the summary and the -j envelope suggest.
type scanNextStep struct {
	Argv []string `json:"argv"`
	Why  string   `json:"why"`
	// SendsTraffic marks a step that sends requests to the target.
	SendsTraffic bool `json:"sends_traffic,omitempty"`
}

// scanArtifacts collects the files the current invocation wrote. Reset at the
// start of a scan command; written by every export path (reports, jsonl,
// stateless exports).
var scanArtifacts struct {
	mu    sync.Mutex
	items []scanArtifact
}

func resetScanArtifacts() {
	scanArtifacts.mu.Lock()
	scanArtifacts.items = nil
	scanArtifacts.mu.Unlock()
}

// noteScanArtifact records a written file; stdout and empty paths are not
// artifacts. Bytes is read from the file (0 for a directory or when unreadable).
func noteScanArtifact(format, path string) {
	if path == "" || path == "-" || path == "/dev/stdout" {
		return
	}
	var size int64
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		size = info.Size()
	}
	abs := path
	if a, err := filepath.Abs(path); err == nil {
		abs = a
	}
	scanArtifacts.mu.Lock()
	defer scanArtifacts.mu.Unlock()
	for _, a := range scanArtifacts.items {
		if a.Path == abs && a.Format == format {
			return
		}
	}
	scanArtifacts.items = append(scanArtifacts.items, scanArtifact{Format: format, Path: abs, Bytes: size})
}

// collectedScanArtifacts returns the files written so far (never nil).
func collectedScanArtifacts() []scanArtifact {
	scanArtifacts.mu.Lock()
	defer scanArtifacts.mu.Unlock()
	return append([]scanArtifact{}, scanArtifacts.items...)
}

// scanNextSteps suggests what to run after a scan: drill into the findings
// when the run persisted, otherwise open what it wrote.
func scanNextSteps(scanUUID, dbPath string, findings int64, persisted bool) []scanNextStep {
	steps := []scanNextStep{}
	if persisted && scanUUID != "" {
		argv := []string{"vigolium", "finding", "--scan-uuid", scanUUID}
		if dbPath != "" {
			argv = append(argv, "--db", dbPath)
		}
		why := "list this scan's findings"
		if findings == 0 {
			why = "confirm the scan stored no findings"
		}
		steps = append(steps, scanNextStep{Argv: argv, Why: why})
		status := []string{"vigolium", "scan", "status", scanUUID}
		if dbPath != "" {
			status = append(status, "--db", dbPath)
		}
		steps = append(steps, scanNextStep{Argv: status, Why: "phase outcomes and coverage caveats"})
	}
	for _, a := range collectedScanArtifacts() {
		if a.Format == "jsonl" {
			steps = append(steps, scanNextStep{Argv: []string{"vigolium", "finding", "load", a.Path}, Why: "browse the exported findings without a database"})
			break
		}
	}
	return steps
}

// summaryTableRows bounds the findings table under the completion summary.
const summaryTableRows = 10

// printSummaryFindingsTable writes up to summaryTableRows of the scan's
// findings, worst first: severity, module, location.
func printSummaryFindingsTable(ctx context.Context, repo *database.Repository, projectUUID, scanUUID string, total int64) {
	if repo == nil || scanUUID == "" || total == 0 {
		return
	}
	findings, err := database.NewFindingsQueryBuilder(repo.DB(), database.QueryFilters{
		ProjectUUID: projectUUID, ObservedInScan: scanUUID, SortBy: "severity", Limit: summaryTableRows,
	}).Execute(ctx)
	if err != nil || len(findings) == 0 {
		return
	}
	modW := 0
	for _, f := range findings {
		modW = max(modW, len(f.ModuleID))
	}
	for _, f := range findings {
		loc := f.URL
		if len(f.MatchedAt) > 0 {
			loc = f.MatchedAt[0]
		}
		if len(loc) > 90 {
			loc = loc[:87] + "..."
		}
		fmt.Fprintf(os.Stderr, "    %-8s  %-*s  %s\n", strings.ToLower(f.Severity), modW, f.ModuleID, terminal.Gray(loc))
	}
	if total > int64(len(findings)) {
		fmt.Fprintf(os.Stderr, "    %s\n", terminal.Gray(fmt.Sprintf("… %d more", total-int64(len(findings)))))
	}
}

// printSummaryTail writes the Report:/Stored:/Next: lines.
func printSummaryTail(scanUUID, dbPath string, findings int64, persisted bool) {
	for _, a := range collectedScanArtifacts() {
		fmt.Fprintf(os.Stderr, "  %s Report: %s %s\n", terminal.Purple(terminal.SymbolInfo), terminal.Cyan(displayExportPath(a.Path)), terminal.Gray("("+a.Format+")"))
	}
	if persisted && dbPath != "" {
		fmt.Fprintf(os.Stderr, "  %s Stored: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.Cyan(terminal.ShortenHome(dbPath)))
	}
	for _, s := range scanNextSteps(scanUUID, dbPath, findings, persisted) {
		fmt.Fprintf(os.Stderr, "  %s Next: %s %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiCyan(quoteArgv(s.Argv)), terminal.Gray("— "+s.Why))
	}
}

// progressLineInterval is how often the foreground progress line prints.
const progressLineInterval = 15 * time.Second

// startProgressLine prints a status line (phase, work items, findings,
// elapsed) on stderr every progressLineInterval while a scan runs in the
// foreground on a terminal without -j/--events/--silent/--stats. Each line is
// newline-terminated so it never collides with the scan's own output.
func startProgressLine(r *runner.Runner, start time.Time) (stop func()) {
	if r == nil || globalSilent || globalJSON || scanOpts.Events != "" || scanOpts.ShowStats || !terminal.StderrIsTerminal() {
		return func() {}
	}
	done := make(chan struct{})
	var once sync.Once
	go func() {
		t := time.NewTicker(progressLineInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if line := progressLineText(r, time.Since(start)); line != "" {
					fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Gray("⧗"), terminal.Gray(line))
				}
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

// progressLineText renders one progress reading, "" when the runner has no
// phase running.
func progressLineText(r *runner.Runner, elapsed time.Duration) string {
	phase, prog, findings := r.LiveProgress()
	if phase == "" {
		return ""
	}
	line := phase
	if prog != nil {
		if prog.Total != nil && *prog.Total > 0 {
			line += fmt.Sprintf(" %d/%d %s", prog.Done, *prog.Total, prog.Unit)
		} else if prog.Done > 0 {
			line += fmt.Sprintf(" %d %s", prog.Done, prog.Unit)
		}
	}
	return fmt.Sprintf("%s · %d finding(s) · %s elapsed", line, findings, elapsed.Round(time.Second))
}
