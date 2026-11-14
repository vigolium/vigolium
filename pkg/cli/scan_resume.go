package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// resumeManifestVersion is the on-disk schema version of the progress manifest.
// Bump it only on an incompatible change; loadResumeManifest tolerates older
// files by treating an unknown shape as "no manifest" (scan everything).
const resumeManifestVersion = 1

// resumeManifest is the sidecar progress file for a stateless parallel fan-out
// (-S -T --split-by-host -P). It stores a single line cursor — not a row per
// target — so it stays tiny no matter how large the target list is. The cursor
// is the contiguous prefix of the (ordered) target list that has finished
// cleanly; on --resume scanning continues from the next line. Because the fan-out
// completes targets out of order under -P, the cursor only advances over the
// uninterrupted run of completed lines, so at most a handful of in-flight
// targets (≤ -P) are ever re-scanned on resume. The file is rewritten atomically
// (temp + rename) whenever the cursor advances, so a Ctrl-C never corrupts it.
//
// Resume is line-index based and therefore assumes the target file's completed
// prefix is unchanged between runs (appending new lines at the end is fine — they
// scan as the new tail). CursorTarget records the target string at the cursor so
// a reordered/edited prefix can be detected and warned about.
type resumeManifest struct {
	Version             int      `json:"version"`
	OutputPrefix        string   `json:"output_prefix"`
	Formats             []string `json:"formats"`
	SettingsFingerprint string   `json:"settings_fingerprint"`
	TargetFiles         []string `json:"target_files"`
	CreatedAt           string   `json:"created_at"`
	UpdatedAt           string   `json:"updated_at"`

	// CompletedThrough is the 0-based index of the last target whose entire
	// prefix [0..CompletedThrough] has finished cleanly. -1 means nothing done.
	CompletedThrough int    `json:"completed_through"`
	CursorTarget     string `json:"cursor_target"`

	// Aggregate counts of the completed prefix, so a resumed run's roll-up
	// reflects prior progress without storing per-target rows or re-reading files.
	Records  int            `json:"records"`
	Findings int            `json:"findings"`
	Severity map[string]int `json:"severity,omitempty"`

	// Parallel and ScanArgs capture enough of the originating command to relaunch
	// it from a bare `vigolium scan --resume` (no other flags): Parallel is the
	// -P degree and ScanArgs is the inherited per-child flag set (childScanArgs —
	// --stateless/--format/--skip/--fuzz-wordlist/…, but NOT the per-target -T/-o/-P/
	// --split-by-host that are reconstructed from the dedicated fields). See
	// resumeFromDiscoveredManifest.
	Parallel int      `json:"parallel,omitempty"`
	ScanArgs []string `json:"scan_args,omitempty"`

	// DoneIndices are targets past the cursor that already finished cleanly
	// (out of order, ahead of a gap), with their counts. Persisted so a resume
	// skips them instead of re-scanning every target after the first failure.
	DoneIndices []resumeDoneEntry `json:"done_indices,omitempty"`

	path    string             // on-disk location; not serialized
	pending map[int]resumeDone // in-memory: out-of-order completions awaiting contiguous advance
}

// resumeDone is one cleanly-completed target held in memory until the cursor
// advances over its line, at which point its counts roll into the aggregates.
type resumeDone struct {
	target string
	stats  childStats
}

// resumeDoneEntry is one persisted out-of-order completion.
type resumeDoneEntry struct {
	Index    int            `json:"index"`
	Target   string         `json:"target"`
	Records  int            `json:"records,omitempty"`
	Findings int            `json:"findings,omitempty"`
	Severity map[string]int `json:"severity,omitempty"`
}

// doneAhead reports whether absolute line absIdx already finished out of order.
func (m *resumeManifest) doneAhead(absIdx int) bool {
	if m == nil {
		return false
	}
	_, ok := m.pending[absIdx]
	return ok
}

// carryoverStats is the prior progress folded into the final roll-up so it
// reflects the whole batch even though previously-completed hosts were skipped.
type carryoverStats struct {
	count int
	stats childStats
}

// resumeManifestPath derives the manifest location from the operator's --output
// prefix (so `-o myt` → `myt.progress.json`). With no -o it falls back to the
// first target file's base name, and finally to a fixed name in the working
// directory, so a manifest always has a deterministic home for --resume to find.
func resumeManifestPath(output string, targetFiles []string) string {
	if base := types.StripFormatExtension(output); base != "" {
		return base + ".progress.json"
	}
	if len(targetFiles) > 0 && targetFiles[0] != "" {
		base := strings.TrimSuffix(filepath.Base(targetFiles[0]), filepath.Ext(targetFiles[0]))
		if base != "" {
			return base + ".progress.json"
		}
	}
	return "vigolium-scan.progress.json"
}

// resumeFromDiscoveredManifest powers the bare `vigolium scan --resume` form:
// with no -T/-t/stdin to scan, it locates the progress manifest in the working
// directory, rebuilds the originating command from it, and relaunches that scan
// with --resume so the operator never has to re-type the full flag set. The
// relaunch runs as a child process (inheriting stdio) rather than re-parsing
// flags in-process, so the resumed scan gets a pristine flag/config state — the
// same faithful round-trip the -P fan-out already relies on for its children.
func resumeFromDiscoveredManifest(cmd *cobra.Command) error {
	manifestPath, err := discoverResumeManifestPath(scanOpts.Output)
	if err != nil {
		return err
	}
	m, ok := loadResumeManifest(manifestPath)
	if !ok {
		return fmt.Errorf("found %s but it is not a readable resume manifest", manifestPath)
	}
	if len(m.TargetFiles) == 0 {
		return fmt.Errorf("resume manifest %s records no target file; cannot auto-resume — re-run with the original flags plus --resume", manifestPath)
	}

	relaunch := buildResumeRelaunchArgs(m)

	if !scanOpts.Silent {
		fmt.Fprintf(os.Stderr, "%s %s picked up %s (%s target(s) already complete) — relaunching the saved scan\n",
			terminal.Aqua("↻"),
			terminal.BoldAqua("Auto-resume:"),
			terminal.Cyan(manifestPath),
			terminal.HiCyan(strconv.Itoa(m.completedCount())))
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate the vigolium binary to resume: %w", err)
	}

	child := exec.Command(exe, append([]string{"scan"}, relaunch...)...) //nolint:gosec // exe is our own binary, args derived from a local manifest
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	runErr := child.Run()
	if runErr == nil {
		return nil
	}
	// The relaunched scan already reported its own progress/errors to the shared
	// stderr, so surface its failure as our exit code without printing a second,
	// redundant error line on top of it.
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
		return exitErr
	}
	return fmt.Errorf("failed to relaunch scan for --resume: %w", runErr)
}

// discoverResumeManifestPath finds the progress manifest a bare --resume should
// pick up. An explicit -o prefix pins it exactly (roch → roch.progress.json);
// otherwise the working directory is scanned for a single *.progress.json. Zero
// or several matches are reported as errors so the operator can disambiguate
// rather than the wrong run being resumed silently.
func discoverResumeManifestPath(output string) (string, error) {
	if output != "" {
		path := resumeManifestPath(output, nil)
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("no resume manifest at %s (derived from -o %s)", path, output)
		}
		return path, nil
	}

	matches, err := filepath.Glob("*.progress.json")
	if err != nil {
		return "", fmt.Errorf("scan current directory for a progress file: %w", err)
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no progress file (*.progress.json) found in the current directory — run --resume from the directory that holds it, or pass -o <output-prefix>")
	case 1:
		return matches[0], nil
	default:
		sort.Strings(matches)
		return "", fmt.Errorf("multiple progress files in the current directory (%s) — pass -o <output-prefix> to choose which run to resume", strings.Join(matches, ", "))
	}
}

// buildResumeRelaunchArgs reconstructs the scan flag list (after the "scan"
// subcommand) that reproduces the manifest's originating run, with --resume
// appended. ScanArgs carries the inherited per-child flags; the per-target
// -T/-o/-P/--split-by-host are rebuilt from the dedicated fields. An older
// manifest without ScanArgs degrades to the minimum needed for a stateless
// per-host run.
func buildResumeRelaunchArgs(m *resumeManifest) []string {
	var args []string
	if len(m.ScanArgs) > 0 {
		args = append(args, m.ScanArgs...)
	} else {
		// Pre-ScanArgs manifest: synthesize the essentials so the basic run still
		// resumes (inherited per-module flags like --fuzz-wordlist are lost).
		args = append(args, "--stateless")
		if len(m.Formats) > 0 {
			args = append(args, "--format", strings.Join(m.Formats, ","))
		}
	}
	for _, tf := range m.TargetFiles {
		args = append(args, "-T", tf)
	}
	if m.OutputPrefix != "" {
		args = append(args, "-o", m.OutputPrefix)
	}
	// max(..,1) keeps a pre-Parallel manifest (field absent ⇒ 0) on the parallel path.
	args = append(args, "-P", strconv.Itoa(max(m.Parallel, 1)), "--split-by-host", "--resume")
	return args
}

// newResumeManifest builds an empty manifest stamped with the run's identity.
func newResumeManifest(path, output string, formats, targetFiles []string, fingerprint string) *resumeManifest {
	now := time.Now().UTC().Format(time.RFC3339)
	return &resumeManifest{
		Version:             resumeManifestVersion,
		OutputPrefix:        output,
		Formats:             formats,
		SettingsFingerprint: fingerprint,
		TargetFiles:         targetFiles,
		CreatedAt:           now,
		UpdatedAt:           now,
		CompletedThrough:    -1,
		Severity:            make(map[string]int),
		path:                path,
		pending:             make(map[int]resumeDone),
	}
}

// loadResumeManifest reads a manifest from disk. ok=false when the file is
// missing, unreadable, or not a recognizable manifest (in which case the caller
// starts fresh and scans every target).
func loadResumeManifest(path string) (*resumeManifest, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var m resumeManifest
	if err := json.Unmarshal(data, &m); err != nil || m.Version == 0 {
		return nil, false
	}
	if m.Severity == nil {
		m.Severity = make(map[string]int)
	}
	m.pending = make(map[int]resumeDone)
	for _, d := range m.DoneIndices {
		if d.Index > m.CompletedThrough {
			m.pending[d.Index] = resumeDone{target: d.Target, stats: childStats{records: d.Records, findings: d.Findings, sev: d.Severity}}
		}
	}
	m.path = path
	return &m, true
}

// save atomically rewrites the manifest (temp file + rename) so a crash or
// Ctrl-C mid-write never leaves a corrupt file that would break a later resume.
func (m *resumeManifest) save() error {
	if m == nil || m.path == "" {
		return nil
	}
	m.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	m.DoneIndices = m.DoneIndices[:0]
	for idx, d := range m.pending {
		m.DoneIndices = append(m.DoneIndices, resumeDoneEntry{Index: idx, Target: d.target, Records: d.stats.records, Findings: d.stats.findings, Severity: d.stats.sev})
	}
	sort.Slice(m.DoneIndices, func(i, j int) bool { return m.DoneIndices[i].Index < m.DoneIndices[j].Index })
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal resume manifest: %w", err)
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("write resume manifest temp file: %w", err)
	}
	if err := os.Rename(tmp, m.path); err != nil {
		return fmt.Errorf("rename resume manifest: %w", err)
	}
	return nil
}

// markDone records that the target at absolute line index absIdx finished
// cleanly, then advances the cursor over every now-contiguous completed line
// (rolling each line's counts into the aggregates). It returns true when the
// cursor moved, so the caller only rewrites the file when the persisted state
// actually changed. Out-of-order completions ahead of the cursor wait in memory
// (bounded by -P) until the gap fills.
func (m *resumeManifest) markDone(absIdx int, target string, stats childStats) bool {
	if m == nil || absIdx <= m.CompletedThrough {
		return false
	}
	_, known := m.pending[absIdx]
	m.pending[absIdx] = resumeDone{target: target, stats: stats}
	// A new out-of-order completion changes the persisted done_indices too.
	advanced := !known
	for {
		di, ok := m.pending[m.CompletedThrough+1]
		if !ok {
			break
		}
		delete(m.pending, m.CompletedThrough+1)
		m.CompletedThrough++
		m.CursorTarget = di.target
		m.Records += di.stats.records
		m.Findings += di.stats.findings
		for k, v := range di.stats.sev {
			m.Severity[k] += v
		}
		advanced = true
	}
	return advanced
}

// completedCount is the number of targets in the cleanly-finished contiguous
// prefix: one past the cursor, floored at 0 (CompletedThrough is -1 when nothing
// is done). nil-safe so callers can use it on a freshly-loaded-or-absent manifest.
func (m *resumeManifest) completedCount() int {
	if m == nil || m.CompletedThrough < 0 {
		return 0
	}
	return m.CompletedThrough + 1
}

// startOffset is the index of the first target still needing a scan: one past
// the completed cursor, clamped to the current batch size.
func (m *resumeManifest) startOffset(total int) int {
	off := m.completedCount()
	if off > total {
		off = total
	}
	return off
}

// carryover snapshots the completed-prefix progress for the roll-up. It copies
// the severity map so later cursor advances during the run don't mutate the
// captured value.
func (m *resumeManifest) carryover() carryoverStats {
	if m == nil {
		return carryoverStats{}
	}
	count := m.completedCount()
	sev := make(map[string]int, len(m.Severity))
	for k, v := range m.Severity {
		sev[k] = v
	}
	records, findings := m.Records, m.Findings
	for _, d := range m.pending {
		count++
		records += d.stats.records
		findings += d.stats.findings
		for k, v := range d.stats.sev {
			sev[k] += v
		}
	}
	return carryoverStats{
		count: count,
		stats: childStats{records: records, findings: findings, sev: sev},
	}
}

// scanSettingsFingerprint hashes the scan flags every child inherits (the
// reconstructed argv minus the per-target/output/parallel flags the parent
// rewrites). A resume whose fingerprint differs from the manifest is warned
// about — previously-completed hosts were scanned under different settings —
// but allowed to proceed.
func scanSettingsFingerprint(cmd *cobra.Command) string {
	args := append([]string(nil), childScanArgs(cmd)...)
	sort.Strings(args)
	sum := sha256.Sum256([]byte(strings.Join(args, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:8])
}

// resumeCommandLine renders the exact command to resume this run: the operator's
// invocation echoed back with --resume appended (once). os.Args[0] is shown as
// the plain "vigolium" rather than its absolute path so the line is readable and
// copy-pasteable.
func resumeCommandLine(argv []string) string {
	parts := []string{"vigolium"}
	hasResume := false
	for _, a := range argv[1:] {
		if a == "--resume" {
			hasResume = true
		}
		parts = append(parts, a)
	}
	if !hasResume {
		parts = append(parts, "--resume")
	}
	return quoteArgv(parts)
}
