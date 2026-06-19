package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
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

	path    string             // on-disk location; not serialized
	pending map[int]resumeDone // in-memory: out-of-order completions awaiting contiguous advance
}

// resumeDone is one cleanly-completed target held in memory until the cursor
// advances over its line, at which point its counts roll into the aggregates.
type resumeDone struct {
	target string
	stats  childStats
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
	m.pending[absIdx] = resumeDone{target: target, stats: stats}
	advanced := false
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

// startOffset is the index of the first target still needing a scan: one past
// the completed cursor, clamped to the current batch size.
func (m *resumeManifest) startOffset(total int) int {
	off := m.CompletedThrough + 1
	if off < 0 {
		off = 0
	}
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
	count := m.CompletedThrough + 1
	if count < 0 {
		count = 0
	}
	sev := make(map[string]int, len(m.Severity))
	for k, v := range m.Severity {
		sev[k] = v
	}
	return carryoverStats{
		count: count,
		stats: childStats{records: m.Records, findings: m.Findings, sev: sev},
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
	for i, p := range parts {
		parts[i] = shellQuoteArg(p)
	}
	return strings.Join(parts, " ")
}

// shellQuoteArg single-quotes an argument when it contains characters a shell
// would otherwise split or interpret, so the rendered resume command pastes back
// intact. Plain tokens (the common case) are returned untouched.
func shellQuoteArg(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '"', '\'', '\\', '$', '`', '&', '|', ';', '(', ')', '<', '>', '*', '?', '[', ']', '{', '}', '#', '~':
			return true
		}
		return false
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
