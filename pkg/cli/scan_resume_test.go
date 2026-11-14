package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A manifest written to disk reloads with the same cursor and aggregates, the
// atomic save leaves no stray temp file, and the reloaded manifest can keep
// advancing.
func TestResumeManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "myt.progress.json")

	m := newResumeManifest(path, "myt", []string{"sqlite", "html"}, []string{"targets.txt"}, "sha256:abc")
	m.markDone(0, "https://a.example.com", childStats{records: 12, findings: 3, sev: map[string]int{"high": 1, "medium": 2}})
	require.NoError(t, m.save())

	// No leftover temp file from the atomic write.
	_, statErr := os.Stat(path + ".tmp")
	assert.True(t, os.IsNotExist(statErr), "temp file should be renamed away")

	got, ok := loadResumeManifest(path)
	require.True(t, ok)
	assert.Equal(t, resumeManifestVersion, got.Version)
	assert.Equal(t, "sha256:abc", got.SettingsFingerprint)
	assert.Equal(t, 0, got.CompletedThrough)
	assert.Equal(t, "https://a.example.com", got.CursorTarget)
	assert.Equal(t, 12, got.Records)
	assert.Equal(t, 3, got.Findings)
	assert.Equal(t, map[string]int{"high": 1, "medium": 2}, got.Severity)

	// A reloaded manifest has a fresh in-memory pending set and keeps advancing.
	require.NotNil(t, got.pending)
	assert.True(t, got.markDone(1, "https://b.example.com", childStats{records: 1}))
	assert.Equal(t, 1, got.CompletedThrough)
	assert.Equal(t, "https://b.example.com", got.CursorTarget)
	// Re-marking a line at or below the cursor is a no-op (no double count).
	assert.False(t, got.markDone(0, "https://a.example.com", childStats{records: 99}))
	assert.Equal(t, 13, got.Records)
}

// A missing or garbage manifest loads as "not found" so the caller scans
// everything rather than erroring.
func TestLoadResumeManifestMissingOrCorrupt(t *testing.T) {
	dir := t.TempDir()
	_, ok := loadResumeManifest(filepath.Join(dir, "nope.json"))
	assert.False(t, ok)

	bad := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte("{not json"), 0644))
	_, ok = loadResumeManifest(bad)
	assert.False(t, ok)

	// Valid JSON but not a manifest (version 0) is also rejected.
	empty := filepath.Join(dir, "empty.json")
	require.NoError(t, os.WriteFile(empty, []byte("{}"), 0644))
	_, ok = loadResumeManifest(empty)
	assert.False(t, ok)
}

func TestResumeManifestPath(t *testing.T) {
	// Derived from the --output prefix, stripping any format extension.
	assert.Equal(t, "myt.progress.json", resumeManifestPath("myt", nil))
	assert.Equal(t, "myt.progress.json", resumeManifestPath("myt.sqlite", nil))
	assert.Equal(t, "out/scan.progress.json", resumeManifestPath("out/scan.html", nil))

	// No -o: fall back to the first target file's base name.
	assert.Equal(t, "subs.progress.json", resumeManifestPath("", []string{"subs.txt"}))
	assert.Equal(t, "subs.progress.json", resumeManifestPath("", []string{"lists/subs.txt"}))

	// Nothing to key on: a fixed default in the working directory.
	assert.Equal(t, "vigolium-scan.progress.json", resumeManifestPath("", nil))
}

// markDone advances the cursor over a contiguous run of completed lines and
// rolls each line's counts into the aggregates as the cursor reaches it.
func TestResumeManifestMarkDoneInOrder(t *testing.T) {
	m := newResumeManifest("p.json", "p", nil, nil, "")
	assert.Equal(t, -1, m.CompletedThrough)

	assert.True(t, m.markDone(0, "https://a", childStats{records: 5, findings: 1, sev: map[string]int{"high": 1}}))
	assert.Equal(t, 0, m.CompletedThrough)
	assert.Equal(t, "https://a", m.CursorTarget)
	assert.Equal(t, 5, m.Records)
	assert.Equal(t, 1, m.Findings)

	assert.True(t, m.markDone(1, "https://b", childStats{records: 3}))
	assert.Equal(t, 1, m.CompletedThrough)
	assert.Equal(t, "https://b", m.CursorTarget)
	assert.Equal(t, 8, m.Records)
}

// An out-of-order completion ahead of the cursor waits in memory (not counted,
// cursor unmoved) until the gap before it fills, then both roll in together.
func TestResumeManifestMarkDoneOutOfOrder(t *testing.T) {
	m := newResumeManifest("p.json", "p", nil, nil, "")

	// Line 1 finishes before line 0 (parallel fan-out): cursor must not move and
	// its counts must not be tallied yet — but the manifest changed (done_indices),
	// so markDone asks for a save.
	assert.True(t, m.markDone(1, "https://b", childStats{records: 3}))
	assert.Equal(t, -1, m.CompletedThrough)
	assert.Equal(t, 0, m.Records)

	// Line 0 fills the gap → cursor jumps to 1, both lines' counts roll in, and
	// CursorTarget reflects the furthest contiguous line.
	assert.True(t, m.markDone(0, "https://a", childStats{records: 5}))
	assert.Equal(t, 1, m.CompletedThrough)
	assert.Equal(t, "https://b", m.CursorTarget)
	assert.Equal(t, 8, m.Records)
}

// startOffset is one past the cursor, clamped to the batch size, and carryover
// snapshots prior progress with an independent severity map.
func TestResumeManifestStartOffsetAndCarryover(t *testing.T) {
	m := newResumeManifest("p.json", "p", []string{"sqlite"}, nil, "")
	m.markDone(0, "https://a", childStats{records: 5, findings: 1, sev: map[string]int{"high": 1}})
	m.markDone(1, "https://b", childStats{records: 3, sev: map[string]int{"medium": 2}})

	assert.Equal(t, 2, m.startOffset(10)) // cursor=1 → resume at line 2
	assert.Equal(t, 2, m.startOffset(2))  // whole batch done → start == total
	assert.Equal(t, 1, m.startOffset(1))  // file shrank below cursor → clamp to total

	carry := m.carryover()
	assert.Equal(t, 2, carry.count)
	assert.Equal(t, 8, carry.stats.records)
	assert.Equal(t, 1, carry.stats.findings)
	assert.Equal(t, map[string]int{"high": 1, "medium": 2}, carry.stats.sev)

	// carryover copied the severity map: later cursor advances don't mutate it.
	m.Severity["high"] = 99
	assert.Equal(t, 1, carry.stats.sev["high"])

	// A fresh manifest carries nothing and resumes from the top.
	fresh := newResumeManifest("p.json", "p", nil, nil, "")
	assert.Equal(t, 0, fresh.startOffset(10))
	assert.Equal(t, 0, fresh.carryover().count)
}

func TestResumeCommandLine(t *testing.T) {
	// --resume is appended exactly once and os.Args[0] becomes plain "vigolium".
	argv := []string{"/usr/local/bin/vigolium", "scan", "-S", "-o", "myt", "-T", "subs.txt"}
	got := resumeCommandLine(argv)
	assert.Equal(t, "vigolium scan -S -o myt -T subs.txt --resume", got)

	// Already present: not duplicated.
	argv = []string{"vigolium", "scan", "--resume", "-T", "subs.txt"}
	got = resumeCommandLine(argv)
	assert.Equal(t, "vigolium scan --resume -T subs.txt", got)

	// Arguments needing the shell get single-quoted so the line pastes back.
	argv = []string{"vigolium", "scan", "-H", "Cookie: a=b; c=d", "-T", "subs.txt"}
	got = resumeCommandLine(argv)
	assert.Equal(t, "vigolium scan -H 'Cookie: a=b; c=d' -T subs.txt --resume", got)
}

func TestQuoteArgvWords(t *testing.T) {
	assert.Equal(t, "plain --skip=kis '' 'with space' 'it'\\''s'",
		quoteArgv([]string{"plain", "--skip=kis", "", "with space", "it's"}))
}

// Bare-resume discovery: an explicit -o pins the manifest exactly, while no -o
// scans the working directory for a single *.progress.json, reporting zero or
// several matches as errors so the operator disambiguates.
func TestDiscoverResumeManifestPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	// Empty directory: nothing to resume.
	_, err := discoverResumeManifestPath("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no progress file")

	// Exactly one manifest: auto-picked.
	require.NoError(t, os.WriteFile("roch.progress.json", []byte("{}"), 0644))
	got, err := discoverResumeManifestPath("")
	require.NoError(t, err)
	assert.Equal(t, "roch.progress.json", got)

	// A second manifest makes the bare form ambiguous.
	require.NoError(t, os.WriteFile("acme.progress.json", []byte("{}"), 0644))
	_, err = discoverResumeManifestPath("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multiple progress files")

	// An explicit -o prefix pins one regardless of how many exist.
	got, err = discoverResumeManifestPath("roch")
	require.NoError(t, err)
	assert.Equal(t, "roch.progress.json", got)

	// An -o prefix whose manifest does not exist is an error.
	_, err = discoverResumeManifestPath("missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no resume manifest")
}

// The relaunch args reproduce the saved run: ScanArgs carries the inherited
// per-child flags and the per-target -T/-o/-P/--split-by-host are rebuilt from
// the dedicated fields, with --resume appended. An older manifest without
// ScanArgs degrades to the stateless essentials.
func TestBuildResumeRelaunchArgs(t *testing.T) {
	m := &resumeManifest{
		OutputPrefix: "roch",
		Formats:      []string{"sqlite", "html"},
		TargetFiles:  []string{"subs.txt"},
		Parallel:     2,
		ScanArgs:     []string{"--stateless", "--format", "sqlite,html", "--fuzz-wordlist", "/w/fast.txt", "--skip", "known-issue-scan"},
	}
	assert.Equal(t, []string{
		"--stateless", "--format", "sqlite,html", "--fuzz-wordlist", "/w/fast.txt", "--skip", "known-issue-scan",
		"-T", "subs.txt", "-o", "roch", "-P", "2", "--split-by-host", "--resume",
	}, buildResumeRelaunchArgs(m))

	// Multiple target files each re-emit a -T; a zero/absent parallel clamps to 1.
	multi := &resumeManifest{TargetFiles: []string{"a.txt", "b.txt"}, ScanArgs: []string{"--stateless"}}
	assert.Equal(t, []string{
		"--stateless", "-T", "a.txt", "-T", "b.txt", "-P", "1", "--split-by-host", "--resume",
	}, buildResumeRelaunchArgs(multi))

	// Pre-ScanArgs manifest: synthesize --stateless + --format from the saved
	// formats so the basic per-host run still resumes.
	old := &resumeManifest{OutputPrefix: "roch", Formats: []string{"jsonl"}, TargetFiles: []string{"subs.txt"}, Parallel: 3}
	assert.Equal(t, []string{
		"--stateless", "--format", "jsonl", "-T", "subs.txt", "-o", "roch", "-P", "3", "--split-by-host", "--resume",
	}, buildResumeRelaunchArgs(old))
}

// The fingerprint is stable across calls, changes when an inherited flag
// changes, and ignores the per-target/output flags the parent rewrites.
func TestScanSettingsFingerprint(t *testing.T) {
	newCmd := func() *cobra.Command {
		c := &cobra.Command{Use: "scan"}
		c.Flags().String("intensity", "", "")
		c.Flags().String("target-file", "", "")
		c.Flags().String("output", "", "")
		return c
	}

	base := newCmd()
	require.NoError(t, base.Flags().Set("intensity", "deep"))
	require.NoError(t, base.Flags().Set("target-file", "a.txt"))
	require.NoError(t, base.Flags().Set("output", "myt"))
	fp1 := scanSettingsFingerprint(base)
	assert.Contains(t, fp1, "sha256:")
	assert.Equal(t, fp1, scanSettingsFingerprint(base), "stable across calls")

	// Changing a per-target/output flag the parent rewrites must NOT move it.
	sameSettings := newCmd()
	require.NoError(t, sameSettings.Flags().Set("intensity", "deep"))
	require.NoError(t, sameSettings.Flags().Set("target-file", "b.txt"))
	require.NoError(t, sameSettings.Flags().Set("output", "other"))
	assert.Equal(t, fp1, scanSettingsFingerprint(sameSettings))

	// Changing an inherited scan setting must move it.
	changed := newCmd()
	require.NoError(t, changed.Flags().Set("intensity", "quick"))
	assert.NotEqual(t, fp1, scanSettingsFingerprint(changed))
}
