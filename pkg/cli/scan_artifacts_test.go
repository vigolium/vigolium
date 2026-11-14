package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestScanSummaryTail: the human summary names what the scan wrote
// (Report:, with the file), where it stored results (Stored:) and what to run
// next (Next:), and the -j fields carry the same artifacts and argv.
func TestScanSummaryTail(t *testing.T) {
	resetScanArtifacts()
	t.Cleanup(resetScanArtifacts)
	dir := t.TempDir()
	report := filepath.Join(dir, "report.html")
	require.NoError(t, os.WriteFile(report, []byte("<html>12345</html>"), 0o644))
	jsonl := filepath.Join(dir, "out.jsonl")
	require.NoError(t, os.WriteFile(jsonl, []byte("{}\n"), 0o644))
	noteScanArtifact("html", report)
	noteScanArtifact("html", report) // once
	noteScanArtifact("jsonl", jsonl)
	noteScanArtifact("jsonl", "-") // stdout is not an artifact

	arts := collectedScanArtifacts()
	require.Len(t, arts, 2)
	require.Equal(t, int64(len("<html>12345</html>")), arts[0].Bytes)

	next := scanNextSteps("scan-1", "/tmp/v.sqlite", 3, true)
	require.Equal(t, []string{"vigolium", "finding", "--scan-uuid", "scan-1", "--db", "/tmp/v.sqlite"}, next[0].Argv)
	require.Equal(t, []string{"vigolium", "finding", "load", arts[1].Path}, next[len(next)-1].Argv)

	out := captureStderr(t, func() { printSummaryTail("scan-1", "/tmp/v.sqlite", 3, true) })
	require.Contains(t, out, "Report:")
	require.Contains(t, out, "report.html")
	require.Contains(t, out, "Stored:")
	require.True(t, strings.Contains(out, "Next:") && strings.Contains(out, "finding --scan-uuid scan-1"), out)

	// A -S run with no artifacts suggests nothing it cannot back.
	resetScanArtifacts()
	require.Empty(t, scanNextSteps("scan-1", "", 0, false))
}
