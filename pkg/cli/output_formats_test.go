package cli

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestFormatFlagHelpIsTheTable: every --format help string is rendered from the
// output format table for its surface, so the formats a command lists are
// exactly the ones it accepts (output.Names; the table test pins Help == Names).
func TestFormatFlagHelpIsTheTable(t *testing.T) {
	cases := []struct {
		cmd     *cobra.Command
		persist bool
		surface output.Surface
	}{
		{rootCmd, true, output.SurfaceScan},
		{exportCmd, false, output.SurfaceExport},
		{importCmd, false, output.SurfaceImport},
		{dbExportCmd, false, output.SurfaceDBExport},
	}
	for _, c := range cases {
		flags := c.cmd.Flags()
		if c.persist {
			flags = c.cmd.PersistentFlags()
		}
		f := flags.Lookup("format")
		require.NotNil(t, f, c.cmd.CommandPath())
		assert.Contains(t, f.Usage, output.FormatsHelp(c.surface), c.cmd.CommandPath())
		for _, name := range output.Names(c.surface) {
			assert.Contains(t, f.Usage, name, c.cmd.CommandPath())
		}
	}
}

// TestFormatSurfacesRejectWithUsageError: each surface rejects a format it does
// not accept with a usage error (exit 2) that lists the surface's valid names.
func TestFormatSurfacesRejectWithUsageError(t *testing.T) {
	t.Run("scan", func(t *testing.T) {
		err := normalizeScanFormats([]string{"html", "bundle"})
		requireUsageError(t, err)
		assert.Contains(t, err.Error(), strings.Join(output.Names(output.SurfaceScan), ", "))
	})
	t.Run("export", func(t *testing.T) {
		_, err := parseExportFormats("sqlite")
		requireUsageError(t, err)
		assert.Contains(t, err.Error(), strings.Join(output.Names(output.SurfaceExport), ", "))
	})
	t.Run("db export", func(t *testing.T) {
		prev := exportFormat
		t.Cleanup(func() { exportFormat = prev })
		exportFormat = "sarif"
		_, _, err := validateDBExportFlags()
		requireUsageError(t, err)
		assert.Contains(t, err.Error(), strings.Join(output.Names(output.SurfaceDBExport), ", "))

		exportFormat = "MD-Table"
		_, _, err = validateDBExportFlags()
		require.NoError(t, err)
		assert.Equal(t, "markdown-table", exportFormat, "aliases resolve through the table")
	})
	t.Run("import", func(t *testing.T) {
		_, err := output.Lookup("jsonl", output.SurfaceImport)
		require.Error(t, err, "import renders reports only")
		_, ok := reportGenerator("jsonl")
		assert.False(t, ok)
		rf, ok := reportGenerator("md")
		require.True(t, ok)
		assert.Equal(t, "markdown", rf.Name)
	})
}

// TestScanFormatMarkdownAlias: `scan --format md` canonicalizes to markdown
// (it used to alias and then fail validation) and the post-scan report tail
// writes the .md file.
func TestScanFormatMarkdownAlias(t *testing.T) {
	formats := []string{"MD", "csv", "junit"}
	require.NoError(t, normalizeScanFormats(formats))
	assert.Equal(t, []string{"markdown", "csv", "junit"}, formats)

	db := newExportTestDB(t)
	const proj = "00000000-0000-0000-0000-0000000000bb"
	seedFindingAndRecord(t, db, proj, "md")

	base := filepath.Join(t.TempDir(), "run")
	opts := &types.Options{Output: base, OutputFormats: formats, ProjectUUID: proj}
	require.NoError(t, maybeGenerateReports(db, opts))

	md, err := os.ReadFile(base + ".md")
	require.NoError(t, err)
	assert.Contains(t, string(md), "Module md")
	csvData, err := os.ReadFile(base + ".csv")
	require.NoError(t, err)
	assert.Contains(t, string(csvData), "hash-md")
	junitData, err := os.ReadFile(base + ".junit.xml")
	require.NoError(t, err)
	var doc struct {
		Failures int `xml:"failures,attr"`
	}
	require.NoError(t, xml.Unmarshal(junitData, &doc))
	assert.Equal(t, 1, doc.Failures, "the seeded high finding fails at the default threshold")
}

// TestGitHubFormatNeverSharesStdoutWithJSON: the github format's workflow
// commands own stdout when there is no -o, so -j and --ci-output-format are
// usage errors; with -o they are fine.
func TestGitHubFormatNeverSharesStdoutWithJSON(t *testing.T) {
	prevJSON, prevCI := globalJSON, globalCIOutput
	t.Cleanup(func() { globalJSON, globalCIOutput = prevJSON, prevCI })

	globalJSON = true
	opts := types.DefaultOptions()
	opts.OutputFormats = []string{"github"}
	requireUsageError(t, reconcileOutputFormats(opts))

	opts = types.DefaultOptions()
	opts.OutputFormats = []string{"github"}
	opts.Output = "ci"
	require.NoError(t, reconcileOutputFormats(opts))

	assert.False(t, formatNeedsOutput("github"), "github streams to stdout without -o")
	assert.True(t, formatNeedsOutput("csv"))
	assert.True(t, formatNeedsOutput("no-such-format"), "unknown formats default to needing -o")
}

// TestDismissedStatusesMatchDatabase: pkg/output cannot import pkg/database, so
// it keeps its own copy of the dismissed statuses; this keeps them equal.
func TestDismissedStatusesMatchDatabase(t *testing.T) {
	assert.Equal(t, database.DismissedFindingStatuses, output.DismissedFindingStatuses)
}

// TestPDFFailureKeepsItsCode: a PDF render failure on the post-scan export path
// reports pdf_failed (not the generic export_failed) and still counts as an
// export failure, so the remaining formats are still written.
func TestPDFFailureKeepsItsCode(t *testing.T) {
	var err error
	recordExportFailure(&err, fmt.Errorf("generate PDF report out.pdf: %w", fmt.Errorf("%w: chrome: exit 1", output.ErrPDFFailed)))
	require.Error(t, err)
	assert.Equal(t, apicontract.CodePDFFailed, classifyErrorCode(err, classifyExitCode(err)))
	assert.True(t, isExportFailure(err))

	err = nil
	recordExportFailure(&err, fmt.Errorf("write out.html: denied"))
	assert.Equal(t, apicontract.CodeExportFailed, classifyErrorCode(err, classifyExitCode(err)))

	// `vigolium export --format pdf` returns the renderer's error directly.
	direct := fmt.Errorf("%w: Chrome/Chromium not found", output.ErrPDFFailed)
	assert.Equal(t, apicontract.CodePDFFailed, classifyErrorCode(direct, classifyExitCode(direct)))
}

// TestReportFlagsReachMeta: --max-body-bytes, --pdf-timeout and --fail-on land
// in the report meta, and a stateless run's discarded store suppresses
// follow-up commands.
func TestReportFlagsReachMeta(t *testing.T) {
	prevBody, prevPDF, prevFail := reportMaxBodyBytes, reportPDFTimeout, scanFailOn
	t.Cleanup(func() { reportMaxBodyBytes, reportPDFTimeout, scanFailOn = prevBody, prevPDF, prevFail })

	reportMaxBodyBytes, reportPDFTimeout, scanFailOn = 128, 0, "high"
	var meta output.HTMLReportMeta
	applyReportFlags(&meta, false)
	assert.Equal(t, 128, meta.MaxBodyBytes)
	assert.Equal(t, "high", meta.FailOn)
	require.NotNil(t, meta.FollowUp)
	assert.Contains(t, meta.FollowUp("finding", "--id", "1"), "finding --id 1")

	reportMaxBodyBytes = 0
	applyReportFlags(&meta, true)
	assert.Equal(t, -1, meta.MaxBodyBytes, "0 disables the cap")
	assert.Empty(t, meta.FollowUp("finding", "--id", "1"), "a discarded store has no follow-up")

	reportPDFTimeout = -1
	requireUsageError(t, validateReportFlags())
}

// TestRenderServerReportNewFormats: REST output_formats renders every REST
// report format through the same table, including the new ones.
func TestRenderServerReportNewFormats(t *testing.T) {
	db := newExportTestDB(t)
	const proj = "00000000-0000-0000-0000-0000000000cc"
	seedFindingAndRecord(t, db, proj, "rest")
	dir := t.TempDir()
	for _, format := range []string{"html", "markdown", "csv", "junit"} {
		require.Contains(t, serverReportFormats(), format)
		out := types.FormatOutputPath(filepath.Join(dir, "output"), format)
		require.NoError(t, renderServerReport(context.Background(), db, format, out, proj, ""), format)
		data, err := os.ReadFile(out)
		require.NoError(t, err, format)
		assert.Contains(t, string(data), "rest", format)
	}
	assert.NotContains(t, serverReportFormats(), "github", "annotations are a CI-stdout format, not a REST artifact")
}
