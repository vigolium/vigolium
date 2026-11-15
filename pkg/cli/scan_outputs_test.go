package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/types"
)

func outputsTestCmd(t *testing.T, format string) *cobra.Command {
	t.Helper()
	swapGlobal(t, &globalFormat, "console")
	c := &cobra.Command{Use: "scan"}
	c.Flags().StringVar(&globalFormat, "format", "console", "")
	if format != "" {
		require.NoError(t, c.Flags().Set("format", format))
	}
	return c
}

func TestResolveScanOutputs(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name       string
		json       bool
		output     string
		format     string
		wantFormat string
		wantOutput string
		wantDoc    string
		usage      bool
	}{
		{name: "html extension picks html", output: "r.html", wantFormat: "html", wantOutput: "r.html"},
		{name: "junit double extension", output: "r.junit.xml", wantFormat: "junit", wantOutput: "r.junit.xml"},
		{name: "jsonl", output: "f.jsonl", wantFormat: "jsonl", wantOutput: "f.jsonl"},
		{name: "unknown extension keeps console", output: "scan.txt", wantFormat: "console", wantOutput: "scan.txt"},
		{name: "explicit format wins", output: "r.html", format: "jsonl", wantFormat: "jsonl", wantOutput: "r.html"},
		{name: ".json without -j", output: "findings.json", usage: true},
		{name: "plain .xml", output: "r.xml", usage: true},
		{name: "-j .json is the document", json: true, output: filepath.Join(dir, "doc.json"), wantFormat: "console", wantDoc: filepath.Join(dir, "doc.json")},
		{name: "-j no extension is the document", json: true, output: filepath.Join(dir, "doc"), wantFormat: "console", wantDoc: filepath.Join(dir, "doc")},
		{name: "-j with an inferred format keeps the base", json: true, output: "r.html", wantFormat: "html", wantOutput: "r.html"},
		{name: "-j --format html -o .json splits", json: true, output: filepath.Join(dir, "r.json"), format: "html", wantFormat: "html", wantOutput: filepath.Join(dir, "r"), wantDoc: filepath.Join(dir, "r.json")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := outputsTestCmd(t, c.format)
			swapGlobal(t, &globalJSON, c.json)
			swapGlobal(t, &scanOpts, types.DefaultOptions())
			swapGlobal(t, &jsonOutputPath, "stale")
			scanOpts.Output = c.output

			err := resolveScanOutputs(cmd)
			if c.usage {
				require.Error(t, err)
				assert.Equal(t, ExitUsageError, classifyExitCode(err))
				var ce clicommon.CLIError
				require.True(t, errors.As(err, &ce))
				assert.NotEmpty(t, ce.Hint)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.wantFormat, globalFormat)
			assert.Equal(t, c.wantOutput, scanOpts.Output)
			assert.Equal(t, c.wantDoc, jsonOutputPath)
		})
	}
}

// .json without -j names both remedies.
func TestResolveScanOutputsJSONNamesRemedies(t *testing.T) {
	cmd := outputsTestCmd(t, "")
	swapGlobal(t, &globalJSON, false)
	swapGlobal(t, &scanOpts, types.DefaultOptions())
	scanOpts.Output = "findings.json"
	err := resolveScanOutputs(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "-j")
	assert.Contains(t, err.Error(), "--format jsonl")
}

func TestPreflightOutputs(t *testing.T) {
	t.Run("creates missing parents and leaves no file", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "nodir", "deeper", "x.jsonl")
		opts := types.DefaultOptions()
		opts.Output = base
		opts.OutputFormats = []string{"jsonl", "html"}
		require.NoError(t, preflightOutputs(opts))
		assert.DirExists(t, filepath.Dir(base))
		assert.NoFileExists(t, base, "the probe removes a file it created")
	})
	t.Run("an existing file is not truncated", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "x.jsonl")
		require.NoError(t, os.WriteFile(p, []byte("keep"), 0o600))
		opts := types.DefaultOptions()
		opts.Output = p
		opts.OutputFormats = []string{"jsonl"}
		require.NoError(t, preflightOutputs(opts))
		assert.Equal(t, "keep", readFileString(t, p))
	})
	t.Run("an unwritable parent is export_failed", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(blocker, nil, 0o600))
		opts := types.DefaultOptions()
		opts.Output = filepath.Join(blocker, "x.html")
		opts.OutputFormats = []string{"html"}
		err := preflightOutputs(opts)
		require.Error(t, err)
		assert.True(t, isExportFailure(err))
		assert.Equal(t, apicontract.CodeExportFailed, classifyErrorCode(err, classifyExitCode(err)))
	})
	t.Run("a directory in place of the file", func(t *testing.T) {
		d := t.TempDir()
		opts := types.DefaultOptions()
		opts.Output = d
		opts.OutputFormats = []string{"console"}
		require.Error(t, preflightOutputs(opts))
	})
}
