package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
)

// resolveScanOutputs settles what -o means for a scan command (scan, run,
// scan-url, scan-request), before any request is sent.
//
//   - With no --format, a known extension picks the format: -o r.html is
//     --format html, -o r.junit.xml is junit, -o r.sqlite is sqlite.
//   - -o x.json is not a scan format. Under -j it names the file the scan
//     document goes to; without -j it is a usage error naming -j and
//     --format jsonl. A plain .xml names .junit.xml.
//   - Under -j, -o names the document file when no format was given or
//     inferred, or when it ends in .json; otherwise it stays the base path the
//     format files are named from.
//
// It rewrites globalFormat, scanOpts.Output and jsonOutputPath (the -j
// document destination), which every later step reads.
func resolveScanOutputs(cmd *cobra.Command) error {
	// The scan commands do not register the read commands' -o, so the document
	// destination is this function's to set; clear what an earlier in-process
	// invocation left behind.
	jsonOutputPath = ""
	path := strings.TrimSpace(scanOpts.Output)
	if path == "" {
		return nil
	}
	formatGiven := cmd != nil && cmd.Flags().Changed("format")
	lower := strings.ToLower(path)
	isJSON := strings.HasSuffix(lower, ".json")

	if !formatGiven {
		switch f, ok := output.FormatByExtension(path, output.SurfaceScan); {
		case ok:
			globalFormat = f.Name
			formatGiven = true
		case isJSON && !globalJSON:
			return usageHintErrorf(
				"pass -j to write the scan document to the file, or --format jsonl -o "+strings.TrimSuffix(path, filepath.Ext(path))+".jsonl for the findings stream",
				"-o %s: a .json file is the -j scan document, not a --format", path)
		case strings.HasSuffix(lower, ".xml"):
			return usageHintErrorf("name the file "+strings.TrimSuffix(path, filepath.Ext(path))+".junit.xml, or pass --format junit",
				"-o %s: .xml is ambiguous; the JUnit report is written as .junit.xml", path)
		}
	}
	if !globalJSON {
		return nil
	}
	if isJSON || !formatGiven {
		jsonOutputPath = path
		if !formatGiven {
			// The document is the only output: no format file, no transcript.
			scanOpts.Output = ""
			return probeOutputPath(path, false)
		}
		// The format files are named from the base: -o r.json --format html
		// writes r.json (the document) and r.html.
		scanOpts.Output = types.StripFormatExtension(path)
		return probeOutputPath(path, false)
	}
	return nil
}

// usageHintErrorf is a usage error (exit 2) carrying a hint.
func usageHintErrorf(hint, format string, args ...any) error {
	return clicommon.CLIError{Err: fmt.Errorf(format, args...), Hint: hint}
}

// scanOutputPaths lists every file or directory base the run's -o will be
// written to: one per format, the console transcript included.
func scanOutputPaths(opts *types.Options) []outputTarget {
	if opts == nil || strings.TrimSpace(opts.Output) == "" {
		return nil
	}
	var out []outputTarget
	for _, f := range opts.OutputFormats {
		name := output.CanonicalFormat(f)
		switch name {
		case "fs":
			// A directory base: <base>-traffic/, <base>-findings/.
			out = append(out, outputTarget{path: opts.OutputBasePath(), dir: true})
		case "console":
			p := opts.Output
			if len(opts.OutputFormats) > 1 {
				p = opts.OutputPathForFormat("console")
			}
			out = append(out, outputTarget{path: p})
		default:
			out = append(out, outputTarget{path: opts.OutputPathForFormat(name)})
		}
	}
	return out
}

type outputTarget struct {
	path string
	dir  bool
}

// preflightOutputs creates the missing parent directories of every -o target
// and checks each can be opened for writing, so an unwritable destination fails
// in milliseconds rather than after the scan, when a -S run's results are gone.
// A failure is export_failed (exit 1), the code the same failure after the scan
// carries.
func preflightOutputs(opts *types.Options) error {
	for _, t := range scanOutputPaths(opts) {
		if err := probeOutputPath(t.path, t.dir); err != nil {
			return err
		}
	}
	return nil
}

// probeOutputPath creates path's parent directory and checks path can be
// written: an existing file is opened for append (not truncated), a missing
// one is created and removed again. dir marks a directory base, whose parent
// only has to exist.
func probeOutputPath(path string, dir bool) error {
	path = strings.TrimSpace(path)
	if path == "" || path == "-" || strings.Contains(path, "://") {
		return nil
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return codedErrorf(apicontract.CodeExportFailed, "cannot write -o %s: create %s: %w", path, parent, err)
	}
	if dir {
		return nil
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return codedErrorf(apicontract.CodeExportFailed, "cannot write -o %s: it is a directory", path)
	}
	_, statErr := os.Stat(path)
	existed := statErr == nil
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return codedErrorf(apicontract.CodeExportFailed, "cannot write -o %s: %w", path, err)
	}
	_ = f.Close()
	if !existed && errors.Is(statErr, fs.ErrNotExist) {
		_ = os.Remove(path)
	}
	return nil
}
