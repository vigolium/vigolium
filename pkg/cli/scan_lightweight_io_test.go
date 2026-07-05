package cli

import (
	"io"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/types"
)

// resetLightweightIOGlobals clears every package global the routing helpers read
// so subtests don't leak state into one another (and into the rest of the suite).
func resetLightweightIOGlobals() {
	scanOpts.Output = ""
	globalStateless = false
	globalSkipPhases = nil
	globalFormat = "console"
	scanPrintFinding = false
	scanPrintTraffic = false
	scanPrintTrafficTree = false
	scanPhaseDiscover = false
	scanPhaseSpider = false
	scanPhaseExternalHarvest = false
	scanPhaseKnownIssueScan = false
}

// The lightweight scan-url / scan-request commands gained -o/--output,
// -S/--stateless, and --skip so their output surface matches `vigolium scan`.
// Before this they errored with "unknown flag", forcing users onto the full
// scan command.
func TestRegisterLightweightScanIOFlags(t *testing.T) {
	defer resetLightweightIOGlobals()

	fs := pflag.NewFlagSet("scan-url", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerLightweightScanIOFlags(fs)

	require.NotNil(t, fs.Lookup("output"), "-o/--output must be registered")
	require.NotNil(t, fs.Lookup("stateless"), "-S/--stateless must be registered")
	require.NotNil(t, fs.Lookup("skip"), "--skip must be registered")
	require.NotNil(t, fs.Lookup("print-finding"), "--print-finding must be registered")
	require.NotNil(t, fs.Lookup("print-traffic"), "--print-traffic must be registered")
	require.NotNil(t, fs.Lookup("print-traffic-tree"), "--print-traffic-tree must be registered")
	assert.Equal(t, "o", fs.Lookup("output").Shorthand)
	assert.Equal(t, "S", fs.Lookup("stateless").Shorthand)

	require.NoError(t, fs.Parse([]string{"-o", "out", "-S", "--skip", "known-issue-scan"}))
	assert.Equal(t, "out", scanOpts.Output)
	assert.True(t, globalStateless)
	assert.Equal(t, []string{"known-issue-scan"}, globalSkipPhases)
}

// hasFileOutputFormat decides whether a run needs the Runner-backed export tail.
// Plain --json keeps globalFormat at "console", so the fast direct path (and the
// JSON shape AI agents consume) is preserved.
func TestHasFileOutputFormat(t *testing.T) {
	defer resetLightweightIOGlobals()

	cases := []struct {
		format string
		want   bool
	}{
		{"console", false},
		{"jsonl", true},
		{"html", true},
		{"jsonl,html", true},
		{"console,jsonl", true},
		{"report", true},
		{"pdf", true},
	}
	for _, tc := range cases {
		globalFormat = tc.format
		assert.Equalf(t, tc.want, hasFileOutputFormat(), "format=%q", tc.format)
	}
}

// needsRunnerScan must trip for every flag the direct path can't satisfy, and
// stay false for a plain quick scan so scan-url keeps its lightweight behavior.
func TestNeedsRunnerScan(t *testing.T) {
	t.Run("plain scan stays on the direct path", func(t *testing.T) {
		resetLightweightIOGlobals()
		defer resetLightweightIOGlobals()
		assert.False(t, needsRunnerScan())
	})

	triggers := map[string]func(){
		"--output":             func() { scanOpts.Output = "out.jsonl" },
		"--stateless":          func() { globalStateless = true },
		"--skip":               func() { globalSkipPhases = []string{"known-issue-scan"} },
		"--print-finding":      func() { scanPrintFinding = true },
		"--print-traffic":      func() { scanPrintTraffic = true },
		"--print-traffic-tree": func() { scanPrintTrafficTree = true },
		"--format jsonl":       func() { globalFormat = "jsonl" },
		"--discover (phase)":   func() { scanPhaseDiscover = true },
		"--spider (phase)":     func() { scanPhaseSpider = true },
	}
	for name, set := range triggers {
		t.Run(name+" routes to the Runner", func(t *testing.T) {
			resetLightweightIOGlobals()
			defer resetLightweightIOGlobals()
			set()
			assert.True(t, needsRunnerScan())
		})
	}
}

// validateRunnerScanOutput mirrors the `vigolium scan` guards: report formats and
// multi-format runs need a -o base path, otherwise the export tail has nowhere to
// write and would silently produce nothing.
func TestValidateRunnerScanOutput(t *testing.T) {
	cases := []struct {
		name    string
		output  string
		formats []string
		wantErr bool
	}{
		{"jsonl to stdout is fine", "", []string{"jsonl"}, false},
		{"console only is fine", "", []string{"console"}, false},
		{"html without -o errors", "", []string{"html"}, true},
		{"report without -o errors", "", []string{"report"}, true},
		{"pdf without -o errors", "", []string{"pdf"}, true},
		{"multi-format without -o errors", "", []string{"jsonl", "html"}, true},
		{"html with -o is fine", "report.html", []string{"html"}, false},
		{"multi-format with -o is fine", "out", []string{"jsonl", "html"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := &types.Options{Output: tc.output, OutputFormats: tc.formats}
			err := validateRunnerScanOutput(opts)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// scan-url accepts -t/--target as a repeatable alternative to the positional URL
// so the command matches `vigolium scan`'s muscle memory.
func TestScanURLTargetFlag(t *testing.T) {
	saved := globalTargets
	defer func() { globalTargets = saved }()

	fs := pflag.NewFlagSet("scan-url", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringSliceVarP(&globalTargets, "target", "t", nil, "")

	globalTargets = nil
	require.NoError(t, fs.Parse([]string{"-t", "https://a.example", "-t", "https://b.example"}))
	assert.Equal(t, []string{"https://a.example", "https://b.example"}, globalTargets)
}
