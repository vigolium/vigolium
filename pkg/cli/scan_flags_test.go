package cli

import (
	"io"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The inline/file auth flags are --auth / --auth-file, but earlier guides (and
// the Docker quick-start commands users copy) still pass --session /
// --session-file. Those are kept as hidden, deprecated aliases so existing
// commands keep working instead of failing with "unknown flag".
func TestAuthFlagAliases(t *testing.T) {
	newFlags := func(includeAuth bool) *pflag.FlagSet {
		fs := pflag.NewFlagSet("scan", pflag.ContinueOnError)
		fs.SetOutput(io.Discard) // swallow the deprecation notice in test output
		registerNativeScanFlags(fs, includeAuth)
		return fs
	}

	t.Run("--session aliases --auth", func(t *testing.T) {
		fs := newFlags(true)
		require.NoError(t, fs.Parse([]string{"--session", "user1:Cookie:a=123"}))
		assert.Equal(t, []string{"user1:Cookie:a=123"}, scanOpts.AuthInline)
	})

	t.Run("--session-file aliases --auth-file", func(t *testing.T) {
		fs := newFlags(true)
		require.NoError(t, fs.Parse([]string{"--session-file", "./admin.yaml"}))
		assert.Equal(t, []string{"./admin.yaml"}, scanOpts.AuthFiles)
	})

	t.Run("canonical --auth still works", func(t *testing.T) {
		fs := newFlags(true)
		require.NoError(t, fs.Parse([]string{"--auth", "admin:Cookie:s=1"}))
		assert.Equal(t, []string{"admin:Cookie:s=1"}, scanOpts.AuthInline)
	})

	// Regression: the alias and the canonical name must share one value list, so
	// mixing them in a single command keeps every value. The earlier
	// duplicate-flag implementation dropped all but the last (pflag tracks
	// "changed" per flag), silently losing a session in multi-session scans.
	t.Run("mixing --auth and --session keeps both values", func(t *testing.T) {
		fs := newFlags(true)
		require.NoError(t, fs.Parse([]string{"--auth", "admin:Cookie:a=1", "--session", "user:Cookie:b=2"}))
		assert.Equal(t, []string{"admin:Cookie:a=1", "user:Cookie:b=2"}, scanOpts.AuthInline)
	})

	t.Run("alias resolves to the canonical flag (not a separate flag)", func(t *testing.T) {
		fs := newFlags(true)
		assert.Same(t, fs.Lookup("auth"), fs.Lookup("session"),
			"--session must resolve to the same flag object as --auth")
		assert.Same(t, fs.Lookup("auth-file"), fs.Lookup("session-file"),
			"--session-file must resolve to the same flag object as --auth-file")
	})

	t.Run("auth flags absent when not included (e.g. scan-url/scan-request)", func(t *testing.T) {
		fs := newFlags(false)
		assert.Nil(t, fs.Lookup("auth"))
		assert.Nil(t, fs.Lookup("session"))
	})
}

// --split-by-host opts stateless multi-target scans back into one output file
// per host. It is off by default so the default is a single unified output file.
func TestSplitByHostFlag(t *testing.T) {
	fs := pflag.NewFlagSet("scan", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerNativeScanFlags(fs, true)

	t.Run("defaults to false (unified output)", func(t *testing.T) {
		globalSplitByHost = false
		require.NoError(t, fs.Parse(nil))
		assert.False(t, globalSplitByHost)
	})

	t.Run("--split-by-host sets the flag", func(t *testing.T) {
		globalSplitByHost = false
		require.NoError(t, fs.Parse([]string{"--split-by-host"}))
		assert.True(t, globalSplitByHost)
	})
}

// --captured-console is the hidden, internal flag the -P/--parallel parent sets
// on each child so the per-target <output>.console.log captures the live finding
// stream and drops the [status] ticker. It must be registered, hidden from help,
// default off, and bind to Options.CapturedConsole when passed.
func TestCapturedConsoleFlag(t *testing.T) {
	fs := pflag.NewFlagSet("scan", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerNativeScanFlags(fs, true)

	flag := fs.Lookup("captured-console")
	require.NotNil(t, flag, "--captured-console must be registered")
	assert.True(t, flag.Hidden, "--captured-console must be hidden from help")

	t.Run("defaults to false", func(t *testing.T) {
		scanOpts.CapturedConsole = false
		require.NoError(t, fs.Parse(nil))
		assert.False(t, scanOpts.CapturedConsole)
	})

	t.Run("--captured-console sets the option", func(t *testing.T) {
		scanOpts.CapturedConsole = false
		require.NoError(t, fs.Parse([]string{"--captured-console"}))
		assert.True(t, scanOpts.CapturedConsole)
	})

	scanOpts.CapturedConsole = false // don't leak into other tests
}

// perTargetOutputPath drives the --split-by-host file naming: the sanitized
// host[:port] is inserted before the format extension so per-target stateless
// exports do not clobber each other.
func TestPerTargetOutputPath(t *testing.T) {
	tests := []struct {
		name     string
		basePath string
		target   string
		idx      int
		want     string
	}{
		{"no extension keeps host suffix", "unify-output", "https://eliona-poc.example.com", 0, "unify-output-eliona-poc.example.com"},
		{"jsonl extension preserved after host", "out.jsonl", "https://etempo-bcn.example.com", 1, "out-etempo-bcn.example.com.jsonl"},
		{"host with port sanitized", "out.jsonl", "http://localhost:8080", 2, "out-localhost_8080.jsonl"},
		{"unparseable target falls back to index", "out.jsonl", "::::", 4, "out-005.jsonl"},
		// --split-by-host with no -o: the file is named by the host alone, no
		// leading "-" separator (the host already disambiguates files).
		{"empty base names file by host", "", "https://insurance.grab-sure.com", 0, "insurance.grab-sure.com"},
		{"empty base keeps bare extension", ".jsonl", "https://insurance.grab-sure.com", 0, "insurance.grab-sure.com.jsonl"},
		{"empty base unparseable falls back to index", "", "::::", 3, "004"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, perTargetOutputPath(tt.basePath, tt.target, tt.idx))
		})
	}
}
