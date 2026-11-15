package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/requestinput"
)

// withInputReadTimeout restores the package global after a test mutates it.
// The global is process-wide and pflag writes it at registration, so a test
// that leaves it changed would silently re-time every later stdin test.
func withInputReadTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	orig := globalInputReadTimeout
	globalInputReadTimeout = d
	t.Cleanup(func() { globalInputReadTimeout = orig })
}

// TestStdinReadTimeoutZeroDisables pins the fix for the one value of
// --input-read-timeout whose documented meaning the code contradicted.
//
// The help text has always said "0 disables it", and ReadBounded has always
// treated a non-positive timeout as "no deadline". In between, stdinReadTimeout
// substituted the three-minute default for anything <= 0, so passing 0 re-armed
// the very deadline the caller asked to remove — and the caller who passes 0 is
// the one feeding vigolium from a producer slower than any deadline they can
// guess.
func TestStdinReadTimeoutZeroDisables(t *testing.T) {
	withInputReadTimeout(t, 0)
	assert.Equal(t, time.Duration(0), stdinReadTimeout(),
		"--input-read-timeout 0 must reach ReadBounded as 0 (no deadline)")

	withInputReadTimeout(t, 5*time.Second)
	assert.Equal(t, 5*time.Second, stdinReadTimeout())
}

// TestInputReadTimeoutDefaultsWithoutTheFlag covers the other half: a command
// that never registers the flag must still be bounded, which is why the default
// now lives in the variable's initializer rather than in stdinReadTimeout's
// fallback.
func TestInputReadTimeoutDefaultsWithoutTheFlag(t *testing.T) {
	fs := pflag.NewFlagSet("fresh", pflag.ContinueOnError)
	registerInputReadTimeoutFlag(fs)
	t.Cleanup(func() { globalInputReadTimeout = defaultInputReadTimeout })

	assert.Equal(t, defaultInputReadTimeout, globalInputReadTimeout,
		"registering the flag must leave the documented default in place")
}

// TestInputReadTimeoutRegisteredOnLightweightCommands: scan-url and
// scan-request both read a request from stdin, and neither had the dial that
// bounds that read. A piped producer that never closed hung them exactly as it
// hung `scan` before the flag was wired up.
func TestInputReadTimeoutRegisteredOnLightweightCommands(t *testing.T) {
	for _, name := range []string{"scan-url", "scan-request"} {
		t.Run(name, func(t *testing.T) {
			cmd, _, err := rootCmd.Find([]string{name})
			require.NoError(t, err)
			require.Equal(t, name, cmd.Name())
			assert.NotNil(t, cmd.Flags().Lookup(inputReadTimeoutFlag),
				"%s reads stdin and must expose --%s", name, inputReadTimeoutFlag)
		})
	}
}

// TestInputReadTimeoutFlagRegisteredOnce guards the shared helper: scan/run/
// ingest take it from registerInputSourceFlags and scan-url/scan-request from
// registerLightweightScanIOFlags. A command that ever took both would panic at
// init with a duplicate flag, so assert the two sets stay disjoint.
func TestInputReadTimeoutFlagRegisteredOnce(t *testing.T) {
	fs := pflag.NewFlagSet("both", pflag.ContinueOnError)
	registerInputReadTimeoutFlag(fs)
	assert.NotPanics(t, func() {
		// A second registration on a *different* set is fine; the point is that
		// the helper is the only definition, so the usage text cannot diverge
		// between commands the way --events once did.
		other := pflag.NewFlagSet("other", pflag.ContinueOnError)
		registerInputReadTimeoutFlag(other)
		assert.Equal(t, fs.Lookup(inputReadTimeoutFlag).Usage, other.Lookup(inputReadTimeoutFlag).Usage)
	})
}

// TestNegativeInputReadTimeoutRejected: with 0 now meaning "no deadline", a
// negative value is the only input the flag cannot express. Folding it into
// "no deadline" too would make `--input-read-timeout -1h` look like it worked.
func TestNegativeInputReadTimeoutRejected(t *testing.T) {
	cmd := &cobra.Command{Use: "fake"}
	registerInputReadTimeoutFlag(cmd.Flags())
	t.Cleanup(func() { globalInputReadTimeout = defaultInputReadTimeout })

	require.NoError(t, cmd.Flags().Parse([]string{"--input-read-timeout", "-1s"}))
	err := validateInputReadTimeout(cmd)
	require.Error(t, err)
	assert.Equal(t, ExitUsageError, classifyExitCode(err), "a bad flag value is a usage error")
	assert.Contains(t, err.Error(), "must be >= 0")
}

// TestInputReadTimeoutZeroAccepted is the companion: the value the error
// message points at must itself be accepted.
func TestInputReadTimeoutZeroAccepted(t *testing.T) {
	cmd := &cobra.Command{Use: "fake"}
	registerInputReadTimeoutFlag(cmd.Flags())
	t.Cleanup(func() { globalInputReadTimeout = defaultInputReadTimeout })

	require.NoError(t, cmd.Flags().Parse([]string{"--input-read-timeout", "0"}))
	require.NoError(t, validateInputReadTimeout(cmd))
	assert.Equal(t, time.Duration(0), stdinReadTimeout())
}

// TestInputReadTimeoutUncheckedOnCommandsWithoutTheFlag: the validator runs in
// PersistentPreRunE for every command, so it must be inert where the flag does
// not exist — including when some earlier command's registration left the
// global at a value this command never chose.
func TestInputReadTimeoutUncheckedOnCommandsWithoutTheFlag(t *testing.T) {
	withInputReadTimeout(t, -time.Hour)
	assert.NoError(t, validateInputReadTimeout(&cobra.Command{Use: "version"}))
	assert.NoError(t, validateInputReadTimeout(nil))
}

// TestNormalizeRawRequestKeepsBodyWithContentLength is the byte-preservation
// case. `scan-request` used to TrimSpace its whole input, which rewrote the
// body of every request whose payload ends in whitespace while leaving
// Content-Length declaring the original length — so the server saw a truncated
// body and the operator saw a request they never wrote.
func TestNormalizeRawRequestKeepsBodyWithContentLength(t *testing.T) {
	withBody := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\n\r\na=1 \r\n\n"
	got := normalizeRawRequestInput(withBody)
	require.Equal(t, withBody, got, "a declared body must survive byte for byte")
	_, body, ok := strings.Cut(got, "\r\n\r\n")
	require.True(t, ok)
	assert.Equal(t, "a=1 \r\n\n", body)

	chunked := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n4\r\na=1 \r\n0\r\n\r\n"
	assert.Equal(t, chunked, normalizeRawRequestInput(chunked),
		"Transfer-Encoding declares a body just as Content-Length does")
}

// TestNormalizeRawRequestTrimsBodylessRequest keeps the forgiving behavior for
// the common case the trim existed to serve: a bodyless GET pasted out of a
// terminal, with a stray blank line at the end.
func TestNormalizeRawRequestTrimsBodylessRequest(t *testing.T) {
	assert.Equal(t,
		"GET / HTTP/1.1\r\nHost: x",
		normalizeRawRequestInput("\n\n  GET / HTTP/1.1\r\nHost: x\r\n\r\n \n"))
}

// TestNormalizeRawRequestAlwaysTrimsLeading: nothing legitimate precedes the
// method, and a blank first line would be parsed as the request line.
func TestNormalizeRawRequestAlwaysTrimsLeading(t *testing.T) {
	in := "\r\n\t POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi\n"
	got := normalizeRawRequestInput(in)
	assert.True(t, strings.HasPrefix(got, "POST / HTTP/1.1"), "got %q", got)
	assert.True(t, strings.HasSuffix(got, "hi\n"), "trailing body bytes kept; got %q", got)
}

// TestRawRequestBodyHeaderLookupIsHeaderOnly: a body that merely mentions
// Content-Length must not make a bodyless request look body-bearing.
func TestRawRequestBodyHeaderLookupIsHeaderOnly(t *testing.T) {
	assert.False(t, requestinput.DeclaresBody("GET /x?q=Content-Length:+5 HTTP/1.1\r\nHost: x\r\n\r\n"))
	assert.True(t, requestinput.DeclaresBody("POST / HTTP/1.1\r\ncontent-length: 1\r\n\r\nz"))
	assert.True(t, requestinput.DeclaresBody("POST / HTTP/1.1\nContent-Length: 1\n\nz"),
		"bare-LF requests are accepted by the parser and must be read the same way")
}

// TestScanRequestFileReadIsBounded covers the -i <file> branch, which was a
// bare os.ReadFile beside a bounded stdin read. -i happily accepts a FIFO or
// /dev/stdin, neither of which has the size or the end ReadFile assumes.
func TestScanRequestFileReadIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "req.txt")
	require.NoError(t, os.WriteFile(path, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), 0600))

	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	_, err = clicommon.ReadBounded(f, path, 4, 0)
	require.Error(t, err, "a file past the limit must fail rather than truncate")
	assert.ErrorIs(t, err, clicommon.ErrStdinTooLarge)
}

// TestInputModesMatchRegistry is the drift guard. The CLI's mode table used to
// carry its own copy of the names and had already gone wrong: it advertised
// "nuclei-output" as canonical with "nuclei" as the alias, the reverse of what
// the parser resolves, and it never listed burpscope's burp-project-config.
func TestInputModesMatchRegistry(t *testing.T) {
	formats := source.Formats()
	require.NotEmpty(t, formats)

	seen := make(map[string]bool, len(formats))
	for _, f := range formats {
		seen[f.Name] = true
		doc, ok := inputModeDocs[f.Name]
		if !assert.True(t, ok, "registry format %q has no --list-input-mode entry", f.Name) {
			continue
		}
		assert.NotEmpty(t, doc.Description, "format %q needs a description", f.Name)
		assert.NotEmpty(t, doc.Example, "format %q needs an example", f.Name)
	}
	for name := range inputModeDocs {
		assert.True(t, seen[name],
			"--list-input-mode documents %q, which the parser does not accept as a canonical name", name)
	}
}

// TestInputModeExamplesUseCanonicalNames: an example that passes an alias to -I
// teaches the alias as the name. The nuclei row did exactly that.
func TestInputModeExamplesUseCanonicalNames(t *testing.T) {
	canonical := make(map[string]bool)
	for _, f := range source.Formats() {
		canonical[f.Name] = true
	}
	for name, doc := range inputModeDocs {
		fields := strings.Fields(doc.Example)
		for i, f := range fields {
			if f != "-I" || i+1 >= len(fields) {
				continue
			}
			assert.True(t, canonical[fields[i+1]],
				"%s example passes -I %s, which is an alias, not the canonical name", name, fields[i+1])
		}
	}
}

// TestInputModeFlagUsageListsEveryFormat: the -I help string is built from the
// registry for the same reason as the table. The literal it replaced offered
// aliases beside canonical names and omitted four formats outright.
func TestInputModeFlagUsageListsEveryFormat(t *testing.T) {
	usage := inputModeFlagUsage()
	for _, f := range source.Formats() {
		assert.Contains(t, usage, f.Name, "-I help text must list %q", f.Name)
	}
	assert.Contains(t, usage, "--list-input-mode")
}

// TestFormatsCopiesAliases: Formats hands out the registry's shape, not its
// storage. A caller that sorted the slice it got back must not reorder the
// table every later caller reads.
func TestFormatsCopiesAliases(t *testing.T) {
	first := source.Formats()
	var idx = -1
	for i, f := range first {
		if len(f.Aliases) > 0 {
			idx = i
			break
		}
	}
	require.GreaterOrEqual(t, idx, 0, "expected at least one format with aliases")
	original := first[idx].Aliases[0]
	first[idx].Aliases[0] = "mutated"

	second := source.Formats()
	assert.Equal(t, original, second[idx].Aliases[0], "Formats must not expose the registry's own slices")
}
