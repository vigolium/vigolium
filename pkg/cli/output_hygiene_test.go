package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// ---------------------------------------------------------------------------
// In-process units.

func TestJSONCompactByDefault(t *testing.T) {
	prev := globalPretty
	t.Cleanup(func() { globalPretty = prev })
	globalPretty = false

	doc, err := encodeAgentJSON(newAgentEnvelope("finding", "", []int{1, 2}, 2, 0, 2))
	require.NoError(t, err)
	assert.Equal(t, 1, bytes.Count(doc, []byte("\n")), "a compact document is one line plus its newline:\n%s", doc)
	assert.True(t, json.Valid(doc))
}

func TestPrettyFlagIndents(t *testing.T) {
	prevPretty, prevStream := globalPretty, jsonStreamMode
	t.Cleanup(func() { globalPretty, jsonStreamMode = prevPretty, prevStream })
	globalPretty = true

	doc, err := encodeAgentJSON(newAgentEnvelope("finding", "", []int{1}, 1, 0, 1))
	require.NoError(t, err)
	assert.Contains(t, string(doc), "\n  \"schema_version\"", "--pretty indents the document")

	// --watch frames NDJSON; a pretty document would split across lines.
	jsonStreamMode = true
	doc, err = encodeAgentJSON(newAgentEnvelope("finding", "", []int{1}, 1, 0, 1))
	require.NoError(t, err)
	assert.Equal(t, 1, bytes.Count(doc, []byte("\n")), "--watch stays one document per line under --pretty")
}

func TestFilterSummaryGoesToStderr(t *testing.T) {
	prevColor, prevTTY := terminal.IsColorEnabled(), terminal.IsTerminal()
	t.Cleanup(func() { terminal.SetColorEnabled(prevColor); terminal.SetIsTerminal(prevTTY) })
	terminal.SetColorEnabled(false)

	var s filterSummary
	s.add("host", "acme.test")

	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() { s.print(false) })
	})
	assert.Empty(t, stdout, "the summary describes the result; it is not part of it")
	assert.Contains(t, stderr, "Filtered by:")
	assert.Contains(t, stderr, "host=acme.test")

	// A document (--markdown/--raw/--burp) redirected away from a terminal
	// gets no echo at all, so 2>&1 cannot glue it onto the document.
	terminal.SetIsTerminal(false)
	stderr = captureStderr(t, func() {
		stdout = captureStdout(t, func() { s.print(true) })
	})
	assert.Empty(t, stdout)
	assert.Empty(t, stderr)

	terminal.SetIsTerminal(true)
	stderr = captureStderr(t, func() { s.print(true) })
	assert.Contains(t, stderr, "Filtered by:", "on a terminal the document view still echoes, on stderr")
}

// colorTestCmd is a command carrying the two color flags bound to the globals,
// parsed from argv, so Changed() means what it does on the real tree.
func colorTestCmd(t *testing.T, argv ...string) *cobra.Command {
	t.Helper()
	prevColor, prevNo := globalColor, globalNoColor
	t.Cleanup(func() { globalColor, globalNoColor = prevColor, prevNo })
	c := &cobra.Command{Use: "x"}
	c.Flags().StringVar(&globalColor, "color", "auto", "")
	c.Flags().BoolVar(&globalNoColor, "no-color", false, "")
	require.NoError(t, c.ParseFlags(argv))
	return c
}

func TestResolveColorMode(t *testing.T) {
	cases := []struct {
		argv []string
		want terminal.ColorMode
		err  bool
	}{
		{nil, terminal.ColorAuto, false},
		{[]string{"--color=always"}, terminal.ColorAlways, false},
		{[]string{"--color", "never"}, terminal.ColorNever, false},
		{[]string{"--no-color"}, terminal.ColorNever, false},
		{[]string{"--no-color", "--color=never"}, terminal.ColorNever, false},
		{[]string{"--no-color", "--color=always"}, "", true},
		{[]string{"--color=sometimes"}, "", true},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.argv, " "), func(t *testing.T) {
			got, err := resolveColorMode(colorTestCmd(t, tc.argv...))
			if tc.err {
				require.Error(t, err)
				assert.Equal(t, 2, classifyExitCode(err), "a bad --color is a usage error")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// The -P parent asks its children for color so their console.log keeps it,
// unless the operator opted out — then it adds nothing and the opt-out (typed
// flag forwarded by childScanArgs, or NO_COLOR inherited) reaches the child.
func TestChildColorArgs(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	prevCI := globalCIOutput
	t.Cleanup(func() { globalCIOutput = prevCI })
	globalCIOutput = false

	assert.Equal(t, []string{"--color=always"}, childColorArgs(colorTestCmd(t)))
	assert.Nil(t, childColorArgs(colorTestCmd(t, "--no-color")))
	assert.Nil(t, childColorArgs(colorTestCmd(t, "--color=never")))
	assert.Nil(t, childColorArgs(colorTestCmd(t, "--color=always")), "a typed --color is already forwarded")

	t.Setenv("NO_COLOR", "1")
	assert.Nil(t, childColorArgs(colorTestCmd(t)))
}

func TestBannerWanted(t *testing.T) {
	prevTTY, prevEvents := terminal.StderrIsTerminal(), scanOpts.Events
	t.Cleanup(func() { terminal.SetStderrIsTerminal(prevTTY); scanOpts.Events = prevEvents })

	scanOpts.Events = ""
	terminal.SetStderrIsTerminal(false)
	assert.False(t, bannerWanted(), "no banner when stderr is captured")
	terminal.SetStderrIsTerminal(true)
	assert.True(t, bannerWanted())
	scanOpts.Events = "ndjson"
	assert.False(t, bannerWanted(), "no banner beside an event stream")
}

func TestResolveStreamOutputPlan(t *testing.T) {
	prevJSON, prevFormat := globalJSON, globalFormat
	t.Cleanup(func() { globalJSON, globalFormat = prevJSON, prevFormat })

	cmdWith := func(format string) *cobra.Command {
		c := &cobra.Command{Use: "replay"}
		c.Flags().StringVar(&globalFormat, "format", "console", "")
		if format != "" {
			require.NoError(t, c.ParseFlags([]string{"--format", format}))
		} else {
			require.NoError(t, c.ParseFlags(nil))
		}
		return c
	}
	cases := []struct {
		name         string
		json         bool
		format, out  string
		humanDefault bool
		want         streamOutputPlan
		usage        bool
	}{
		{"default human", false, "", "", true, streamOutputPlan{human: true}, false},
		{"-j", true, "", "", true, streamOutputPlan{envelope: true}, false},
		{"--format jsonl", false, "jsonl", "", true, streamOutputPlan{stream: true}, false},
		{"-o file", false, "", "r.jsonl", true, streamOutputPlan{human: true, stream: true, streamPath: "r.jsonl"}, false},
		{"-j -o file", true, "", "r.jsonl", true, streamOutputPlan{envelope: true, stream: true, streamPath: "r.jsonl"}, false},
		{"-j --format jsonl -o", true, "jsonl", "r.jsonl", true, streamOutputPlan{envelope: true, stream: true, streamPath: "r.jsonl"}, false},
		{"-j --format jsonl", true, "jsonl", "", true, streamOutputPlan{}, true},
		{"--format html", false, "html", "", true, streamOutputPlan{}, true},
		{"--format console", false, "console", "", true, streamOutputPlan{human: true}, false},
		{"bulk legacy default", false, "", "", false, streamOutputPlan{stream: true, legacyBulkDefault: true}, false},
		{"bulk legacy -o", false, "", "r.jsonl", false, streamOutputPlan{human: true, stream: true, streamPath: "r.jsonl"}, false},
		{"bulk -j", true, "", "", false, streamOutputPlan{envelope: true}, false},
		{"bulk --format jsonl", false, "jsonl", "", false, streamOutputPlan{stream: true}, false},
		{"bulk --format console", false, "console", "", false, streamOutputPlan{human: true}, false},
		{"--format console,jsonl", false, "console,jsonl", "", true, streamOutputPlan{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			globalJSON = tc.json
			got, err := resolveStreamOutputPlan(cmdWith(tc.format), tc.out, tc.humanDefault)
			if tc.usage {
				require.Error(t, err)
				assert.Equal(t, 2, classifyExitCode(err))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Subprocess runs of the real Execute(): the color, banner and stdout contracts
// are about what reaches a pipe, so they are asserted on real pipes.

const b3ChildEnv = "VIGOLIUM_B3_ARGS"

func TestOutputHygieneChild(t *testing.T) {
	raw := os.Getenv(b3ChildEnv)
	if raw == "" {
		t.Skip("child process helper")
	}
	os.Args = append([]string{"vigolium"}, strings.Split(raw, "\x1f")...)
	Execute()
	os.Exit(0)
}

// runB3 re-execs the test binary as `vigolium <args...>` with stdout and stderr
// on pipes (so neither is a TTY), a throwaway HOME whose first-run marker is
// present, and no inherited color or proxy variables unless extraEnv sets them.
func runB3(t *testing.T, extraEnv []string, args ...string) (exitCode int, stdout, stderr string) {
	t.Helper()
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".vigolium"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".vigolium", initMarkerFileName), []byte("ok"), 0o600))

	cmd := exec.Command(os.Args[0], "-test.run=^TestOutputHygieneChild$", "-test.v=false")
	env := []string{b3ChildEnv + "=" + strings.Join(args, "\x1f"), "HOME=" + home,
		"VIGOLIUM_DISABLE_UPDATE_CHECK=1"}
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case name == "HOME", strings.HasPrefix(name, "VIGOLIUM_"),
			name == "NO_COLOR", name == "FORCE_COLOR", name == "CLICOLOR_FORCE",
			strings.EqualFold(name, "http_proxy"), strings.EqualFold(name, "https_proxy"),
			strings.EqualFold(name, "all_proxy"):
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = append(env, extraEnv...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String(), errb.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), out.String(), errb.String()
	default:
		t.Fatalf("run child: %v", err)
		return -1, "", ""
	}
}

// The repro: `vigolium db stats 2>&1 >/dev/null | cat -v` printed ^[[ escapes,
// because color was forced on for every command. With both streams on pipes
// nothing may carry an escape code; --color=always proves the check can see one.
func TestPipedOutputCarriesNoANSI(t *testing.T) {
	db := seedCompactDB(t)

	code, stdout, stderr := runB3(t, nil, "--db", db, "db", "stats")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.NotContains(t, stderr, "\x1b[", "stderr on a pipe must carry no ANSI")
	assert.NotContains(t, stdout, "\x1b[", "stdout on a pipe must carry no ANSI")
	assert.NotContains(t, stderr, "Crafted with", "no banner when stderr is not a terminal")

	code, stdout, _ = runB3(t, nil, "--db", db, "--color=always", "db", "stats")
	require.Equal(t, 0, code)
	assert.Contains(t, stdout, "\x1b[", "--color=always colors even a pipe (the -P console.log case)")

	_, stdout, _ = runB3(t, []string{"FORCE_COLOR=1"}, "--db", db, "db", "stats")
	assert.Contains(t, stdout, "\x1b[", "FORCE_COLOR forces color under auto")

	_, stdout, _ = runB3(t, []string{"FORCE_COLOR=1"}, "--db", db, "--color=never", "db", "stats")
	assert.NotContains(t, stdout, "\x1b[", "an explicit --color=never beats FORCE_COLOR")
}

func TestTrafficTreeJSONRejected(t *testing.T) {
	db := seedCompactDB(t)
	for _, argv := range [][]string{
		{"traffic", "--tree", "-j"},
		{"traffic", "tree", "-j"},
		{"traffic", "--markdown", "-j"},
		{"traffic", "--raw", "-j"},
		{"traffic", "--burp", "-j"},
	} {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			code, stdout, stderr := runB3(t, nil, append([]string{"--db", db}, argv...)...)
			assert.Equal(t, 2, code, "stderr:\n%s", stderr)
			doc := oneJSONDocument(t, stdout)
			assert.Equal(t, false, doc["ok"])
			errObj, _ := doc["error"].(map[string]any)
			assert.Equal(t, "usage_error", errObj["code"])
			assert.Contains(t, errObj["message"], "--group-by host")
		})
	}
}

// replay prints the human summary by default and one envelope under -j; the
// stream is --format jsonl. fuzz likewise: table, envelope, stream.
func TestReplayAndFuzzPolarity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello %s", r.URL.Query().Get("id"))
	}))
	t.Cleanup(srv.Close)
	db := filepath.Join(t.TempDir(), "b3.sqlite")
	replayArgs := func(extra ...string) []string {
		return append([]string{"--db", db, "replay", "-i", srv.URL + "/x"}, extra...)
	}

	t.Run("replay default is human", func(t *testing.T) {
		code, stdout, stderr := runB3(t, nil, replayArgs()...)
		require.Equal(t, 0, code, "stderr:\n%s", stderr)
		assert.Contains(t, stdout, "Baseline")
		assert.False(t, json.Valid([]byte(strings.TrimSpace(stdout))), "default output is not JSON:\n%s", stdout)
	})
	t.Run("replay -j is one envelope", func(t *testing.T) {
		code, stdout, stderr := runB3(t, nil, replayArgs("-j")...)
		require.Equal(t, 0, code, "stderr:\n%s", stderr)
		doc := oneJSONDocument(t, stdout)
		assert.Equal(t, "replay", doc["command"])
		assert.Equal(t, true, doc["ok"])
		items, _ := doc["items"].([]any)
		require.Len(t, items, 1)
		assert.Contains(t, items[0], "result")
		assert.Equal(t, 1, strings.Count(stdout, "\n"), "-j is compact by default")
	})
	t.Run("replay --format jsonl is the stream", func(t *testing.T) {
		code, stdout, stderr := runB3(t, nil, replayArgs("--format", "jsonl")...)
		require.Equal(t, 0, code, "stderr:\n%s", stderr)
		doc := oneJSONDocument(t, stdout)
		assert.NotContains(t, doc, "schema_version", "a stream line is the bare replayOutput")
		assert.Contains(t, doc, "result")
	})
	t.Run("replay -j --format jsonl needs -o", func(t *testing.T) {
		code, stdout, _ := runB3(t, nil, replayArgs("-j", "--format", "jsonl")...)
		assert.Equal(t, 2, code)
		assert.Equal(t, false, oneJSONDocument(t, stdout)["ok"])
	})
	t.Run("replay --pretty warns and stays human", func(t *testing.T) {
		code, stdout, stderr := runB3(t, nil, replayArgs("--pretty")...)
		require.Equal(t, 0, code, "stderr:\n%s", stderr)
		assert.Contains(t, stdout, "Baseline")
		assert.Contains(t, stderr, "--pretty is deprecated")
	})
	t.Run("replay -j --pretty indents", func(t *testing.T) {
		code, stdout, stderr := runB3(t, nil, replayArgs("-j", "--pretty")...)
		require.Equal(t, 0, code, "stderr:\n%s", stderr)
		assert.Greater(t, strings.Count(stdout, "\n"), 1)
		assert.NotContains(t, stderr, "deprecated", "--pretty with -j is the global flag's own meaning")
		oneJSONDocument(t, stdout)
	})

	fuzzArgs := func(extra ...string) []string {
		return append([]string{"--db", db, "fuzz", srv.URL + "/?id=FUZZ", "-p", "aaa", "-p", "bbb",
			"--ignore-scope", "--no-calibrate", "--match-status-code", "all"}, extra...)
	}
	t.Run("fuzz default is a table", func(t *testing.T) {
		code, stdout, stderr := runB3(t, nil, fuzzArgs()...)
		require.Equal(t, 0, code, "stderr:\n%s", stderr)
		assert.Contains(t, stdout, `"aaa"`)
		assert.Contains(t, stdout, "status=200")
		assert.False(t, strings.HasPrefix(strings.TrimSpace(stdout), "{"), "default output is not JSONL:\n%s", stdout)
	})
	t.Run("fuzz -j is one envelope", func(t *testing.T) {
		code, stdout, stderr := runB3(t, nil, fuzzArgs("-j")...)
		require.Equal(t, 0, code, "stderr:\n%s", stderr)
		doc := oneJSONDocument(t, stdout)
		assert.Equal(t, "fuzz", doc["command"])
		assert.EqualValues(t, 2, doc["sent"])
		assert.EqualValues(t, 2, doc["matched"])
		assert.Len(t, doc["items"], 2, "top results are the rows")
		// The confirmation scan sends traffic, so it is a next step, never the
		// read-only query hint.
		assert.NotContains(t, doc, "query_argv")
		assert.Equal(t, true, doc["sends_traffic"])
		next, _ := doc["next"].([]any)
		require.Len(t, next, 1)
		step := next[0].(map[string]any)
		assert.Equal(t, true, step["sends_traffic"])
		assert.Contains(t, step["argv"], "scan-url", "a URL source is confirmed with scan-url, not scan-request -i")
		assert.NotContains(t, fmt.Sprint(step["argv"]), "FUZZ")
		assert.NotContains(t, stderr, `"payload"`, "the per-payload stream no longer spills onto stderr")
	})
	t.Run("fuzz --format jsonl is the stream", func(t *testing.T) {
		code, stdout, stderr := runB3(t, nil, fuzzArgs("--format", "jsonl")...)
		require.Equal(t, 0, code, "stderr:\n%s", stderr)
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		require.Len(t, lines, 2, "one line per send:\n%s", stdout)
		for _, l := range lines {
			var v map[string]any
			require.NoError(t, json.Unmarshal([]byte(l), &v))
			assert.Contains(t, v, "payload")
		}
	})
	t.Run("fuzz -o writes the stream and keeps the table", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "fuzz.jsonl")
		code, stdout, stderr := runB3(t, nil, fuzzArgs("-o", out)...)
		require.Equal(t, 0, code, "stderr:\n%s", stderr)
		assert.Contains(t, stdout, "status=200")
		data, err := os.ReadFile(out)
		require.NoError(t, err)
		assert.Equal(t, 2, strings.Count(string(data), "\n"))
	})
}

// oneJSONDocument asserts stdout holds exactly one JSON document and decodes it.
func oneJSONDocument(t *testing.T, stdout string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(stdout))
	var doc map[string]any
	require.NoError(t, dec.Decode(&doc), "stdout is not JSON:\n%s", stdout)
	var extra json.RawMessage
	assert.Error(t, dec.Decode(&extra), "stdout carries more than one document:\n%s", stdout)
	return doc
}
