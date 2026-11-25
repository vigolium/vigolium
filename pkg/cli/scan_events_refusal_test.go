package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/contract/contracttest"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

// captureRefusalStdout runs fn with os.Stdout on a pipe and returns what it
// wrote.
func captureRefusalStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	prev := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() { os.Stdout = prev }()
	fn()
	_ = w.Close()
	os.Stdout = prev
	return <-done
}

// isolateRefusalState clears the process stream and the scan globals the
// refusal reads, and restores them afterwards.
func isolateRefusalState(t *testing.T) {
	t.Helper()
	prevEmitter := scanevents.Default()
	prevEvents, prevUUID, prevGlobalUUID, prevJSON := scanOpts.Events, scanOpts.ScanUUID, globalScanUUID, globalJSON
	scanevents.Install(nil)
	scanOpts.Events, scanOpts.ScanUUID, globalScanUUID, globalJSON = "", "", "", false
	t.Cleanup(func() {
		scanevents.Install(prevEmitter)
		scanOpts.Events, scanOpts.ScanUUID, globalScanUUID, globalJSON = prevEvents, prevUUID, prevGlobalUUID, prevJSON
	})
}

// singleTerminal decodes stdout as exactly one scan.finished line.
func singleTerminal(t *testing.T, out string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 1, "exactly one line on stdout, got:\n%s", out)
	var ev map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &ev), lines[0])
	require.Equal(t, scanevents.TypeScanFinished, ev["type"])
	contracttest.ValidateEvent(t, []byte(lines[0]))
	return ev
}

// An unknown flag stops cobra before it binds --events, so the stream is
// recovered from argv, and the refusal is the one terminal line: failed, exit
// 2, usage_error, the pinned scan uuid, zero records.
func TestRefusalBeforeStreamWritesOneTerminal(t *testing.T) {
	isolateRefusalState(t)
	argv := []string{"--bogus-flag", "--events", "ndjson", "--scan-uuid", "11111111-2222-3333-4444-555555555555"}
	raw := scanCmd.ParseFlags(argv)
	require.Error(t, raw)
	err := flagErrorFunc(scanCmd, raw)
	code := classifyExitCode(err)
	require.Equal(t, ExitUsageError, code)

	out := captureRefusalStdout(t, func() {
		emitRefusalTerminalEvent(scanCmd, err, code, append([]string{"scan"}, argv...))
	})
	ev := singleTerminal(t, out)
	assert.Equal(t, scanevents.StatusFailed, ev["status"])
	assert.EqualValues(t, ExitUsageError, ev["exit_code"])
	assert.Equal(t, string(apicontract.CodeUsageError), ev["error_code"])
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", ev["scan_uuid"])
	assert.EqualValues(t, 0, ev["records_written"])
	assert.Contains(t, ev["message"], "bogus-flag")

	// Contract: every key on the line is in the published scan.finished schema.
	s, serr := contract.EventSchema(scanevents.TypeScanFinished)
	require.NoError(t, serr)
	schema, _ := json.Marshal(s)
	for key := range ev {
		assert.Contains(t, string(schema), `"`+key+`"`, "scan.finished schema carries %s", key)
	}
}

// A refusal after the flags bound (a config the run refuses) carries that
// refusal's own code and the bound scan uuid.
func TestRefusalCarriesItsErrorCode(t *testing.T) {
	isolateRefusalState(t)
	scanOpts.Events = "ndjson"
	globalScanUUID = "pinned-scan"
	err := codedErrorf(apicontract.CodeConfigInvalid, "dynamic-assessment.max_module_tier: bogus")
	code := classifyExitCode(err)

	out := captureRefusalStdout(t, func() { emitRefusalTerminalEvent(scanCmd, err, code, nil) })
	ev := singleTerminal(t, out)
	assert.Equal(t, string(apicontract.CodeConfigInvalid), ev["error_code"])
	assert.EqualValues(t, code, ev["exit_code"])
	assert.Equal(t, "pinned-scan", ev["scan_uuid"])
}

// No second terminal event: a stream that already wrote one is left alone.
func TestRefusalSkipsAStreamAlreadyTerminated(t *testing.T) {
	isolateRefusalState(t)
	scanOpts.Events = "ndjson"
	var buf bytes.Buffer
	em := scanevents.New(&buf, "u")
	scanevents.Install(em)
	em.Finish(scanevents.Event{Status: scanevents.StatusFailed})
	require.True(t, em.Terminated())

	out := captureRefusalStdout(t, func() {
		emitRefusalTerminalEvent(scanCmd, errors.New("boom"), ExitError, nil)
	})
	assert.Empty(t, out)
	assert.Equal(t, 1, strings.Count(buf.String(), scanevents.TypeScanFinished))
}

// No stream asked for, -j owning stdout, or a command whose --events is not
// the scan stream (scan wait): nothing is written.
func TestRefusalWritesNothingWithoutAScanStream(t *testing.T) {
	isolateRefusalState(t)
	err := usageErrorf("nope")
	check := func(name string, fn func()) {
		t.Helper()
		assert.Empty(t, captureRefusalStdout(t, fn), name)
	}
	check("no --events", func() { emitRefusalTerminalEvent(scanCmd, err, ExitUsageError, []string{"scan"}) })
	check("invalid --events", func() {
		emitRefusalTerminalEvent(scanCmd, err, ExitUsageError, []string{"scan", "--events", "xml"})
	})

	globalJSON = true
	check("-j owns stdout", func() {
		emitRefusalTerminalEvent(scanCmd, err, ExitUsageError, []string{"scan", "--events", "ndjson", "-j"})
	})
	globalJSON = false

	wait, _, ferr := rootCmd.Find([]string{"scan", "wait"})
	require.NoError(t, ferr)
	check("scan wait", func() {
		emitRefusalTerminalEvent(wait, err, ExitUsageError, []string{"scan", "wait", "--events", "ndjson"})
	})
	check("nil error", func() {
		emitRefusalTerminalEvent(scanCmd, nil, ExitSuccess, []string{"scan", "--events", "ndjson"})
	})
}

// End to end through Execute: a scan refused before its stream began prints
// exactly one scan.finished on stdout, whose exit_code is the process's.
func TestRefusedScanStreamsOneTerminalEndToEnd(t *testing.T) {
	for name, tc := range map[string]struct {
		args      []string
		errorCode string
	}{
		"unknown flag":   {[]string{"scan", "--bogus-flag", "--events", "ndjson", "--scan-uuid", "e2e-scan"}, "usage_error"},
		"bare scan":      {[]string{"scan", "--events", "ndjson", "--scan-uuid", "e2e-scan"}, "usage_error"},
		"refused --only": {[]string{"scan", "--events", "ndjson", "--scan-uuid", "e2e-scan", "--only", "no-such-phase", "https://127.0.0.1:1"}, "usage_error"},
		// A refusal raised by the run itself, after the flags bound.
		"run, refused intensity": {[]string{"run", "dynamic-assessment", "--events", "ndjson", "--scan-uuid", "e2e-scan", "--intensity", "bogus"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runA2Scan(t, tc.args...)
			require.NotEqual(t, 0, code, "stderr:\n%s", stderr)
			ev := singleTerminal(t, stdout)
			assert.Equal(t, scanevents.StatusFailed, ev["status"])
			assert.EqualValues(t, code, ev["exit_code"], "the line names the exit the process took")
			assert.NotEmpty(t, ev["error_code"])
			if tc.errorCode != "" {
				assert.Equal(t, tc.errorCode, ev["error_code"])
			}
			assert.Equal(t, "e2e-scan", ev["scan_uuid"])
		})
	}
}
