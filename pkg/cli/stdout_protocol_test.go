package cli

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// withStdoutProtocolGlobals clears the print-mode globals validateStdoutProtocol
// reads, and restores them afterwards. pflag owns them for the process.
func withStdoutProtocolGlobals(t *testing.T) {
	t.Helper()
	prevFinding, prevTraffic, prevTree := scanPrintFinding, scanPrintTraffic, scanPrintTrafficTree
	prevJSON, prevCI := globalJSON, globalCIOutput
	t.Cleanup(func() {
		scanPrintFinding, scanPrintTraffic, scanPrintTrafficTree = prevFinding, prevTraffic, prevTree
		globalJSON, globalCIOutput = prevJSON, prevCI
	})
	scanPrintFinding, scanPrintTraffic, scanPrintTrafficTree = false, false, false
	globalJSON, globalCIOutput = false, false
}

// --events owns stdout. Every other writer listed here would interleave with it
// into a stream that is not what either contract describes, and nothing used to
// detect the combination: the output was corrupt and the exit code was 0.
func TestValidateStdoutProtocol(t *testing.T) {
	withStdoutProtocolGlobals(t)

	eventsOpts := func() *types.Options {
		o := types.DefaultOptions()
		o.Events = "ndjson"
		return o
	}

	t.Run("no events is always fine", func(t *testing.T) {
		o := types.DefaultOptions()
		o.OutputFormats = []string{"jsonl"}
		scanPrintFinding = true
		t.Cleanup(func() { scanPrintFinding = false })
		assert.NoError(t, validateStdoutProtocol(o),
			"the rule is one-way: these combinations are only a conflict once --events is asked for")
	})

	t.Run("events alone is fine", func(t *testing.T) {
		assert.NoError(t, validateStdoutProtocol(eventsOpts()))
	})

	t.Run("events + stdout jsonl is a usage error", func(t *testing.T) {
		o := eventsOpts()
		o.OutputFormats = []string{"jsonl"}
		err := validateStdoutProtocol(o)
		require.Error(t, err)
		assert.Equal(t, ExitUsageError, classifyExitCode(err))
		assert.Contains(t, err.Error(), "-o", "the message must name the fix")
	})

	t.Run("events + jsonl with -o is fine", func(t *testing.T) {
		o := eventsOpts()
		o.OutputFormats = []string{"jsonl"}
		o.Output = "run.jsonl"
		assert.NoError(t, validateStdoutProtocol(o),
			"jsonl with a destination goes to the file, so there is no collision")
	})

	for name, set := range map[string]func(){
		"--print-finding":      func() { scanPrintFinding = true },
		"--print-traffic":      func() { scanPrintTraffic = true },
		"--print-traffic-tree": func() { scanPrintTrafficTree = true },
	} {
		t.Run("events + "+name+" is a usage error", func(t *testing.T) {
			withStdoutProtocolGlobals(t)
			set()
			err := validateStdoutProtocol(eventsOpts())
			require.Error(t, err)
			assert.Equal(t, ExitUsageError, classifyExitCode(err))
			assert.Contains(t, err.Error(), name)
		})
	}

	t.Run("nil options", func(t *testing.T) {
		assert.NoError(t, validateStdoutProtocol(nil))
	})
}

// -j is the scan document: it reserves stdout and is no longer mapped onto
// --format jsonl. Every other stdout writer next to it is a usage error naming
// the conflict; the jsonl stream with a -o file is not a conflict.
func TestValidateStdoutProtocolScanDocumentOwnsStdout(t *testing.T) {
	withStdoutProtocolGlobals(t)
	globalJSON = true

	o := types.DefaultOptions()
	o.OutputFormats = []string{"console"}
	require.NoError(t, reconcileOutputFormats(o))
	assert.False(t, o.HasFormat("jsonl"), "-j must not turn into --format jsonl")
	assert.False(t, o.DeferredJSONLExport, "no jsonl export unless --format jsonl was given")
	assert.True(t, o.StdoutDocument, "-j reserves stdout for the scan document")
	require.NoError(t, validateStdoutProtocol(o), "-j alone is fine")

	withJSONL := types.DefaultOptions()
	withJSONL.OutputFormats = []string{"jsonl"}
	withJSONL.Output = "run.jsonl"
	require.NoError(t, reconcileOutputFormats(withJSONL))
	assert.True(t, withJSONL.DeferredJSONLExport)
	assert.NoError(t, validateStdoutProtocol(withJSONL), "the stream goes to the file, the document to stdout")

	for name, mk := range map[string]func() *types.Options{
		"--events": func() *types.Options {
			o := types.DefaultOptions()
			o.Events = "ndjson"
			return o
		},
		"--format jsonl": func() *types.Options {
			o := types.DefaultOptions()
			o.OutputFormats = []string{"jsonl"}
			return o
		},
	} {
		t.Run("-j + "+name, func(t *testing.T) {
			err := validateStdoutProtocol(mk())
			require.Error(t, err)
			assert.Equal(t, ExitUsageError, classifyExitCode(err))
			assert.Contains(t, err.Error(), name)
		})
	}
	for name, set := range map[string]func(){
		"--print-finding":      func() { scanPrintFinding = true },
		"--print-traffic":      func() { scanPrintTraffic = true },
		"--print-traffic-tree": func() { scanPrintTrafficTree = true },
	} {
		t.Run("-j + "+name, func(t *testing.T) {
			withStdoutProtocolGlobals(t)
			globalJSON = true
			set()
			err := validateStdoutProtocol(types.DefaultOptions())
			require.Error(t, err)
			assert.Equal(t, ExitUsageError, classifyExitCode(err))
			assert.Contains(t, err.Error(), name)
		})
	}
}

// A per-target fan-out has no single scan document to print: -j there is a
// usage error rather than an empty stdout.
func TestRejectFanOutJSON(t *testing.T) {
	withStdoutProtocolGlobals(t)
	assert.NoError(t, rejectFanOutJSON())
	globalJSON = true
	err := rejectFanOutJSON()
	require.Error(t, err)
	assert.Equal(t, ExitUsageError, classifyExitCode(err))
	assert.Contains(t, err.Error(), "-P/--parallel")
}

// --events must reach the Runner, which is the only thing that emits it.
func TestBuildPhaseOptionsCopiesEvents(t *testing.T) {
	resetLightweightIOGlobals()
	t.Cleanup(resetLightweightIOGlobals)

	scanOpts.Events = "ndjson"
	opts, err := buildPhaseOptions("http://events.example/")
	require.NoError(t, err)
	assert.Equal(t, "ndjson", opts.Events,
		"the flag parsed, validated, and then described nothing because the Runner got an empty Events path")
}

// A Ctrl-C partway through a multi-target run used to leave the caller with
// results for the targets that finished and no statement at all about the rest,
// which reads identically to a run that scanned them and found nothing.
func TestScanInputsStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inputs := []scanInput{
		{target: "http://a.example/", method: "GET"},
		{target: "http://b.example/", method: "GET"},
		{target: "http://c.example/", method: "GET"},
	}

	var calls atomic.Int64
	results, notScanned, err := scanInputs(ctx, inputs, func(_ context.Context, in scanInput) (*scanResult, error) {
		calls.Add(1)
		cancel() // the operator's Ctrl-C lands during the first target
		return &scanResult{Target: in.target}, nil
	})

	assert.NoError(t, err)
	require.EqualValues(t, 1, calls.Load(), "dispatch must stop, not merely mark the rest")
	require.Len(t, results, 1)
	assert.Equal(t, "http://a.example/", results[0].Target)
	assert.Equal(t, []string{"http://b.example/", "http://c.example/"}, notScanned,
		"the targets that were never scanned must be named, not silently absent")
}

// A per-input error does not stop the batch: the remaining targets are
// independent, and the caller asked for all of them.
func TestScanInputsContinuesPastAFailure(t *testing.T) {
	inputs := []scanInput{{target: "a"}, {target: "b"}}
	boom := errors.New("executor failed")

	results, notScanned, err := scanInputs(context.Background(), inputs,
		func(_ context.Context, in scanInput) (*scanResult, error) {
			if in.target == "a" {
				return nil, boom
			}
			return &scanResult{Target: in.target}, nil
		})

	require.ErrorIs(t, err, boom, "the failure must still reach the exit code")
	require.Len(t, results, 1, "the target that did scan must still be reported")
	assert.Equal(t, "b", results[0].Target)
	assert.Empty(t, notScanned)
}

// dispatchScanInputs must notice the interrupt between inputs: both the direct
// and the Runner path go through it, and only the direct path's executor sees
// the context itself.
func TestDispatchScanInputsStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Nothing is dispatched at all, so no network or database is touched: an
	// already-cancelled context means the operator stopped before this started.
	err := dispatchScanInputs(ctx, nil, []scanInput{{rr: &httpmsg.HttpRequestResponse{}, target: "a"}})
	assert.NoError(t, err)
}
