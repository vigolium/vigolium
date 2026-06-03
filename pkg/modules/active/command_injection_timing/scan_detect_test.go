package command_injection_timing

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// baseDelay is the short latency for non-sleeping requests: comfortably under the
// derived threshold (~3.5s, dominated by minSleepMargin).
const baseDelay = 500 * time.Millisecond

// fixedStall is the non-scaling delay used by the scaling-rejection test: above
// the derived threshold (so the high-sleep probe clears it) but as small as
// practical to keep the multi-second test cheap.
const fixedStall = 4 * time.Second

// sleepArgRe extracts the requested seconds from an injected sleep/ping payload.
var sleepArgRe = regexp.MustCompile(`sleep (\d+)|ping -n (\d+)`)

func requestedSleep(r *http.Request) int {
	mm := sleepArgRe.FindStringSubmatch(r.URL.Query().Get("cmd"))
	if mm == nil {
		return 0
	}
	for _, g := range mm[1:] {
		if g != "" {
			n, _ := strconv.Atoi(g)
			return n
		}
	}
	return 0
}

// flushAndSleep writes a 200, flushes headers (so the body delay stays clear of
// the requester's response-header timeout), sleeps d, then writes the body.
func flushAndSleep(w http.ResponseWriter, d time.Duration) {
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	time.Sleep(d)
	_, _ = w.Write([]byte("ok"))
}

// scalingHandler emulates a genuine time-based command-injection sink: the delay
// equals the requested sleep duration and is near-instant otherwise.
func scalingHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if n := requestedSleep(r); n > 0 {
			flushAndSleep(w, time.Duration(n)*time.Second)
			return
		}
		flushAndSleep(w, baseDelay)
	}
}

// TestScanPerRequest_DetectsTimingCmdi drives the scan against a sink whose delay
// scales with the injected sleep value; the multi-round scaling confirmation must
// report a finding.
func TestScanPerRequest_DetectsTimingCmdi(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-second timing test in -short mode")
	}
	srv := httptest.NewServer(scalingHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?cmd=host")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a time-based command injection finding when the delay scales")
	assert.Equal(t, "cmd", res[0].FuzzingParameter)
}

// TestScanPerRequest_NoFalsePositive_Fast: a uniformly fast server never yields a
// finding. Runs in -short (no multi-second sleeps occur because the server never
// stalls, so the high-sleep probe falls under threshold immediately).
func TestScanPerRequest_NoFalsePositive_Fast(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?cmd=host")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that never stalls must not yield a timing finding")
}

// TestConfirmTiming_RejectsFixedDelay is the key scaling test: a sink that stalls
// a FIXED amount on any sleep payload (not proportional to the requested
// duration) must be rejected — the high−low differential does not track the
// requested factor. It drives confirmTiming directly with a single template and
// an explicit threshold so it exercises the scaling-rejection logic in one
// multi-second probe rather than the full per-template matrix.
func TestConfirmTiming_RejectsFixedDelay(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-second timing test in -short mode")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestedSleep(r) > 0 {
			flushAndSleep(w, fixedStall) // fixed, non-scaling
			return
		}
		flushAndSleep(w, baseDelay)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?cmd=host")
	ip := modtest.InsertionPoint(t, rr, "cmd")
	tmpl := infra.CmdiSleepTemplates()[0] // ";sleep %d"

	res, err := New().confirmTiming(rr, client, ip, tmpl, ip.BaseValue(), 3*time.Second)
	require.NoError(t, err)
	assert.Nil(t, res, "a fixed (non-scaling) delay must not be reported as command injection")
}

