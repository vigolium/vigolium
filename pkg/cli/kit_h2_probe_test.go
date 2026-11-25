package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func h2ProbeFlagsReset(t *testing.T) {
	t.Helper()
	saved := struct {
		target, method, data string
		headers              []string
		cl                   int64
		open, verify, h2c    bool
		chunk                int
		timeout              time.Duration
		json                 bool
	}{kitH2ProbeTarget, kitH2ProbeMethod, kitH2ProbeData, kitH2ProbeHeaders, kitH2ProbeContentLength,
		kitH2ProbeOpenStream, kitH2ProbeVerifyTLS, kitH2ProbeCleartext, kitH2ProbeChunkSize, kitH2ProbeTimeout, globalJSON}
	t.Cleanup(func() {
		kitH2ProbeTarget, kitH2ProbeMethod, kitH2ProbeData, kitH2ProbeHeaders = saved.target, saved.method, saved.data, saved.headers
		kitH2ProbeContentLength, kitH2ProbeOpenStream, kitH2ProbeVerifyTLS = saved.cl, saved.open, saved.verify
		kitH2ProbeCleartext, kitH2ProbeChunkSize, kitH2ProbeTimeout, globalJSON = saved.h2c, saved.chunk, saved.timeout, saved.json
		jsonResultEmitted = false
	})
}

// A declared content-length the body falls short of: with the stream ended
// the server answers at once; with it left open the probe reports timed_out.
func TestKitH2Probe_TimingOracle(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	run := func(open bool) kitH2ProbeItem {
		h2ProbeFlagsReset(t)
		kitH2ProbeTarget, kitH2ProbeMethod, kitH2ProbeData = srv.URL+"/submit", "POST", "abc"
		kitH2ProbeHeaders, kitH2ProbeContentLength, kitH2ProbeOpenStream = nil, 30, open
		kitH2ProbeVerifyTLS, kitH2ProbeCleartext, kitH2ProbeChunkSize = false, false, 0
		kitH2ProbeTimeout, globalJSON = 1200*time.Millisecond, true
		kitH2ProbeIgnoreScope = true
		var runErr error
		out := captureStdout(t, func() { runErr = runKitH2Probe(kitH2ProbeCmd, nil) })
		if runErr != nil {
			t.Fatalf("runKitH2Probe: %v", runErr)
		}
		var doc struct {
			Items []kitH2ProbeItem `json:"items"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Items) != 1 {
			t.Fatalf("output: %v\n%s", err, out)
		}
		return doc.Items[0]
	}

	ended := run(false)
	if !ended.Answered || ended.TimedOut || ended.ALPN != "h2" || ended.BodyBytes != 3 || ended.DeclaredContentLength == nil || *ended.DeclaredContentLength != 30 {
		t.Fatalf("ended stream = %+v", ended)
	}
	open := run(true)
	if open.Answered || !open.TimedOut || !open.OpenStream || open.ElapsedMS < 1200 {
		t.Fatalf("open stream = %+v; want timed_out after the 1.2s wait", open)
	}
}

func TestKitH2Probe_UsageErrors(t *testing.T) {
	h2ProbeFlagsReset(t)
	kitH2ProbeCleartext = false
	for _, target := range []string{"", "ftp://x/", "http://plain.test/"} {
		kitH2ProbeTarget = target
		if err := runKitH2Probe(kitH2ProbeCmd, nil); err == nil {
			t.Errorf("target %q accepted", target)
		}
	}
}
