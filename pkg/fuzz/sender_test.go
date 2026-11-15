package fuzz

import (
	"context"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/replay"
)

// TestRunUsesSenderWithoutClient verifies fuzz's Sender seam: with a Sender set,
// Run needs no *http.Client and every send (baseline + each payload) flows
// through it, and OnMatch surfaces the exact request bytes for matched results.
func TestRunUsesSenderWithoutClient(t *testing.T) {
	positions, err := ResolvePositions([]byte("GET /p?id=1 HTTP/1.1\r\nHost: acme.test\r\n\r\n"), Selectors{Mode: "params"})
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var matched [][]byte
	job := Job{
		Raw:       []byte("GET /p?id=1 HTTP/1.1\r\nHost: acme.test\r\n\r\n"),
		Scheme:    "https",
		Hostname:  "acme.test",
		Positions: positions,
		Payloads:  []string{"boom"},
		Matchers:  Matchers{AllStatus: true},
		Sender: func(_ context.Context, _ []byte) *replay.Summary {
			return &replay.Summary{Status: 200, ResponseLen: 4, RawBody: []byte("boom")}
		},
		OnMatch: func(_ Result, rawRequest []byte) {
			mu.Lock()
			matched = append(matched, append([]byte(nil), rawRequest...))
			mu.Unlock()
		},
	}
	report, err := Run(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if report.Sent != 1 || report.Matched != 1 {
		t.Fatalf("report = %+v", report)
	}
	if len(matched) != 1 {
		t.Fatalf("OnMatch should have fired once, got %d", len(matched))
	}
}

func TestRunRequiresClientOrSender(t *testing.T) {
	positions, _ := ResolvePositions([]byte("GET /p?id=1 HTTP/1.1\r\nHost: acme.test\r\n\r\n"), Selectors{Mode: "params"})
	_, err := Run(context.Background(), Job{
		Raw:       []byte("GET /p?id=1 HTTP/1.1\r\nHost: acme.test\r\n\r\n"),
		Hostname:  "acme.test",
		Positions: positions,
		Payloads:  []string{"x"},
	})
	if err == nil {
		t.Fatal("expected an error when neither Client nor Sender is set")
	}
}

// Sent counts payload sends; SentTotal counts every request on the wire,
// baseline samples and calibration probes included.
func TestRunSentTotalCountsEverySend(t *testing.T) {
	raw := []byte("GET /p?id=1 HTTP/1.1\r\nHost: acme.test\r\n\r\n")
	positions, err := ResolvePositions(raw, Selectors{Mode: "params"})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	sends := 0
	report, err := Run(context.Background(), Job{
		Raw: raw, Scheme: "https", Hostname: "acme.test", Positions: positions,
		Payloads:        []string{"a", "b", "c"},
		BaselineSamples: 2,
		AutoCalibrate:   true,
		Sender: func(_ context.Context, _ []byte) *replay.Summary {
			mu.Lock()
			sends++
			mu.Unlock()
			return &replay.Summary{Status: 200, ResponseLen: 4, RawBody: []byte("page")}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Sent != 3 {
		t.Fatalf("Sent = %d, want the 3 payload sends", report.Sent)
	}
	want := 3 + 2 + len(calibrationProbes)
	if report.SentTotal != want || sends != want {
		t.Fatalf("SentTotal = %d (sender saw %d), want %d", report.SentTotal, sends, want)
	}
}
