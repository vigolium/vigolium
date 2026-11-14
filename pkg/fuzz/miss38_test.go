package fuzz

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/replay"
)

// TestBuildPlanSniperIsLazyAndBounded: sniper expansion is additive, so it
// must honour MaxCases and must not materialize the plan.
func TestBuildPlanSniperIsLazyAndBounded(t *testing.T) {
	raw := []byte("GET /?a=FUZZ&b=FUZZ2 HTTP/1.1\r\nHost: x\r\n\r\n")
	positions, err := ResolvePositions(raw, Selectors{})
	if err != nil || len(positions) != 2 {
		t.Fatalf("positions: %v %d", err, len(positions))
	}
	plan, err := BuildPlan(ModeSniper, positions, [][]string{{"1", "2", "3"}, {"x"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Len() != 4 {
		t.Fatalf("Len = %d, want 4", plan.Len())
	}
	if _, ok := plan.(CaseSlice); ok {
		t.Fatal("sniper plan must be lazy, got a materialized slice")
	}
	want := []string{"1", "2", "3", "x"}
	for i, w := range want {
		c := plan.At(i)
		if got := c.Assignments[0].Payload; got != w {
			t.Fatalf("At(%d) payload = %s, want %s", i, got, w)
		}
	}
	if plan.At(3).Assignments[0].Position.Name == plan.At(0).Assignments[0].Position.Name {
		t.Fatal("case 3 must belong to the second position")
	}

	huge := make([]string, MaxCases/2+1)
	for i := range huge {
		huge[i] = "p"
	}
	if _, err := BuildPlan(ModeSniper, positions, [][]string{huge, huge}, nil); err == nil {
		t.Fatal("sniper over MaxCases must error")
	}
	if _, err := BuildCases(ModeSniper, positions, [][]string{huge, huge}, nil); err == nil {
		t.Fatal("BuildCases sniper over MaxCases must error")
	}
}

// TestCalibrationPerPositionWithLengthBucket: each position learns its own
// catch-all, and a catch-all that reflects the probe (a few bytes of length
// jitter) still matches.
func TestCalibrationPerPositionWithLengthBucket(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := r.URL.Query().Get("a")
		b := r.URL.Query().Get("b")
		switch {
		case a == "real":
			_, _ = fmt.Fprint(w, strings.Repeat("realcontent ", 40))
		case b != "FUZZ2":
			// b's catch-all: a 404 page that reflects the value.
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, "no such item: %s", b)
		default:
			_, _ = fmt.Fprintf(w, "list page for %s", a)
		}
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	raw := []byte("GET /?a=FUZZ&b=FUZZ2 HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	positions, err := ResolvePositions(raw, Selectors{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(ModeSniper, positions, [][]string{{"real"}, {"item-0000000000000001", "item-000000000000000000002"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	got := map[string]Result{}
	job := Job{
		Raw:    raw,
		Scheme: "http", Hostname: host, Port: port,
		Plan: plan, AutoCalibrate: true,
		Client:      replay.NewDefaultClient(nil, 5*time.Second),
		Concurrency: 2,
		OnResult: func(r Result) {
			mu.Lock()
			got[r.Payload] = r
			mu.Unlock()
		},
	}
	if _, err := Run(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if got["real"].Calibrated {
		t.Fatal("distinct content at position a must not be calibrated away")
	}
	if !got["item-0000000000000001"].Calibrated || !got["item-000000000000000000002"].Calibrated {
		t.Fatalf("position b's reflecting 404 must be calibrated per position: %+v / %+v", got["item-0000000000000001"], got["item-000000000000000000002"])
	}
}

// TestRunAbortsOnFailedBaseline: a dead baseline aborts unless allowed.
func TestRunAbortsOnFailedBaseline(t *testing.T) {
	var hits atomic.Int64
	job := Job{
		Raw:      []byte("GET /?q=FUZZ HTTP/1.1\r\nHost: x\r\n\r\n"),
		Scheme:   "http",
		Hostname: "x",
		Port:     80,
		Payloads: []string{"a", "b"},
		Sender: func(context.Context, []byte) *replay.Summary {
			hits.Add(1)
			return &replay.Summary{Error: "connection refused"}
		},
	}
	positions, _ := ResolvePositions(job.Raw, Selectors{})
	job.Positions = positions
	if _, err := Run(context.Background(), job); err == nil {
		t.Fatal("expected an error when every baseline sample fails")
	}
	if hits.Load() != 1 {
		t.Fatalf("payloads were sent after a failed baseline: %d sends", hits.Load())
	}
	hits.Store(0)
	job.AllowBaselineError = true
	if _, err := Run(context.Background(), job); err != nil {
		t.Fatalf("AllowBaselineError run: %v", err)
	}
	if hits.Load() != 3 {
		t.Fatalf("sends = %d, want 3", hits.Load())
	}
}
