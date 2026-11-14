package parammine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The scan leaves a confirmation reserve, so a candidate isolated
// before the budget runs out is still confirmed instead of discarded.
func TestMine_BudgetReserveConfirmsCandidate(t *testing.T) {
	srv, _ := hiddenApp(t)
	words := append([]string{"callback", "debug"}, fillerNames(62)...)
	res, err := Mine(context.Background(), baseRequest(t, "GET", srv.URL+"/search", "", nil), words, httpSender(t), Config{MaxRequests: 8})
	if err != nil {
		t.Fatal(err)
	}
	if res.Requests > 8 {
		t.Fatalf("requests = %d, budget 8", res.Requests)
	}
	if got := hitNames(res); len(got) != 1 || got["callback"] == "" {
		t.Fatalf("hits = %v, want [callback] confirmed from the reserve (unconfirmed %d, aborted %q)", got, len(res.Unconfirmed), res.Aborted)
	}
	if res.Aborted != AbortBudget {
		t.Errorf("aborted = %q, want %q (debug's bisection was cut)", res.Aborted, AbortBudget)
	}
}

// A block burst during confirmation reports the isolated names as
// unconfirmed leads rather than dropping them.
func TestMine_BlockedCandidateReportedUnconfirmed(t *testing.T) {
	var n atomic.Int64
	page := "<html><body>" + strings.Repeat("<li>row</li>", 40) + "</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) > 3 { // baselines + first chunk answer, then the WAF arms
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, "slow down")
			return
		}
		body := page
		if cb := r.URL.Query().Get("callback"); cb != "" {
			body = cb + "(" + page + ")"
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	words := append([]string{"callback"}, fillerNames(20)...)
	res, err := Mine(context.Background(), baseRequest(t, "GET", srv.URL+"/x", "", nil), words, httpSender(t), Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits) != 0 {
		t.Fatalf("hits = %v, want none confirmed", hitNames(res))
	}
	if len(res.Unconfirmed) != 1 || res.Unconfirmed[0].Name != "callback" {
		t.Fatalf("unconfirmed = %+v, want [callback]", res.Unconfirmed)
	}
	if res.Unconfirmed[0].Exchange == nil {
		t.Error("an unconfirmed lead carries the probe that isolated it")
	}
}
