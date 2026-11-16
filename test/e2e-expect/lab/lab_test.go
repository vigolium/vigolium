package lab

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestLedgerRecordsStatusesAndConcurrency(t *testing.T) {
	l := New()
	defer l.Close()
	ok := l.Serve("ok", SafeEcho())
	ok.Faults.SetLatency(100 * time.Millisecond)
	down := l.Serve("down", SafeEcho())
	down.Faults.SetDown(true)
	hang := l.Serve("hang", Hang())

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(ok.URL + "/search?q=1")
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	if _, err := http.Get(down.URL + "/"); err == nil {
		t.Fatal("a downed server must not answer")
	}
	c := &http.Client{Timeout: 200 * time.Millisecond}
	if _, err := c.Get(hang.URL + "/"); err == nil {
		t.Fatal("hang must not answer")
	}

	if got := l.Ledger.Count("ok"); got != 4 {
		t.Errorf("ok: %d hits, want 4", got)
	}
	if got := l.Ledger.PeakConcurrency("ok"); got < 2 {
		t.Errorf("ok: peak concurrency %d, want the 4 parallel requests to overlap", got)
	}
	if got := l.Ledger.StatusCounts("down")[StatusDropped]; got == 0 {
		t.Errorf("down: want dropped hits, got %v", l.Ledger.StatusCounts("down"))
	}
	deadline := time.Now().Add(2 * time.Second)
	for l.Ledger.Count("hang") == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := l.Ledger.StatusCounts("hang")[StatusClientGone]; got != 1 {
		t.Errorf("hang: want 1 client-gone hit, got %v", l.Ledger.StatusCounts("hang"))
	}
	if n := l.Ledger.MaxInWindow("ok", time.Second); n != 4 {
		t.Errorf("MaxInWindow = %d, want 4", n)
	}
}
