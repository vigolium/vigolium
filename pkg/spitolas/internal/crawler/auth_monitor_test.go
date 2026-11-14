package crawler

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
)

type fakeMonitor struct {
	gen      uint64
	headers  map[string]string
	changed  chan struct{}
	observed []int
}

func (f *fakeMonitor) Observe(_ uint64, status int, _ http.Header, _ []byte) {
	f.observed = append(f.observed, status)
}
func (f *fakeMonitor) Changed() <-chan struct{} { return f.changed }
func (f *fakeMonitor) Credentials() (uint64, map[string]string, []*http.Cookie) {
	return f.gen, f.headers, nil
}

// A re-login elsewhere in the scan (new credential generation) is
// re-applied to the browser once per generation.
func TestRefreshAuthIfChanged(t *testing.T) {
	rec := &authRecorder{}
	c := newAuthCrawler(t, "https://app.example.com/", nil, rec)
	mon := &fakeMonitor{gen: 1, headers: map[string]string{"Authorization": "Bearer gen1"}}
	c.config.AuthMonitor = mon

	c.refreshAuthIfChanged(nil)
	c.refreshAuthIfChanged(nil)
	if len(rec.headers) != 1 || rec.headers[0]["Authorization"] != "Bearer gen1" {
		t.Fatalf("headers applied = %v, want one gen1 application", rec.headers)
	}
	mon.gen, mon.headers = 2, map[string]string{"Authorization": "Bearer gen2"}
	c.refreshAuthIfChanged(nil)
	if len(rec.headers) != 2 || rec.headers[1]["Authorization"] != "Bearer gen2" {
		t.Errorf("re-login not re-applied: %v", rec.headers)
	}
}

// A re-login signal (Changed) makes the next action re-apply the
// credentials even when the generation number is unchanged, and captured
// in-scope responses reach the session's logged-out detector.
func TestAuthChangedAndObserve(t *testing.T) {
	rec := &authRecorder{}
	c := newAuthCrawler(t, "https://app.example.com/", nil, rec)
	mon := &fakeMonitor{gen: 1, headers: map[string]string{"Authorization": "Bearer g1"}, changed: make(chan struct{}, 1)}
	c.config.AuthMonitor = mon
	c.refreshAuthIfChanged(nil)
	if len(rec.headers) != 1 {
		t.Fatalf("initial apply: %v", rec.headers)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.watchAuthChanges(ctx, mon)
	mon.changed <- struct{}{}
	deadline := time.Now().Add(2 * time.Second)
	for !c.authDirty.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	c.refreshAuthIfChanged(nil)
	if len(rec.headers) != 2 {
		t.Errorf("Changed() must trigger a re-apply; applied %d times", len(rec.headers))
	}

	c.observeAuthResponse(&network.TrafficEntry{Response: &network.ResponseData{Status: 401}})
	if len(mon.observed) != 1 || mon.observed[0] != 401 {
		t.Errorf("observed = %v, want [401]", mon.observed)
	}
}
