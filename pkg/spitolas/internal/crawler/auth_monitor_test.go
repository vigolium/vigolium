package crawler

import (
	"net/http"
	"testing"
)

type fakeMonitor struct {
	gen     uint64
	headers map[string]string
}

func (f *fakeMonitor) Observe(uint64, int, http.Header, []byte) {}
func (f *fakeMonitor) Credentials() (uint64, map[string]string, []*http.Cookie) {
	return f.gen, f.headers, nil
}

// MISS-26: a re-login elsewhere in the scan (new credential generation) is
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
