package notify

import (
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

type captureBackend struct {
	mu   sync.Mutex
	sent []*output.ResultEvent
}

func (c *captureBackend) Send(r *output.ResultEvent) error {
	c.mu.Lock()
	c.sent = append(c.sent, r)
	c.mu.Unlock()
	return nil
}
func (c *captureBackend) SendRaw(string) error { return nil }
func (c *captureBackend) Close()               {}

// SAFE-12: notifications carry a redacted clone; the caller's event is
// untouched.
func TestManagerSendRedactsClone(t *testing.T) {
	be := &captureBackend{}
	m := New(Config{Backends: []Backend{be}, AllowedSeverities: []string{"all"}, RedactHeaders: map[string]struct{}{"x-op": {}}})
	ev := &output.ResultEvent{
		Info:    output.Info{Name: "x", Severity: severity.High},
		Request: "GET /?api_key=QSECRET HTTP/1.1\r\nAuthorization: Bearer ASECRET\r\nX-Op: OSECRET\r\n\r\n",
	}
	if err := m.Send(ev); err != nil {
		t.Fatal(err)
	}
	m.Close()
	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.sent) != 1 {
		t.Fatalf("sent %d, want 1", len(be.sent))
	}
	for _, s := range []string{"QSECRET", "ASECRET", "OSECRET"} {
		if strings.Contains(be.sent[0].Request, s) {
			t.Errorf("notification leaks %s", s)
		}
	}
	if !strings.Contains(ev.Request, "ASECRET") {
		t.Error("the caller's event must not be modified")
	}
}
