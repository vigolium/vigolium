package oast_probe

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// fakeOAST is a minimal OASTProvider that hands out a fixed callback host so the
// test can assert how each header is shaped.
type fakeOAST struct{ host string }

func (f fakeOAST) GenerateURL(_, _, _, _, _ string) string { return f.host }
func (f fakeOAST) Enabled() bool                           { return true }

// TestOASTProbe_CollaboratorEverywhereHeaders drives the live injection path and
// asserts the Collaborator-Everywhere additions: bare-host IP headers, the
// wap.xml UAProf form, the RFC 7239 Forwarded "for=" form, the unchanged URL form,
// and the always-on Cache-Control: no-transform companion on every probe.
func TestOASTProbe_CollaboratorEverywhereHeaders(t *testing.T) {
	const host = "abc123.oast.test"

	var mu sync.Mutex
	var seen []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Clone())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/index")
	scanCtx := &modkit.ScanContext{OASTProvider: fakeOAST{host: host}}

	if _, err := New().ScanPerRequest(rr, client, scanCtx); err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("no probe requests reached the server")
	}

	// Every probe must carry the anti-mangling companion header.
	for i, h := range seen {
		if got := h.Get("Cache-Control"); got != "no-transform" {
			t.Errorf("request %d Cache-Control = %q, want no-transform", i, got)
		}
	}

	// Each shaped header must appear with its expected value in some probe.
	want := map[string]string{
		"True-Client-IP": host,                          // bare
		"X-Client-IP":    host,                          // bare
		"X-Wap-Profile":  "http://" + host + "/wap.xml", // UAProf
		"Forwarded":      "for=" + host,                 // RFC 7239
		"Referer":        "http://" + host,              // unchanged URL form
	}
	for name, exp := range want {
		found := false
		for _, h := range seen {
			if h.Get(name) == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no probe carried %s: %q", name, exp)
		}
	}
}
