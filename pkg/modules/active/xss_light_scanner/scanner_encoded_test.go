package xss_light_scanner

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// decodingReflectHandler simulates an application that performs one extra
// URL-decode of the q parameter before reflecting it into the HTML body — the
// classic "filter passes %3C, app turns it into <" pre-encoding bug.
func decodingReflectHandler(extraDecode bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q") // framework already decoded once
		if extraDecode {
			if dec, err := url.QueryUnescape(q); err == nil {
				q = dec
			}
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>Hello " + q + "</body></html>"))
	}
}

func TestEncodedScanner_DetectsExtraDecode(t *testing.T) {
	srv := httptest.NewServer(decodingReflectHandler(true))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")

	// The confirm step re-sends the executable payload through the same encoding;
	// executingProbe stands in for a browser that pops alert(marker).
	mod := NewEncodedScanner()
	mod.base.Probe = executingProbe

	res, err := mod.ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res) == 0 {
		t.Fatal("expected an XSS finding for an app that double-decodes the parameter")
	}
	if res[0].FuzzingParameter != "q" {
		t.Fatalf("expected finding on q, got %q", res[0].FuzzingParameter)
	}
	if !strings.Contains(res[0].Info.Description, "[encoded:") {
		t.Fatalf("finding should note the encoding used: %q", res[0].Info.Description)
	}
	// The encoding-aware confirm must reach the browser tier: the executable
	// payload survives the app's extra decode and pops.
	if res[0].Info.Severity != severity.High || res[0].Info.Confidence != severity.Certain {
		t.Fatalf("expected browser-confirmed High/Certain, got %s/%s", res[0].Info.Severity, res[0].Info.Confidence)
	}
}

func TestEncodedScanner_NoFindingWhenNotDecoded(t *testing.T) {
	// App reflects the value verbatim (no extra decode); the encoded probe stays
	// inert text (%3C...), so there must be no finding.
	srv := httptest.NewServer(decodingReflectHandler(false))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")

	mod := NewEncodedScanner()
	mod.base.Probe = executingProbe

	res, err := mod.ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected no finding when app does not decode, got %d", len(res))
	}
}
