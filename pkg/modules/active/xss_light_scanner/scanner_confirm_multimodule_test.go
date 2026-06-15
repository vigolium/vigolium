package xss_light_scanner

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// These tests prove the URL-param scanner now runs the SAME browser-confirm +
// operator-chaining step as param-discovery (via the shared confirmXSS), rather
// than reporting raw transform heuristics. The path and encoded scanners route
// through the identical confirmXSS call (covered by the encoded High test and
// shared confirm_test tiers).

func TestURLParams_BrowserConfirmed_High(t *testing.T) {
	// Existing URL param reflects into a JS string; the executable payload pops.
	srv := httptest.NewServer(jsStringHandler(nil))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?body=hi")

	mod := NewURLParamsScanner()
	mod.Probe = executingProbe

	res, err := mod.ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
	if res[0].FuzzingParameter != "body" {
		t.Fatalf("expected finding on body, got %q", res[0].FuzzingParameter)
	}
	if res[0].Info.Severity != severity.High || res[0].Info.Confidence != severity.Certain {
		t.Fatalf("expected browser-confirmed High/Certain, got %s/%s", res[0].Info.Severity, res[0].Info.Confidence)
	}
}

func TestURLParams_DroppedWhenPayloadFiltered(t *testing.T) {
	// Canary chars survive (heuristic flags it) but the keywords a real payload
	// needs are stripped, so the executable breakout never survives → drop.
	stripKeywords := func(s string) string {
		for _, kw := range []string{"alert", "onload", "onerror", "svg"} {
			s = strings.ReplaceAll(s, kw, "")
		}
		return s
	}
	srv := httptest.NewServer(jsStringHandler(stripKeywords))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?body=hi")

	mod := NewURLParamsScanner()
	mod.Probe = executingProbe

	res, err := mod.ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected the reflection-only false positive to be dropped, got %d: %+v", len(res), res)
	}
}
