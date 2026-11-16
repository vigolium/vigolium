package oast

import (
	"context"
	"strings"
	"testing"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// TestBlindXSSRating: a browser fetching the planted script is High/Firm and
// names the rendering page; DNS only, a library client, or a crawler is
// Suspect/Tentative.
func TestBlindXSSRating(t *testing.T) {
	pctx := PayloadContext{Class: oastclass.BlindXSS, InjectionType: "blind xss", ParameterName: "comment", TargetURL: "https://app.test/feedback"}
	rate := func(proto, raw string) (severity.Severity, severity.Confidence, string) {
		sev, conf, desc := classifyInteraction(proto, pctx)
		return refineOASTCallback(&server.Interaction{Protocol: proto, RawRequest: raw}, pctx, sev, conf, desc)
	}
	browser := "GET /b.js HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0 (X11) AppleWebKit/537.36 Chrome/120 Safari/537.36\r\nReferer: https://admin.app.test/tickets/7\r\n\r\n"
	sev, conf, desc := rate("http", browser)
	if sev != severity.High || conf != severity.Firm || !strings.Contains(desc, "admin.app.test/tickets/7") {
		t.Errorf("browser fetch = %s/%s %q", sev, conf, desc)
	}
	for name, tc := range map[string][2]string{
		"dns only":   {"dns", ""},
		"library":    {"http", "GET /b.js HTTP/1.1\r\nUser-Agent: Go-http-client/1.1\r\n\r\n"},
		"crawler":    {"http", "GET /b.js HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)\r\n\r\n"},
		"no ua http": {"http", "GET /b.js HTTP/1.1\r\n\r\n"},
	} {
		if sev, conf, _ := rate(tc[0], tc[1]); sev != severity.Suspect || conf != severity.Tentative {
			t.Errorf("%s = %s/%s, want suspect/tentative", name, sev, conf)
		}
	}
}

// A blind-XSS callback persists vuln_class xss_blind even when the planting
// module's findings span classes (oast-probe): the class comes from what the
// payload was minted for, so a consumer never routes it to a reflected proof.
func TestBlindXSSCallbackStoresVulnClass(t *testing.T) {
	repo := newOASTTestRepo(t)
	const project = "proj-bxss"
	svc := &Service{repo: repo, scanUUID: "scan-bxss", projectUUID: project}
	const nonce = "bxss0000000000000000000nonce42"
	svc.trackerCache().Add(nonce, PayloadContext{
		Class:         oastclass.BlindXSS,
		TargetURL:     "https://app.test/feedback",
		ParameterName: "comment",
		InjectionType: "blind xss",
		ModuleID:      "oast-probe",
		CallbackURL:   nonce + ".oast.vigolium.com",
	})
	svc.handleInteraction(&server.Interaction{
		Protocol:   "http",
		UniqueID:   nonce,
		RawRequest: "GET /b.js HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0 (X11) AppleWebKit/537.36 Chrome/120 Safari/537.36\r\nReferer: https://admin.app.test/tickets/7\r\n\r\n",
	})
	highs, err := repo.GetFindingsBySeverity(context.Background(), project, "high", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(highs) != 1 {
		t.Fatalf("stored %d high findings, want 1", len(highs))
	}
	if got := highs[0].VulnClass; got != "xss_blind" {
		t.Fatalf("stored vuln_class = %q, want xss_blind", got)
	}
}
