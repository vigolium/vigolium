package oast

import (
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
