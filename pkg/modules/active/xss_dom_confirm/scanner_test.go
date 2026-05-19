package xss_dom_confirm

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

func TestMatchCanary(t *testing.T) {
	canary := "vig-x-abcdef"
	dialogs := []spitolas.DialogEvent{
		{Type: "alert", Message: "unrelated"},
		{Type: "confirm", Message: "wrapping " + canary + " inside"},
	}
	hit := matchCanary(dialogs, canary)
	if hit == nil {
		t.Fatalf("expected canary match")
	}
	if hit.Type != "confirm" {
		t.Fatalf("matched wrong dialog: %+v", hit)
	}

	if matchCanary(dialogs, "vig-x-not-here") != nil {
		t.Fatalf("expected no match for absent canary")
	}
}

func TestNavigableURLAppendsHashFragment(t *testing.T) {
	rr, err := httpmsg.GetRawRequestFromURL("http://example.com/search?q=hello")
	if err != nil {
		t.Fatalf("GetRawRequestFromURL: %v", err)
	}
	points, err := httpmsg.CreateAllInsertionPoints(rr.Request().Raw(), true)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints: %v", err)
	}

	var qPoint httpmsg.InsertionPoint
	for _, ip := range points {
		if ip.Type() == httpmsg.INS_PARAM_URL && ip.Name() == "q" {
			qPoint = ip
			break
		}
	}
	if qPoint == nil {
		t.Fatalf("q insertion point not found; got %d points", len(points))
	}

	fuzzedRaw := qPoint.BuildRequest([]byte(`"'><svg/onload=alert("vig-x-test")>//`))
	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}
	fuzzedReq = fuzzedReq.WithService(rr.Service())

	url, err := navigableURL(fuzzedReq, `<svg/onload=alert("vig-x-test")>`)
	if err != nil {
		t.Fatalf("navigableURL: %v", err)
	}

	if !strings.Contains(url, "q=") {
		t.Fatalf("URL missing q param: %q", url)
	}
	if !strings.Contains(url, "#") {
		t.Fatalf("URL missing hash fragment: %q", url)
	}
}
