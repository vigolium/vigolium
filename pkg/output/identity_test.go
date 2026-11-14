package output

import (
	"crypto/sha1"
	"encoding/hex"
	"testing"

	"github.com/vigolium/vigolium/pkg/types/severity"
)

func timingEvent(desc, url string) *ResultEvent {
	return &ResultEvent{
		ModuleID:           "command-injection-timing",
		Info:               Info{Name: "OS Command Injection (time-based)", Description: desc, Severity: severity.High},
		URL:                url,
		Matched:            url,
		Request:            "GET /run?cmd=sleep HTTP/1.1\r\nHost: app.test\r\n\r\n",
		InsertionPointType: "URL_PARAM",
		FuzzingParameter:   "cmd",
		BaseURL:            "https://APP.test:443/run?cmd=ls",
	}
}

// TestIdentity_ProseDoesNotChangeIdentity: a re-detection whose
// description carries a different measured delay is the same finding.
func TestIdentity_ProseDoesNotChangeIdentity(t *testing.T) {
	a := timingEvent("delayed 5012ms", "https://app.test/run?cmd=sleep%205")
	b := timingEvent("delayed 5023ms", "https://app.test/run?cmd=sleep%2010")
	if a.ID() != b.ID() {
		t.Fatalf("identity changed with prose/payload:\n%s\n%s", a.IdentityKey(), b.IdentityKey())
	}
	want := "v2|finding|command-injection-timing|OS Command Injection (time-based)|GET|https://app.test/run|URL_PARAM:cmd"
	if got := a.IdentityKey(); got != want {
		t.Fatalf("IdentityKey = %q, want %q", got, want)
	}
	c := timingEvent("delayed 5012ms", "https://app.test/run")
	c.FuzzingParameter = "other"
	if c.ID() == a.ID() {
		t.Fatal("a different parameter must be a different finding")
	}
}

// TestIdentity_V1AndDedupKeepHistoricalHash pins the pre-v2 hash bytes for
// findings without an insertion point and for DedupKey producers.
func TestIdentity_V1AndDedupKeepHistoricalHash(t *testing.T) {
	sum := func(s string) string { h := sha1.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
	e := &ResultEvent{ModuleID: "m", Info: Info{Description: "d", Severity: severity.Low}, Matched: "https://x/y"}
	if got, want := e.ID(), sum("m|d|low|https://x/y"); got != want {
		t.Fatalf("v1 ID = %s, want %s", got, want)
	}
	e.RecordKind = RecordKindCandidate
	if got, want := e.ID(), sum("candidate|m|d|low|https://x/y"); got != want {
		t.Fatalf("candidate v1 ID = %s, want %s", got, want)
	}
	d := &ResultEvent{ModuleID: "m", DedupKey: "nonce1", InsertionPointType: "URL_PARAM"}
	if got, want := d.ID(), sum("dedup|nonce1"); got != want {
		t.Fatalf("dedup ID = %s, want %s", got, want)
	}
	if HashContentV1(RecordKindFinding, "m", "d", "low", "https://x/y") != sum("m|d|low|https://x/y") {
		t.Fatal("HashContentV1 disagrees with the v1 ID")
	}
}

func TestCanonicalLocation(t *testing.T) {
	for in, want := range map[string]string{
		"HTTP://Example.COM:80/a/b?x=1#f": "http://example.com/a/b",
		"https://h:8443":                  "https://h:8443/",
		"https://[::1]:443/p":             "https://[::1]/p",
		"/rel?q":                          "/rel",
	} {
		if got := CanonicalLocation(in); got != want {
			t.Errorf("CanonicalLocation(%q) = %q, want %q", in, got, want)
		}
	}
}
