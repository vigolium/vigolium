package modkit

import "testing"

func TestWAFRegistry_MarkAndGet(t *testing.T) {
	r := NewWAFRegistry()

	if got := r.Get("example.com"); got != "" {
		t.Fatalf("empty registry: want \"\", got %q", got)
	}

	r.Mark("Example.com", "Cloudflare")
	if got := r.Get("example.com"); got != "cloudflare" {
		t.Fatalf("case-insensitive store/lookup: want cloudflare, got %q", got)
	}
}

func TestWAFRegistry_SpecificNotDowngradedByGeneric(t *testing.T) {
	r := NewWAFRegistry()
	r.Mark("h", "cloudflare")
	r.Mark("h", "generic")
	if got := r.Get("h"); got != "cloudflare" {
		t.Fatalf("specific WAF must survive a later generic mark, got %q", got)
	}
}

func TestWAFRegistry_GenericUpgradedToSpecific(t *testing.T) {
	r := NewWAFRegistry()
	r.Mark("h", "generic")
	r.Mark("h", "akamai")
	if got := r.Get("h"); got != "akamai" {
		t.Fatalf("generic must upgrade to specific, got %q", got)
	}
}

func TestWAFRegistry_NilSafe(t *testing.T) {
	var r *WAFRegistry
	r.Mark("h", "x") // must not panic
	if got := r.Get("h"); got != "" {
		t.Fatalf("nil registry Get: want \"\", got %q", got)
	}
}

func TestScanContext_WAFAccessorsNilSafe(t *testing.T) {
	var sc *ScanContext
	sc.MarkWAF("h", "x") // must not panic
	if got := sc.DetectedWAF("h"); got != "" {
		t.Fatalf("nil ScanContext DetectedWAF: want \"\", got %q", got)
	}

	sc2 := &ScanContext{} // WAFStack unset
	sc2.MarkWAF("h", "x")
	if got := sc2.DetectedWAF("h"); got != "" {
		t.Fatalf("unset WAFStack: want \"\", got %q", got)
	}

	sc3 := &ScanContext{WAFStack: NewWAFRegistry()}
	sc3.MarkWAF("h", "imperva")
	if got := sc3.DetectedWAF("h"); got != "imperva" {
		t.Fatalf("wired WAFStack: want imperva, got %q", got)
	}
}
