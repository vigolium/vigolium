package modkit

import "testing"

func sig(status int, body string) ResponseSignature {
	return NewResponseSignature(status, body, "")
}

func TestQuickRatioShared(t *testing.T) {
	a := sig(200, "welcome user dashboard home")
	if got := QuickRatio(a, a); got != 1.0 {
		t.Errorf("identical bodies ratio = %v, want 1.0", got)
	}
	empty := sig(200, "")
	if got := QuickRatio(sig(200, "content here"), empty); got != 0.0 {
		t.Errorf("one-empty ratio = %v, want 0.0", got)
	}
	// Dynamic-noise tokens (long hex/digit runs) collapse away → still similar.
	x := sig(200, "inventory item token=deadbeefcafe0001 ts=1717000000")
	y := sig(200, "inventory item token=00112233445566aa ts=1718999999")
	if !RatioSimilar(x, y) {
		t.Error("responses differing only in dynamic tokens should be ratio-similar")
	}
}

func TestRatioSimilarStatusFlip(t *testing.T) {
	a := sig(200, "same page content here")
	b := sig(302, "same page content here")
	if RatioSimilar(a, b) {
		t.Error("different status codes must never be ratio-similar")
	}
}

func TestConfirmReflectionAllRoundsMustReflect(t *testing.T) {
	// Every round reflects → confirmed.
	calls := 0
	ok, err := ConfirmReflection(3, func(c string) (bool, error) {
		calls++
		if len(c) == 0 {
			t.Error("canary must be non-empty")
		}
		return true, nil
	})
	if err != nil || !ok {
		t.Fatalf("all-reflect: ok=%v err=%v", ok, err)
	}
	if calls != 3 {
		t.Errorf("expected 3 rounds, got %d", calls)
	}

	// One round fails to reflect → not confirmed, stops early.
	calls = 0
	ok, _ = ConfirmReflection(3, func(c string) (bool, error) {
		calls++
		return calls == 1, nil // first reflects, second doesn't
	})
	if ok {
		t.Error("a non-reflecting round must fail confirmation")
	}
	if calls != 2 {
		t.Errorf("should stop at first non-reflecting round, got %d calls", calls)
	}
}

func TestConfirmReflectionFreshCanaryEachRound(t *testing.T) {
	seen := map[string]bool{}
	_, _ = ConfirmReflection(4, func(c string) (bool, error) {
		if seen[c] {
			t.Errorf("canary %q reused across rounds", c)
		}
		seen[c] = true
		return true, nil
	})
	if len(seen) != 4 {
		t.Errorf("expected 4 distinct canaries, got %d", len(seen))
	}
}

func TestConfirmNotSoft404RedirectToAuth(t *testing.T) {
	// A 3xx to a login page is never a genuine hit, regardless of wildcard probe.
	if ConfirmNotSoft404(nil, nil, nil, 302, []byte("redirecting"), "/login") {
		t.Error("3xx redirect to /login must be rejected as a soft hit")
	}
	// A 3xx elsewhere with a nil ScanContext fails open (cannot probe).
	if !ConfirmNotSoft404(nil, nil, nil, 302, []byte("redirecting"), "/dashboard") {
		t.Error("3xx to a non-auth path with no probe context should fail open")
	}
	// A 200 with nil ScanContext fails open.
	if !ConfirmNotSoft404(nil, nil, nil, 200, []byte("real content"), "") {
		t.Error("200 with no probe context should fail open (genuine until proven wildcard)")
	}
}

func TestFreshCanaryShape(t *testing.T) {
	c := FreshCanary()
	if len(c) < 6 || c[:3] != "vgo" {
		t.Errorf("FreshCanary() = %q, want vgo-prefixed token", c)
	}
	if c == FreshCanary() {
		t.Error("FreshCanary() should produce distinct values")
	}
}

func TestReconfirmConfigDefaults(t *testing.T) {
	c := ReconfirmConfig{}.withDefaults()
	if c.PayloadRounds != 2 {
		t.Errorf("default PayloadRounds = %d, want 2", c.PayloadRounds)
	}
	c = ReconfirmConfig{PayloadRounds: 5}.withDefaults()
	if c.PayloadRounds != 5 {
		t.Errorf("explicit PayloadRounds overridden: got %d", c.PayloadRounds)
	}
}

func TestConfirmBodyDifferentialMissingData(t *testing.T) {
	// No client / empty requests → cannot run, must fail open (Ran=false).
	res := ConfirmBodyDifferential(nil, nil, nil, nil, "", 0, ReconfirmConfig{})
	if res.Ran || res.Confirmed {
		t.Errorf("missing data should yield Ran=false Confirmed=false, got %+v", res)
	}
}

func TestDeltaTokenSetKeepsNumericMarkers(t *testing.T) {
	// Short numeric markers (e.g. a template math result, or struts OGNL result)
	// must survive — they are exactly what reflection-style modules key on.
	d := deltaTokenSet("the answer is 49 and 1614244871 here")
	if d["49"] == 0 {
		t.Error("short numeric marker 49 should be preserved")
	}
	if d["1614244871"] == 0 {
		t.Error("10-digit numeric marker should be preserved")
	}
	// Single-character tokens are dropped as noise.
	if d["a"] != 0 {
		t.Error("single-char tokens should be dropped")
	}
}

func TestDeltaTokenSetStripsVolatileHeaders(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"Date: Mon, 01 Jan 2030 00:00:00 GMT\r\n" +
		"Set-Cookie: session=deadbeefcafe1234567890ff; Path=/\r\n" +
		"Content-Length: 5123\r\n" +
		"Server: nginx\r\n\r\n" +
		"welcome home"
	d := deltaTokenSet(raw)
	// Volatile header values must not appear as tokens.
	for _, tok := range []string{"session", "5123", "gmt"} {
		if d[tok] != 0 {
			t.Errorf("volatile header token %q should be stripped", tok)
		}
	}
	// Real content survives.
	if d["welcome"] == 0 || d["nginx"] == 0 {
		t.Errorf("non-volatile content should be preserved, got %v", d)
	}
}

func TestCrossIDConfigDefaults(t *testing.T) {
	c := CrossIDConfig{}.withDefaults()
	if c.SelfRounds != 2 {
		t.Errorf("default SelfRounds = %d, want 2", c.SelfRounds)
	}
	if c = (CrossIDConfig{SelfRounds: 4}).withDefaults(); c.SelfRounds != 4 {
		t.Errorf("explicit SelfRounds overridden: got %d", c.SelfRounds)
	}
}

func TestConfirmCrossIDDifferentialFailOpen(t *testing.T) {
	// No client → cannot run the same-id refetch, so the verdict must fail open
	// (Ran=false) and callers keep the finding. CrossRatio is still computed.
	v := ConfirmCrossIDDifferential(nil, nil, nil, "the original resource body", 200, "a different resource body", CrossIDConfig{})
	if v.Ran {
		t.Errorf("nil client must fail open (Ran=false), got %+v", v)
	}
	if v.CrossRatio <= 0 || v.CrossRatio >= 1 {
		t.Errorf("cross ratio should be computed even when the refetch cannot run, got %v", v.CrossRatio)
	}
}

// TestRawBodySignatureKeepsDynamicRuns is the crux of why the determinism gate
// uses a raw (non-collapsed) signature: two responses that differ ONLY in
// per-request dynamic runs (nonces, counters) look near-identical to the
// noise-collapsing NewResponseSignature, but the gate must see them as different
// — that divergence is exactly how it recognizes a non-deterministic endpoint.
func TestRawBodySignatureKeepsDynamicRuns(t *testing.T) {
	a := "session beacon nonce=deadbeefcafe0001 counter=1717000000 stable text here"
	b := "session beacon nonce=00112233445566aa counter=1718999999 stable text here"

	// Collapsed signatures treat noise-only diffs as the same page.
	if got := QuickRatio(NewResponseSignature(200, a, ""), NewResponseSignature(200, b, "")); got < UpperRatioBound {
		t.Errorf("collapsed signatures should see noise-only diffs as similar, ratio=%v", got)
	}
	// Raw signatures (used by the gate) must see the per-request runs as different.
	if got := QuickRatio(rawBodySignature(200, a), rawBodySignature(200, b)); got >= UpperRatioBound {
		t.Errorf("raw signatures must see per-request nonce diffs as dissimilar, ratio=%v", got)
	}
}

func TestDeltaTokenSetCollapsesLongRuns(t *testing.T) {
	// A very long hex/digit run (session id / hash) collapses away so it can't
	// masquerade as introduced content.
	d := deltaTokenSet("token=abcdef0123456789abcdef body text")
	if d["abcdef0123456789abcdef"] != 0 {
		t.Error("16+ char hex run should be collapsed")
	}
	if d["body"] == 0 || d["text"] == 0 {
		t.Error("normal tokens should survive collapse")
	}
}
