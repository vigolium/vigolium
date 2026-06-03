package sqli_boolean_blind

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestQuickRatio(t *testing.T) {
	mk := func(body string) responseSignature { return newResponseSignature(200, body, "") }

	tests := []struct {
		name      string
		a, b      responseSignature
		wantAtLst float64 // ratio must be >= this
		wantAtMst float64 // ratio must be <= this
	}{
		{
			name: "identical bodies", a: mk("welcome user dashboard home"), b: mk("welcome user dashboard home"),
			wantAtLst: 1.0, wantAtMst: 1.0,
		},
		{
			name: "both empty", a: mk(""), b: mk(""),
			wantAtLst: 1.0, wantAtMst: 1.0,
		},
		{
			name: "one empty", a: mk("some content here"), b: mk(""),
			wantAtLst: 0.0, wantAtMst: 0.0,
		},
		{
			name:      "near identical with dynamic noise stripped",
			a:         mk("welcome user csrf_token=abcdef1234567890 page rows ts=1717000000"),
			b:         mk("welcome user csrf_token=0987654321fedcba page rows ts=1718999999"),
			wantAtLst: 0.95, wantAtMst: 1.0, // long hex + long digit runs collapsed away
		},
		{
			name:      "completely different pages",
			a:         mk("login form please authenticate username password"),
			b:         mk("error fatal database connection refused stack trace"),
			wantAtLst: 0.0, wantAtMst: 0.3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := quickRatio(tt.a, tt.b)
			if got < tt.wantAtLst || got > tt.wantAtMst {
				t.Errorf("quickRatio() = %v, want in [%v, %v]", got, tt.wantAtLst, tt.wantAtMst)
			}
		})
	}
}

func TestRatioSimilar(t *testing.T) {
	mk := func(body string) responseSignature { return newResponseSignature(200, body, "") }

	// Same content with only dynamic tokens differing must stay similar.
	a := mk("inventory list item apple banana cherry token=deadbeefcafe0001")
	b := mk("inventory list item apple banana cherry token=00112233445566aa")
	if !ratioSimilar(a, b) {
		t.Error("responses differing only in a long hex token should be ratio-similar")
	}

	// Different status codes are never similar.
	c := newResponseSignature(302, "inventory list item apple banana cherry", "")
	if ratioSimilar(a, c) {
		t.Error("different status codes must not be ratio-similar")
	}

	// Materially different bodies are not similar.
	d := mk("access denied you are not authorized to view this resource")
	if ratioSimilar(a, d) {
		t.Error("materially different bodies must not be ratio-similar")
	}
}

func TestNormalizeForRatio(t *testing.T) {
	// Reflected payload is stripped before tokenization.
	counts, _ := tokenize(normalizeForRatio("hello PAYLOAD_MARKER world", "payload_marker"))
	if _, ok := counts["payload_marker"]; ok {
		t.Error("reflected value should be stripped from normalized tokens")
	}
	if counts["hello"] != 1 || counts["world"] != 1 {
		t.Errorf("expected hello/world tokens preserved, got %v", counts)
	}
}

func TestIsDifferent(t *testing.T) {
	tests := []struct {
		name string
		a, b responseSignature
		want bool
	}{
		{
			name: "different status codes",
			a:    responseSignature{StatusCode: 200, BodyLength: 100, BodyHash: sha256.Sum256([]byte("a"))},
			b:    responseSignature{StatusCode: 302, BodyLength: 100, BodyHash: sha256.Sum256([]byte("a"))},
			want: true,
		},
		{
			name: "identical responses",
			a:    responseSignature{StatusCode: 200, BodyLength: 100, BodyHash: sha256.Sum256([]byte("same"))},
			b:    responseSignature{StatusCode: 200, BodyLength: 100, BodyHash: sha256.Sum256([]byte("same"))},
			want: false,
		},
		{
			name: "large body length difference (>100 bytes)",
			a:    responseSignature{StatusCode: 200, BodyLength: 500, BodyHash: sha256.Sum256([]byte("a"))},
			b:    responseSignature{StatusCode: 200, BodyLength: 200, BodyHash: sha256.Sum256([]byte("b"))},
			want: true,
		},
		{
			name: "body length difference >20%",
			a:    responseSignature{StatusCode: 200, BodyLength: 100, BodyHash: sha256.Sum256([]byte("a"))},
			b:    responseSignature{StatusCode: 200, BodyLength: 75, BodyHash: sha256.Sum256([]byte("b"))},
			want: true,
		},
		{
			name: "small body length difference (<20% and <100 bytes)",
			a:    responseSignature{StatusCode: 200, BodyLength: 1000, BodyHash: sha256.Sum256([]byte("a"))},
			b:    responseSignature{StatusCode: 200, BodyLength: 990, BodyHash: sha256.Sum256([]byte("b"))},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDifferent(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("isDifferent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStatusOK(t *testing.T) {
	if !statusOK(responseSignature{StatusCode: 200}) {
		t.Error("200 should be OK")
	}
	for _, code := range []int{301, 302, 304, 403, 404, 500} {
		if statusOK(responseSignature{StatusCode: code}) {
			t.Errorf("status %d should not be OK", code)
		}
	}
}

func TestHasSubstantialBodyDifference(t *testing.T) {
	h := func(s string) [32]byte { return sha256.Sum256([]byte(s)) }
	tests := []struct {
		name string
		a, b responseSignature
		want bool
	}{
		{"identical", responseSignature{BodyLength: 1000, BodyHash: h("x")}, responseSignature{BodyLength: 1000, BodyHash: h("x")}, false},
		{"big absolute and relative", responseSignature{BodyLength: 1000, BodyHash: h("a")}, responseSignature{BodyLength: 500, BodyHash: h("b")}, true},
		{"big absolute small relative", responseSignature{BodyLength: 10000, BodyHash: h("a")}, responseSignature{BodyLength: 9850, BodyHash: h("b")}, false},
		{"small absolute", responseSignature{BodyLength: 1000, BodyHash: h("a")}, responseSignature{BodyLength: 950, BodyHash: h("b")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasSubstantialBodyDifference(tt.a, tt.b); got != tt.want {
				t.Errorf("hasSubstantialBodyDifference() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Numeric-context classification is covered by infra.TestIsNumericValue; the
// payload-selection tests below exercise its use through getPayloadsForValue.

func TestGetPayloadsForValue(t *testing.T) {
	// Numeric value should return numeric payloads + bypass
	numPayloads := getPayloadsForValue("42")
	hasNumeric := false
	for _, p := range numPayloads {
		if p.context == "numeric" {
			hasNumeric = true
			break
		}
	}
	if !hasNumeric {
		t.Error("getPayloadsForValue(\"42\") should include numeric payloads")
	}

	// String value should return string payloads + bypass
	strPayloads := getPayloadsForValue("admin")
	hasString := false
	for _, p := range strPayloads {
		if p.context == "string" {
			hasString = true
			break
		}
	}
	if !hasString {
		t.Error("getPayloadsForValue(\"admin\") should include string payloads")
	}

	// Both should include bypass payloads
	for _, payloads := range [][]payloadPair{numPayloads, strPayloads} {
		hasBypass := false
		for _, p := range payloads {
			if p.context == "bypass" {
				hasBypass = true
				break
			}
		}
		if !hasBypass {
			t.Error("payloads should include bypass payloads")
		}
	}
}

func TestBuildMatrixPayloads(t *testing.T) {
	for _, numeric := range []bool{true, false} {
		boundaries := stringBoundaries
		if numeric {
			boundaries = numericBoundaries
		}
		pairs := buildMatrixPayloads(numeric)
		// Each boundary yields one AND and one OR pair.
		if want := len(boundaries) * 2; len(pairs) != want {
			t.Fatalf("numeric=%v: got %d matrix pairs, want %d", numeric, len(pairs), want)
		}
		for _, p := range pairs {
			if p.context != "matrix" {
				t.Errorf("expected context=matrix, got %q", p.context)
			}
			if p.trueVal == p.falseVal {
				t.Errorf("matrix pair has identical TRUE/FALSE: %q", p.trueVal)
			}
			if p.trueVal == "" || p.falseVal == "" {
				t.Errorf("matrix pair has empty value: %+v", p)
			}
		}
	}
}

func TestGetPayloadsForValueIncludesMatrix(t *testing.T) {
	for _, v := range []string{"42", "admin"} {
		hasMatrix := false
		for _, p := range getPayloadsForValue(v) {
			if p.context == "matrix" {
				hasMatrix = true
				break
			}
		}
		if !hasMatrix {
			t.Errorf("getPayloadsForValue(%q) should include boundary-matrix payloads", v)
		}
	}
}

func TestStringPayloadsStartWithAND(t *testing.T) {
	// AND-based payloads must come first for login form detection.
	// They create reliable TRUE/FALSE differentials even when the
	// base value matches an existing record.
	if len(stringPayloads) == 0 {
		t.Fatal("stringPayloads is empty")
	}
	first := stringPayloads[0]
	if !strings.Contains(first.trueVal, "AND") {
		t.Errorf("first string payload should be AND-based, got trueVal=%q", first.trueVal)
	}
}

func TestPayloadPairsAreValid(t *testing.T) {
	allPairs := append(append(stringPayloads, numericPayloads...), bypassPayloads...)
	for _, pair := range allPairs {
		if pair.trueVal == pair.falseVal {
			t.Errorf("payload pair in %s context has identical TRUE/FALSE: %q", pair.context, pair.trueVal)
		}
		if pair.trueVal == "" || pair.falseVal == "" {
			t.Errorf("payload pair in %s context has empty value", pair.context)
		}
		// TRUE payload should contain "1=1" or "a'='a" etc.
		if !strings.Contains(pair.trueVal, "1=1") && !strings.Contains(pair.trueVal, "a'='a") && !strings.Contains(pair.trueVal, "1\"=\"1") {
			t.Logf("Warning: TRUE payload %q may not be a TRUE condition", pair.trueVal)
		}
	}
}
