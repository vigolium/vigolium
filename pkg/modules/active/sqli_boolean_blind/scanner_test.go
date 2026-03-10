package sqli_boolean_blind

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestIsDifferent(t *testing.T) {
	tests := []struct {
		name string
		a, b responseSignature
		want bool
	}{
		{
			name: "different status codes",
			a:    responseSignature{statusCode: 200, bodyLength: 100, bodyHash: sha256.Sum256([]byte("a"))},
			b:    responseSignature{statusCode: 302, bodyLength: 100, bodyHash: sha256.Sum256([]byte("a"))},
			want: true,
		},
		{
			name: "identical responses",
			a:    responseSignature{statusCode: 200, bodyLength: 100, bodyHash: sha256.Sum256([]byte("same"))},
			b:    responseSignature{statusCode: 200, bodyLength: 100, bodyHash: sha256.Sum256([]byte("same"))},
			want: false,
		},
		{
			name: "large body length difference (>100 bytes)",
			a:    responseSignature{statusCode: 200, bodyLength: 500, bodyHash: sha256.Sum256([]byte("a"))},
			b:    responseSignature{statusCode: 200, bodyLength: 200, bodyHash: sha256.Sum256([]byte("b"))},
			want: true,
		},
		{
			name: "body length difference >20%",
			a:    responseSignature{statusCode: 200, bodyLength: 100, bodyHash: sha256.Sum256([]byte("a"))},
			b:    responseSignature{statusCode: 200, bodyLength: 75, bodyHash: sha256.Sum256([]byte("b"))},
			want: true,
		},
		{
			name: "small body length difference (<20% and <100 bytes)",
			a:    responseSignature{statusCode: 200, bodyLength: 1000, bodyHash: sha256.Sum256([]byte("a"))},
			b:    responseSignature{statusCode: 200, bodyLength: 990, bodyHash: sha256.Sum256([]byte("b"))},
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

func TestIsSimilar(t *testing.T) {
	tests := []struct {
		name string
		a, b responseSignature
		want bool
	}{
		{
			name: "identical responses",
			a:    responseSignature{statusCode: 200, bodyLength: 100, bodyHash: sha256.Sum256([]byte("same"))},
			b:    responseSignature{statusCode: 200, bodyLength: 100, bodyHash: sha256.Sum256([]byte("same"))},
			want: true,
		},
		{
			name: "different status codes not similar",
			a:    responseSignature{statusCode: 200, bodyLength: 100, bodyHash: sha256.Sum256([]byte("a"))},
			b:    responseSignature{statusCode: 302, bodyLength: 100, bodyHash: sha256.Sum256([]byte("a"))},
			want: false,
		},
		{
			name: "small variance is similar",
			a:    responseSignature{statusCode: 200, bodyLength: 1000, bodyHash: sha256.Sum256([]byte("a"))},
			b:    responseSignature{statusCode: 200, bodyLength: 1010, bodyHash: sha256.Sum256([]byte("b"))},
			want: true,
		},
		{
			name: "large variance is not similar",
			a:    responseSignature{statusCode: 200, bodyLength: 1000, bodyHash: sha256.Sum256([]byte("a"))},
			b:    responseSignature{statusCode: 200, bodyLength: 1100, bodyHash: sha256.Sum256([]byte("b"))},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSimilar(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("isSimilar() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsNumericValue(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"123", true},
		{"-42", true},
		{"3.14", true},
		{"", false},
		{"abc", false},
		{"12abc", false},
		{"john@example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got := isNumericValue(tt.value)
			if got != tt.want {
				t.Errorf("isNumericValue(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

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
