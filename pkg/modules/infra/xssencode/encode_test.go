package xssencode

import "testing"

func TestURLEncode(t *testing.T) {
	if got := URLEncode("<x>"); got != "%3Cx%3E" {
		t.Fatalf("URLEncode: %q", got)
	}
}

func TestBase64(t *testing.T) {
	if got := Base64("ab"); got != "YWI=" {
		t.Fatalf("Base64: %q", got)
	}
}

func TestDedupeVariants(t *testing.T) {
	in := []Variant{
		{Name: "a", Value: "x"},
		{Name: "b", Value: "x"},    // duplicate value → dropped
		{Name: "c", Value: ""},     // empty → dropped
		{Name: "d", Value: "base"}, // equals baseline → dropped
		{Name: "e", Value: "y"},
	}
	out := dedupeVariants(in, "base")
	if len(out) != 2 {
		t.Fatalf("want 2 variants, got %d: %+v", len(out), out)
	}
	if out[0].Value != "x" || out[1].Value != "y" {
		t.Fatalf("unexpected order/values: %+v", out)
	}
}
