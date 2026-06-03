package waf

import (
	"net/http"
	"testing"
)

func TestClassifyParts_CloudflareBlock(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "cloudflare")
	h.Set("Cf-Ray", "abc123")

	res := ClassifyParts(403, h, []byte("Attention Required! | Cloudflare"))
	if res == nil || !res.IsBlocked {
		t.Fatal("expected a cloudflare block result")
	}
	if res.WAFType != "cloudflare" {
		t.Fatalf("want cloudflare, got %q", res.WAFType)
	}
}

func TestClassifyParts_NonBlockingStatus(t *testing.T) {
	if res := ClassifyParts(200, http.Header{}, []byte("ok")); res != nil {
		t.Fatalf("200 must not be a block, got %+v", res)
	}
}

func TestClassifyParts_GenericFallback(t *testing.T) {
	res := ClassifyParts(403, http.Header{}, []byte("You have been blocked"))
	if res == nil || res.WAFType != "generic" {
		t.Fatalf("want generic block, got %+v", res)
	}
}
