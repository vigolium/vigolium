package waf

import (
	"net/http"
	"testing"
)

func TestClassifyResponse_CloudflareBlock(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "cloudflare")
	h.Set("Cf-Ray", "abc123")

	res := ClassifyResponse(403, h, []byte("Attention Required! | Cloudflare"))
	if res == nil || !res.IsBlocked {
		t.Fatal("expected a cloudflare block result")
	}
	if res.WAFType != "cloudflare" {
		t.Fatalf("want cloudflare, got %q", res.WAFType)
	}
}

func TestClassifyResponse_NonBlockingStatus(t *testing.T) {
	if res := ClassifyResponse(200, http.Header{}, []byte("ok")); res != nil {
		t.Fatalf("200 must not be a block, got %+v", res)
	}
}

func TestClassifyResponse_GenericFallback(t *testing.T) {
	res := ClassifyResponse(403, http.Header{}, []byte("You have been blocked"))
	if res == nil || res.WAFType != "generic" {
		t.Fatalf("want generic block, got %+v", res)
	}
}

// The generic rule alone names no vendor: Kind refused, Vendor "".
func TestBlockResult_KindAndVendor(t *testing.T) {
	generic := ClassifyResponse(403, http.Header{}, []byte("<h1>403 Forbidden</h1>"))
	if generic.Kind() != KindRefused || generic.Vendor() != "" {
		t.Fatalf("generic-only match: kind %q vendor %q, want refused and no vendor", generic.Kind(), generic.Vendor())
	}
	h := http.Header{}
	h.Set("Server", "cloudflare")
	cf := ClassifyResponse(403, h, []byte("Attention Required! | Cloudflare"))
	if cf.Kind() != KindVendor || cf.Vendor() != "cloudflare" {
		t.Fatalf("cloudflare block: kind %q vendor %q", cf.Kind(), cf.Vendor())
	}
	var none *BlockResult
	if none.Kind() != "" || none.Vendor() != "" {
		t.Fatal("nil result has no kind or vendor")
	}
}
