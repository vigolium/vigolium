package xss_dom_confirm

import (
	"strings"
	"testing"
)

func TestNewPayloadCanaryUnique(t *testing.T) {
	a, err := NewPayload()
	if err != nil {
		t.Fatalf("NewPayload: %v", err)
	}
	b, err := NewPayload()
	if err != nil {
		t.Fatalf("NewPayload: %v", err)
	}
	if a.Canary == b.Canary {
		t.Fatalf("two payloads share canary %q", a.Canary)
	}
	if !strings.HasPrefix(a.Canary, "vig-x-") {
		t.Fatalf("canary %q missing vig-x- prefix", a.Canary)
	}
}

func TestNewPayloadEmbedsCanary(t *testing.T) {
	p, err := NewPayload()
	if err != nil {
		t.Fatalf("NewPayload: %v", err)
	}
	if !strings.Contains(p.Body, p.Canary) {
		t.Fatalf("Body %q does not contain canary %q", p.Body, p.Canary)
	}
	if !strings.Contains(p.Hash, p.Canary) {
		t.Fatalf("Hash %q does not contain canary %q", p.Hash, p.Canary)
	}
	if !strings.Contains(p.Body, "alert") {
		t.Fatalf("Body %q missing alert call", p.Body)
	}
}
