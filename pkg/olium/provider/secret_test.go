package provider

import (
	"fmt"
	"strings"
	"testing"
)

func TestSecret_FormattersHideValue(t *testing.T) {
	s := secret("sk-ant-supersecret")

	cases := []struct {
		verb string
		fn   func() string
	}{
		{"%v", func() string { return fmt.Sprintf("%v", s) }},
		{"%s", func() string { return fmt.Sprintf("%s", s) }}, //nolint:staticcheck // intentionally exercising %s on the secret type
		{"%q", func() string { return fmt.Sprintf("%q", s) }},
		{"%#v", func() string { return fmt.Sprintf("%#v", s) }},
		{"%+v", func() string { return fmt.Sprintf("%+v", s) }},
	}
	for _, c := range cases {
		got := c.fn()
		if strings.Contains(got, "supersecret") {
			t.Errorf("verb %s leaked the raw value: %q", c.verb, got)
		}
		if !strings.Contains(got, secretStringHidden) {
			t.Errorf("verb %s missing placeholder: %q", c.verb, got)
		}
	}
}

func TestSecret_StructFieldHidden(t *testing.T) {
	type holder struct {
		Key secret
	}
	h := holder{Key: secret("sk-ant-leak-me")}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		got := fmt.Sprintf(verb, h)
		if strings.Contains(got, "leak-me") {
			t.Errorf("verb %s on struct leaked value: %q", verb, got)
		}
	}
}

func TestSecret_RevealReturnsRaw(t *testing.T) {
	if got := secret("plain").Reveal(); got != "plain" {
		t.Errorf("Reveal() = %q, want plain", got)
	}
	if !secret("").IsZero() {
		t.Errorf("empty secret should be zero")
	}
	if secret("x").IsZero() {
		t.Errorf("non-empty secret should not be zero")
	}
}

func TestScrubSecrets(t *testing.T) {
	cases := []struct {
		in     string
		wantOK bool // true if the literal "sk-..." chunk should be gone
	}{
		{"sk-ant-api03-AAAAAAAAAA", true},
		{"sk-ant-oat01-BBBBBBBBBB", true},
		{"Bearer aaaabbbbccccddddeeeeffffggggg", true},
		{"AIzaSyAAAAAAAAAAAAAAAAAAAAAAA", true},
		{"ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", true},
		{"benign string with no secrets", false},
	}
	for _, c := range cases {
		got := scrubSecrets(c.in)
		hadSecret := got != c.in
		if hadSecret != c.wantOK {
			t.Errorf("scrubSecrets(%q) = %q; wanted scrub=%v", c.in, got, c.wantOK)
		}
		if c.wantOK && !strings.Contains(got, secretPlaceholder) {
			t.Errorf("scrubSecrets(%q) = %q; missing placeholder", c.in, got)
		}
	}
}
