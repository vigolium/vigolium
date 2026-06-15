package linkfinder

import "testing"

// TestExtractPaths_RootRelativeWithQuery covers quoted root-relative routes that
// appear in framework payloads (Salesforce Aura component defs, SPA route
// tables) and used to be dropped — either for being a single-segment path or for
// tripping the X_Y spam heuristic on enterprise identifiers. The reflected query
// parameter must be preserved (it is the scan's insertion point).
func TestExtractPaths_RootRelativeWithQuery(t *testing.T) {
	body := []byte(`
		{"HTMLAttributes":{"value":{"src":"/apex/APP_Login_NewCaptcha?source=reqRegCaptcha","id":"reqRegCaptcha"}}},
		fn.add("/apex/APP_Login_NewCaptchaCheckBox?captchaLanguage=", cmp.get("v.lang")),
		var r = "/register?source=weuci";
		var s = "/My_Servlet?id=1";
	`)
	got := ExtractPaths(body)

	want := []string{
		"/apex/APP_Login_NewCaptcha?source=reqRegCaptcha",
		"/apex/APP_Login_NewCaptchaCheckBox?captchaLanguage=",
		"/register?source=weuci",
		"/My_Servlet?id=1",
	}
	set := make(map[string]bool, len(got))
	for _, p := range got {
		set[p] = true
	}
	for _, w := range want {
		if !set[w] {
			t.Errorf("ExtractPaths missing %q; got %v", w, got)
		}
	}
}

func TestPathHasQuery(t *testing.T) {
	cases := map[string]bool{
		"/apex/Foo?source=y": true,
		"/a?b=c":             true,
		"/apex/Foo":          false,
		"/apex/Foo?":         false, // "?" with no name=value
		"/apex/Foo?novalue":  false, // no "="
		"":                   false,
		"https://h/p?x=1":    true,
	}
	for in, want := range cases {
		if got := PathHasQuery(in); got != want {
			t.Errorf("PathHasQuery(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestLooksLikeStructuredPath(t *testing.T) {
	// Real enterprise routes (lowercase words) are exempted from the spam filter.
	for _, p := range []string{
		"/apex/APP_Login_NewCaptcha?source=x",
		"/My_Servlet",
		"/user_profile",
	} {
		if !looksLikeStructuredPath(p) {
			t.Errorf("looksLikeStructuredPath(%q) = false, want true", p)
		}
	}
	// All-caps minified noise and non-paths are NOT exempted (spam filter still applies).
	for _, p := range []string{
		"/A_B",
		"A_B",
		"//host",
		"/",
	} {
		if looksLikeStructuredPath(p) {
			t.Errorf("looksLikeStructuredPath(%q) = true, want false", p)
		}
	}
}
