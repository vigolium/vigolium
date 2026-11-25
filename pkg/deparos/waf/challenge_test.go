package waf

import (
	"net/http"
	"strings"
	"testing"
)

func TestChallengeRows_Signatures(t *testing.T) {
	html := http.Header{"Content-Type": {"text/html; charset=utf-8"}}
	cases := []struct {
		name   string
		status int
		header http.Header
		body   string
		vendor string
	}{
		{"cloudflare header", 200, http.Header{"Cf-Mitigated": {"challenge"}}, "", "cloudflare"},
		{"cloudflare body", 200, html, `<script>(function(){window._cf_chl_opt={cvId:'3'}})()</script>`, "cloudflare"},
		{"aws waf 202", 202, http.Header{"X-Amzn-Waf-Action": {"challenge"}}, "", "aws_waf"},
		{"aws waf captcha", 200, http.Header{"X-Amzn-Waf-Action": {"Captcha"}}, "", "aws_waf"},
		{"vercel", 200, http.Header{"X-Vercel-Mitigated": {"challenge"}}, "", "vercel"},
		{"akamai interstitial", 200, html, `<script src="/_sec/cp_challenge/sec-cpt-int-4-3.js"></script>`, "akamai"},
		{"imperva incident", 200, html, `Request unsuccessful. Incapsula incident ID: 123-456`, "imperva"},
		{"sucuri", 200, html, `<script>sucuri_cloudproxy_js='',S='...'</script>`, "sucuri"},
		{"datadome", 200, html, `<iframe src="https://geo.captcha-delivery.com/captcha/?initialCid=x"></iframe>`, "datadome"},
		{"perimeterx", 200, html, `<div id="px-captcha"></div>`, "perimeterx"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := ClassifyResponse(c.status, c.header, []byte(c.body))
			if res == nil || !res.Challenge || res.WAFType != c.vendor || res.Kind() != KindChallenge {
				t.Fatalf("got %+v, want a %s challenge", res, c.vendor)
			}
			if res.Vendor() != c.vendor {
				t.Fatalf("Vendor() = %q", res.Vendor())
			}
		})
	}
}

// Pages a vendor's sensor rides on, and statuses no row names, are not
// challenges.
func TestChallengeRows_Negatives(t *testing.T) {
	html := http.Header{"Content-Type": {"text/html"}}
	for name, body := range map[string]string{
		"plain page":              "<html><body>Welcome</body></html>",
		"imperva sensor":          `<script src="/_Incapsula_Resource?SWJIYLWA=719d34d31c8e3a6e6fffd425f7e032f3"></script>`,
		"perimeterx sensor":       `<script>window._pxAppId='PXabc';</script>`,
		"cloudflare jsd injector": `<script>a.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js'</script>`,
	} {
		if res := ClassifyResponse(200, html, []byte(body)); res != nil {
			t.Errorf("%s classified as %+v", name, res)
		}
	}
	if res := ClassifyResponse(404, http.Header{"Cf-Mitigated": {"challenge"}}, nil); res != nil {
		t.Errorf("404 is no row's status: %+v", res)
	}
	if res := ClassifyResponse(200, http.Header{"Content-Type": {"application/json"}}, []byte(`{"x":"window._cf_chl_opt"}`)); res != nil {
		t.Errorf("a JSON body is not a challenge page: %+v", res)
	}
	big := "window._cf_chl_opt" + strings.Repeat("a", challengeMaxBody)
	if res := ClassifyResponse(200, html, []byte(big)); res != nil {
		t.Errorf("a body past the interstitial size is the application: %+v", res)
	}
}

// ClassifyResponse routes a success status to the challenge signatures and a
// block status to the rules; the candidate gate admits both.
func TestClassifyResponse_Routes(t *testing.T) {
	if res := ClassifyResponse(202, http.Header{"X-Amzn-Waf-Action": {"challenge"}}, nil); res.Kind() != KindChallenge {
		t.Fatalf("202 challenge: %+v", res)
	}
	if res := ClassifyResponse(403, http.Header{}, []byte("You have been blocked")); res.Kind() != KindRefused {
		t.Fatalf("403 generic: %+v", res)
	}
	for code, want := range map[int]bool{200: true, 202: true, 403: true, 429: true, 404: false, 302: false} {
		if IsCandidateStatusCode(code) != want {
			t.Errorf("IsCandidateStatusCode(%d) != %v", code, want)
		}
	}
}
